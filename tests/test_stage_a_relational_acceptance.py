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


class StageARelationalAcceptanceTests(StageARelationalTestBase):
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

    def test_launch_predicate_gate_accepts_only_memory_free_structural_tautologies(self):
        condition = {
            "op": "unsigned_less",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 4},
        }
        tautology = {
            "op": "or",
            "left": {"op": "not", "value": condition},
            "right": condition,
        }
        self.assertTrue(_semantic_bool_is_structural_tautology(tautology))
        self.assertTrue(_launch_state_predicates_structurally_true([{
            "original": tautology,
            "candidate": tautology,
            "exact_memory_reads": [],
        }]))
        self.assertFalse(_launch_state_predicates_structurally_true([{
            "original": condition,
            "candidate": condition,
            "exact_memory_reads": [],
        }]))
        self.assertFalse(_launch_state_predicates_structurally_true([{
            "original": tautology,
            "candidate": tautology,
            "exact_memory_reads": [{"bytes": 4}],
        }]))

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

    def test_linked_shallow_wrapper_applies_parameterized_environment(self):
        source = _lean_acceptance_linked_shallow_node(
            {"node_id": 2}, parameterized_environment=True
        )

        self.assertIn(
            "exact acceptanceLinkedRunningNodeRefinedOfShallow",
            source,
        )
        self.assertIn(
            "(acceptanceRunningNode2Refined originalEnvironment "
            "candidateEnvironment environmentRefines)",
            source,
        )
        lift = _lean_acceptance_linked_shallow_lift(
            parameterized_environment=True
        )
        self.assertEqual(
            lift.count("LinkedRunningProductNodeStepRefined.of_shallow"), 1
        )

    def test_launch_check_ranges_are_exact_and_reject_invalid_width(self):
        self.assertEqual(
            _launch_check_ranges(2500, 1024),
            [(0, 1024), (1024, 1024), (2048, 452)],
        )
        with self.assertRaisesRegex(StageAInputError, "must be positive"):
            _launch_check_ranges(2500, 0)

    def test_launch_structural_image_ranges_preserve_exact_coverage(self):
        ranges = _launch_structural_image_ranges(
            image_base=0x400001,
            span_start=0,
            span_size=24,
            excluded_ranges=[(7, 11), (9, 13), (30, 34)],
            structurally_immutable=True,
        )
        self.assertEqual(
            ranges,
            [
                (0, 3, False),
                (3, 4, True),
                (7, 8, False),
                (15, 8, True),
                (23, 1, False),
            ],
        )
        self.assertEqual(sum(size for _start, size, _ in ranges), 24)
        self.assertEqual(
            [start for start, _size, structural in ranges if structural],
            [3, 15],
        )
        self.assertEqual(
            _launch_structural_image_ranges(
                image_base=0x400000,
                span_start=4,
                span_size=8,
                excluded_ranges=[],
                structurally_immutable=False,
            ),
            [(4, 8, False)],
        )

    def test_launch_proof_aggregation_forms_balanced_module_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = _pe32_image_with_writable_data(
                b"\xeb\xfe", relocation_offsets=[]
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(image)
            candidate.write_bytes(image)
            contract = self._write_contract(
                root / "relation.json", region_size=2
            )
            prepared = root / "prepared"
            aggregation_environment = {
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_AGGREGATION_FANOUT":
                    "8",
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_STACK_CHECK_CHUNK":
                    "64",
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_CHECK_CHUNK": "1",
            }

            with patch.dict(os.environ, aggregation_environment):
                result = stage_a_prepare_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=prepared,
                )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["linked_acceptance"]["status"],
                "ready",
                result,
            )
            self.assertEqual(
                result["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )
            graph = json.loads(
                (prepared / "module-graph.json").read_text(encoding="utf-8")
            )
            modules = graph["modules"]
            check_imports = modules[
                "RelationalLaunchCheckCertificate"
            ]["imports"]
            self.assertLessEqual(len(check_imports), 3, check_imports)
            self.assertFalse(
                any("Leaf" in imported for imported in check_imports),
                check_imports,
            )
            self.assertIn(
                "RelationalLaunchStackMemoryAggregateLevel1Node0",
                check_imports,
            )

            stack_level0 = sorted(
                module for module in modules
                if module.startswith(
                    "RelationalLaunchStackMemoryAggregateLevel0Node"
                )
            )
            self.assertEqual(len(stack_level0), 8, stack_level0)
            self.assertTrue(any(
                module.startswith(
                    "RelationalLaunchCandidateImageSpan2AggregateLevel0Node"
                )
                for module in modules
            ))
            stack_root_imports = modules[
                "RelationalLaunchStackMemoryAggregateLevel1Node0"
            ]["imports"]
            self.assertEqual(
                [
                    imported for imported in stack_root_imports
                    if imported.startswith(
                        "RelationalLaunchStackMemoryAggregateLevel0Node"
                    )
                ],
                stack_level0,
            )
            for node_index, module in enumerate(stack_level0):
                leaf_imports = [
                    imported for imported in modules[module]["imports"]
                    if imported.startswith("RelationalLaunchStackMemoryLeaf")
                ]
                self.assertEqual(
                    leaf_imports,
                    [
                        f"RelationalLaunchStackMemoryLeaf{leaf_index}"
                        for leaf_index in range(node_index * 8, node_index * 8 + 8)
                    ],
                )

            aggregate_modules = [
                module for module in modules
                if module.startswith("RelationalLaunch")
                and "Aggregate" in module
            ]
            self.assertTrue(aggregate_modules)
            for module in aggregate_modules:
                proof_imports = [
                    imported for imported in modules[module]["imports"]
                    if imported != "RelationalLaunchProofAggregation"
                ]
                self.assertLessEqual(len(proof_imports), 8, (module, proof_imports))
                aggregate_source = (
                    prepared / "lean" / "StageA" / f"{module}.lean"
                ).read_text(encoding="utf-8")
                self.assertNotIn("sorry", aggregate_source)
                self.assertNotIn("native_decide", aggregate_source)

            reachable = set()
            pending = ["RelationalLaunchCheckCertificate"]
            while pending:
                module = pending.pop()
                if module in reachable:
                    continue
                reachable.add(module)
                pending.extend(modules[module]["imports"])
            launch_leaves = {
                module for module in modules
                if module.startswith("RelationalLaunch") and "Leaf" in module
            }
            self.assertTrue(launch_leaves)
            self.assertLessEqual(launch_leaves, reachable)

            launch_checks = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchCheckCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertNotIn("Leaf", launch_checks.split("namespace", 1)[0])
            self.assertIn(
                "exact consoleLaunchStackMemoryAggregateLevel1Node0Step7Checked",
                launch_checks,
            )
            self.assertIn("IndexedBoolCertificate.holds_of_ranges", launch_checks)

            repeated = root / "repeated"
            with patch.dict(os.environ, aggregation_environment):
                repeated_result = stage_a_prepare_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=repeated,
                )
            self.assertEqual(
                repeated_result["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )
            repeated_graph = json.loads(
                (repeated / "module-graph.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                {
                    module: metadata for module, metadata in modules.items()
                    if module.startswith("RelationalLaunch")
                },
                {
                    module: metadata
                    for module, metadata in repeated_graph["modules"].items()
                    if module.startswith("RelationalLaunch")
                },
            )

            aggregate_path = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchStackMemoryAggregateLevel1Node0.lean"
            )
            aggregate_path.write_text(
                aggregate_path.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(StageAInputError, "source hash"):
                _validate_prepared_relational(prepared)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for PE TLS parsing")
    def test_formal_tls_directory_and_callback_parsing(self):
        absent = _pe32_tls_image((), include_tls=False)
        two_callbacks = _pe32_tls_image((0x1000, 0x1010))
        writable_callbacks = _pe32_tls_image(
            (0x1000, 0x1010), callback_array_writable=True
        )
        writable_directory = bytearray(_pe32_tls_image(
            (0x1000, 0x1010), callback_array_writable=True
        ))
        # Keep the callback array itself in immutable headers while leaving the
        # TLS directory's AddressOfCallbacks word in writable image data.
        struct.pack_into("<I", writable_directory, 0x40C, 0x4001E0)
        struct.pack_into(
            "<III", writable_directory, 0x1E0, 0x401000, 0x401010, 0
        )
        writable_directory = bytes(writable_directory)
        malformed_callback = _pe32_tls_image((0x1000, 0x3000))
        unterminated = _pe32_tls_image((0x1000,), terminate_callbacks=False)

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            for name, image in {
                "absent": absent,
                "two": two_callbacks,
                "writable": writable_callbacks,
                "writable-directory": writable_directory,
                "malformed": malformed_callback,
                "unterminated": unterminated,
            }.items():
                (lean_dir / f"{name}.exe").write_bytes(image)
            self.assertEqual(
                _parse_stage_a_pe(lean_dir / "absent.exe").tls_callback_rvas, ()
            )
            self.assertEqual(
                _parse_stage_a_pe(lean_dir / "two.exe").tls_callback_rvas,
                (0x1000, 0x1010),
            )
            self.assertTrue(
                _parse_stage_a_pe(lean_dir / "two.exe").tls_callback_array_immutable
            )
            self.assertFalse(
                _parse_stage_a_pe(
                    lean_dir / "writable.exe"
                ).tls_callback_array_immutable
            )
            self.assertFalse(
                _parse_stage_a_pe(
                    lean_dir / "writable-directory.exe"
                ).tls_callback_array_immutable
            )
            self.assertIsNotNone(
                _parse_stage_a_pe(
                    lean_dir / "malformed.exe"
                ).tls_callback_parse_error
            )
            self.assertIsNotNone(
                _parse_stage_a_pe(
                    lean_dir / "unterminated.exe"
                ).tls_callback_parse_error
            )
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            shutil.copyfile(source_root / "X87.lean", stage_a / "X87.lean")
            shutil.copyfile(source_root / "Formal.lean", stage_a / "Formal.lean")
            (stage_a / "FormalTlsParsing.lean").write_text(
                "import StageA.Formal\n\n"
                "namespace StageA.FormalTlsParsingTests\n\n"
                "open StageA.Formal\n\n"
                "set_option maxRecDepth 1000000\n"
                "set_option maxHeartbeats 0\n\n"
                f"def absentImage : Bytes := {list(absent)}\n\n"
                f"def twoCallbackImage : Bytes := {list(two_callbacks)}\n\n"
                f"def writableCallbackImage : Bytes := {list(writable_callbacks)}\n\n"
                f"def writableDirectoryImage : Bytes := {list(writable_directory)}\n\n"
                f"def malformedCallbackImage : Bytes := {list(malformed_callback)}\n\n"
                f"def unterminatedImage : Bytes := {list(unterminated)}\n\n"
                "def expectedTlsDirectory : PETlsDirectory32 := {\n"
                "  rawDataStartVa := 0x402080\n"
                "  rawDataEndVa := 0x402084\n"
                "  indexVa := 0x402084\n"
                "  callbacksVa := 0x402040\n"
                "  zeroFillSize := 0\n"
                "  characteristics := 0\n"
                "}\n\n"
                "example :\n"
                "    (parsePE32 absentImage).bind parseTlsDirectory32 = some none := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 absentImage).bind parseTlsCallbackRvas = some [] := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 twoCallbackImage).bind parseTlsDirectory32 =\n"
                "      some (some expectedTlsDirectory) := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 twoCallbackImage).bind parseTlsCallbackRvas =\n"
                "      some [0x1000, 0x1010] := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 twoCallbackImage).map tlsCallbackArrayImmutable =\n"
                "      some true := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 writableCallbackImage).map tlsCallbackArrayImmutable =\n"
                "      some false := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 writableDirectoryImage).bind parseTlsCallbackRvas =\n"
                "      some [0x1000, 0x1010] := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 writableDirectoryImage).map tlsCallbackArrayImmutable =\n"
                "      some false := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 malformedCallbackImage).bind parseTlsCallbackRvas = none := by\n"
                "  decide\n\n"
                "example :\n"
                "    (parsePE32 unterminatedImage).bind parseTlsCallbackRvas = none := by\n"
                "  decide\n\n"
                "end StageA.FormalTlsParsingTests\n",
                encoding="utf-8",
            )

            lean = _run_lean_relational(lean_dir, bundle="FormalTlsParsing")

        self.assertEqual(lean["status"], "checked", lean)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for TLS root proofs")
    def test_tls_callbacks_become_lean_checked_launch_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = _pe32_tls_image((0x1020, 0x1010))
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
                    {"id": 1, "original_rva": 0x1010, "candidate_rva": 0x1010},
                    {"id": 2, "original_rva": 0x1020, "candidate_rva": 0x1020},
                ],
                "regions": [
                    {
                        "id": "entry", "root": True,
                        "original": {"rva": 0x1000, "size": 1},
                        "candidate": {"rva": 0x1000, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "tls-callback-1", "root": False,
                        "original": {"rva": 0x1010, "size": 3},
                        "candidate": {"rva": 0x1010, "size": 3},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "tls-callback-2", "root": False,
                        "original": {"rva": 0x1020, "size": 3},
                        "candidate": {"rva": 0x1020, "size": 3},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [
                    {"id": "gap-1", "side": "both", "rva": 0x1001, "size": 15},
                    {"id": "gap-2", "side": "both", "rva": 0x1013, "size": 13},
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
            self.assertEqual(
                result["acceptance"]["status"],
                "ready",
                result["acceptance"],
            )
            self.assertEqual(
                result["acceptance"]["launch"]["tls_callback_node_ids"],
                [2, 1],
            )
            self.assertEqual(
                result["acceptance"]["launch"]["continuation_target_ids"],
                [1, 0],
            )
            normalized = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                normalized["launch"]["tls_callback_target_ids"], [2, 1]
            )
            callback_windows = {
                region_index: [
                    window for window in normalized["regions"][region_index].get(
                        "stack_windows", []
                    )
                    if window["original_register"] == "esp"
                    and window["candidate_register"] == "esp"
                ]
                for region_index in (1, 2)
            }
            self.assertEqual(len(callback_windows[2]), 1)
            self.assertEqual(len(callback_windows[1]), 1)
            self.assertGreaterEqual(callback_windows[2][0]["bytes_above"], 32)
            self.assertGreaterEqual(callback_windows[1][0]["bytes_above"], 16)
            graph = json.loads(
                (prepared / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(graph["root_node_ids"], [0, 1, 2])
            static_context = (
                prepared / "lean" / "StageA" / "RelationalStaticContextBase.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("tlsCallbackTargetIds := [2, 1]", static_context)
            self.assertIn("targetId := 1, kind := .tlsInitializer", static_context)
            self.assertIn("targetId := 2, kind := .tlsInitializer", static_context)
            launch_definition = (
                prepared / "lean" / "StageA" / "RelationalLaunchDefinition.lean"
            ).read_text(encoding="utf-8")
            for offset in (4, 8, 12):
                self.assertIn(
                    f"originalOffset := {offset}, candidateOffset := {offset}",
                    launch_definition,
                )
            acceptance_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(
                    (prepared / "lean" / "StageA").glob(
                        "RelationalAcceptanceChunk*.lean"
                    )
                )
            )
            self.assertIn("exactWordTransfers := [", acceptance_source)

            checked = _run_lean_relational(
                prepared / "lean", bundle="RelationalStaticContext"
            )
            self.assertEqual(checked["status"], "checked", checked)

            acceptance_checked = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(
                acceptance_checked["status"], "checked", acceptance_checked
            )

            negative = (
                prepared / "lean" / "StageA" / "RelationalTlsRootNegative.lean"
            )
            negative.write_text(
                "import StageA.RelationalStaticContext\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Relational\n\n"
                "def omittedTlsRootsContext : StaticProofContext := {\n"
                "  staticProofContext with\n"
                "  roots := [{ targetId := 0, kind := .entrypoint }]\n"
                "}\n\n"
                "def reorderedTlsCallbacksContext : StaticProofContext := {\n"
                "  staticProofContext with tlsCallbackTargetIds := [1, 2]\n"
                "}\n\n"
                "theorem omittedTlsRootsRejected :\n"
                "    tlsLaunchInventoryValid omittedTlsRootsContext = false := by\n"
                "  decide\n\n"
                "theorem reorderedTlsCallbacksRejected :\n"
                "    tlsLaunchInventoryValid reorderedTlsCallbacksContext = false := by\n"
                "  decide\n\n"
                "end StageA.GeneratedRelational\n",
                encoding="utf-8",
            )
            negative_checked = _run_lean_relational(
                prepared / "lean", bundle="RelationalTlsRootNegative"
            )
            self.assertEqual(negative_checked["status"], "checked", negative_checked)

            writable_image = bytearray(_pe32_tls_image(
                (0x1010, 0x1020), callback_array_writable=True
            ))
            # Callback 0 rewrites callback slot 1 to executable zero padding at
            # RVA 0x101e. A launch model that snapshots the on-disk inventory
            # would otherwise omit that runtime entry surface.
            writable_image[0x210:0x21d] = (
                b"\xc7\x05" + struct.pack("<I", 0x402044)
                + struct.pack("<I", 0x40101E) + b"\xc2\x0c\x00"
            )
            writable_original = root / "writable-original.exe"
            writable_candidate = root / "writable-candidate.exe"
            writable_original.write_bytes(bytes(writable_image))
            writable_candidate.write_bytes(bytes(writable_image))
            writable_contract_data = json.loads(
                contract.read_text(encoding="utf-8")
            )
            callback_region = next(
                region
                for region in writable_contract_data["regions"]
                if region["id"] == "tls-callback-1"
            )
            callback_region["original"]["size"] = 13
            callback_region["candidate"]["size"] = 13
            callback_gap = next(
                padding
                for padding in writable_contract_data["padding"]
                if padding["id"] == "gap-2"
            )
            callback_gap["rva"] = 0x101D
            callback_gap["size"] = 3
            writable_contract = root / "writable-relation.json"
            writable_contract.write_text(
                json.dumps(writable_contract_data), encoding="utf-8"
            )
            writable_result = stage_a_prepare_relational(
                original=writable_original,
                candidate=writable_candidate,
                relation_contract=writable_contract,
                out=root / "writable-prepared",
            )
            self.assertEqual(writable_result["verdict"], "incomplete", writable_result)
            self.assertIn(
                "pre_entry_tls_callback_array_mutable",
                {
                    issue["category"]
                    for issue in writable_result["issues"]
                },
            )
            self.assertFalse(
                (root / "writable-prepared" / "whole-program-acceptance.json").exists()
            )

            wrong_pop_image = _pe32_tls_image(
                (0x1020, 0x1010), callback_pop_bytes=8
            )
            wrong_original = root / "wrong-pop-original.exe"
            wrong_candidate = root / "wrong-pop-candidate.exe"
            wrong_original.write_bytes(wrong_pop_image)
            wrong_candidate.write_bytes(wrong_pop_image)
            wrong_result = stage_a_prepare_relational(
                original=wrong_original,
                candidate=wrong_candidate,
                relation_contract=contract,
                out=root / "wrong-pop-prepared",
            )
            self.assertEqual(wrong_result["status"], "prepared", wrong_result)
            self.assertEqual(
                wrong_result["acceptance"]["status"], "incomplete",
                wrong_result["acceptance"],
            )
            self.assertTrue(
                {
                    "return_active_frame_location_unchecked",
                    "return_node_profile_unmet",
                    "return_runtime_frame_claim_missing",
                }
                & {
                    blocker["code"]
                    for blocker in wrong_result["acceptance"]["blockers"]
                },
                wrong_result["acceptance"],
            )

    def test_protocol_contract_without_decoded_site_cannot_reach_acceptance(self):
        plan = _whole_program_acceptance_plan(
            {
                "machine_import_call_contracts": [{
                    "id": 3,
                    "import": {"dll": "msvcrt.dll", "symbol": "exit"},
                    "disposition": "protocol",
                }],
                "regions": [],
            },
            [],
            {
                "nodes": [],
                "edges": [],
                "root_node_ids": [],
                "evidence": {"reachable_product_local_complete": False},
            },
            {"edges": [], "regions": []},
            [],
            [],
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertEqual(plan["protocol_callback_node_ids"], [])
        self.assertIn(
            "reachable_product_local_incomplete",
            {blocker["code"] for blocker in plan["blockers"]},
        )
        self.assertNotEqual(plan["profile"], "stateful-external-protocol-v1")

    def test_console_launch_rejects_dll_and_export_entry_surfaces(self):
        def plan(launch_profile: dict[str, Any]) -> dict[str, Any]:
            return _whole_program_acceptance_plan(
                {"machine_import_call_contracts": [], "regions": []},
                [],
                {
                    "nodes": [],
                    "edges": [],
                    "root_node_ids": [],
                    "evidence": {"reachable_product_local_complete": False},
                },
                {"edges": [], "regions": []},
                [],
                [],
                launch_profile=launch_profile,
            )

        dll = plan({
            "original_is_dll": True,
            "candidate_is_dll": True,
            "original_exports": (),
            "candidate_exports": (),
        })
        exported = plan({
            "original_exports": ({
                "ordinal": 1,
                "name": "entry",
                "rva": 0x1000,
                "kind": "code",
                "forwarder": None,
            },),
            "candidate_exports": (),
        })
        malformed = plan({
            "original_exports": None,
            "candidate_exports": (),
            "original_export_parse_error": "truncated export table",
        })

        self.assertIn(
            "console_launch_dll_unsupported",
            {blocker["code"] for blocker in dll["blockers"]},
        )
        self.assertIn(
            "console_launch_exports_unsupported",
            {blocker["code"] for blocker in exported["blockers"]},
        )
        self.assertIn(
            "console_launch_export_inventory_unparsed",
            {blocker["code"] for blocker in malformed["blockers"]},
        )

    def test_loader_diagnostics_fail_closed_without_authorizing_acceptance(self):
        def plan(loader_diagnostics: dict[str, Any]) -> dict[str, Any]:
            return _whole_program_acceptance_plan(
                {"machine_import_call_contracts": [], "regions": []},
                [],
                {
                    "nodes": [],
                    "edges": [],
                    "root_node_ids": [],
                    "evidence": {"reachable_product_local_complete": False},
                },
                {"edges": [], "regions": []},
                [],
                [],
                launch_profile={
                    "original_exports": (),
                    "candidate_exports": (),
                    "original_loader_diagnostics": loader_diagnostics,
                    "candidate_loader_diagnostics": loader_diagnostics,
                },
            )

        warning = {
            "policy": "pe32-console-preferred-base-v1",
            "status": "conditional-launch",
            "authorizes_stage_a": False,
            "diagnostics": [{
                "severity": "warning",
                "code": "dynamic_base_requires_preferred_base",
                "message": "preferred-base launch is required",
            }],
        }
        invalid = {
            "policy": "pe32-console-preferred-base-v1",
            "status": "invalid",
            "authorizes_stage_a": False,
            "diagnostics": [{
                "severity": "error",
                "code": "section_virtual_overlap",
                "message": "mapped section spans overlap",
            }],
        }

        warning_plan = plan(warning)
        invalid_plan = plan(invalid)

        self.assertNotIn(
            "loader_image_invalid",
            {blocker["code"] for blocker in warning_plan["blockers"]},
        )
        self.assertEqual(
            warning_plan["launch"]["original_loader_diagnostics"], warning
        )
        self.assertIn(
            "loader_image_invalid",
            {blocker["code"] for blocker in invalid_plan["blockers"]},
        )

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

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for sharded relational proofs")
    def test_sharded_local_proof_uses_canonical_static_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x89\xd8\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            report = root / "report"

            with patch.dict(os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            self.assertTrue(
                result["claim_scope"]["whole_program_observational_equivalence"]
            )
            shard = (report / "lean" / "StageA" / "RelationalProofShard0.lean").read_text(
                encoding="utf-8"
            )
            definitions = (
                report / "lean" / "StageA" / "RelationalDefinitionsShard0.lean"
            ).read_text(encoding="utf-8")
            bundle = (report / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            static_context = (
                report / "lean" / "StageA" / "RelationalStaticContext.lean"
            ).read_text(encoding="utf-8")
            closure_data = (
                report / "lean" / "StageA" / "RelationalProofClosureData.lean"
            ).read_text(encoding="utf-8")
            static_usage = (
                report / "lean" / "StageA" /
                "RelationalProofStaticUsageCertificate.lean"
            ).read_text(encoding="utf-8")
            static_usage_leaf = (
                report / "lean" / "StageA" /
                "RelationalProofStaticUsageLeaf0.lean"
            ).read_text(encoding="utf-8")
            static_usage_chunk = (
                report / "lean" / "StageA" /
                "RelationalProofStaticUsageChunk0.lean"
            ).read_text(encoding="utf-8")
            region_index_data = (
                report / "lean" / "StageA" /
                "RelationalProofRegionIndexData.lean"
            ).read_text(encoding="utf-8")
            original_coverage_data = (
                report / "lean" / "StageA" /
                "RelationalProofOriginalCoverageData.lean"
            ).read_text(encoding="utf-8")
            candidate_coverage_data = (
                report / "lean" / "StageA" /
                "RelationalProofCandidateCoverageData.lean"
            ).read_text(encoding="utf-8")
            original_decode = (
                report / "lean" / "StageA" / "RelationalProofOriginalDecodeChunk0.lean"
            ).read_text(encoding="utf-8")
            candidate_decode = (
                report / "lean" / "StageA" / "RelationalProofCandidateDecodeChunk0.lean"
            ).read_text(encoding="utf-8")
            direct = (
                report / "lean" / "StageA" / "RelationalProofDirectChunk0.lean"
            ).read_text(encoding="utf-8")
            region_chunk = (
                report / "lean" / "StageA" / "RelationalRegionChunk0.lean"
            ).read_text(encoding="utf-8")
            region_chunks = (
                report / "lean" / "StageA" / "RelationalRegionChunks.lean"
            ).read_text(encoding="utf-8")
            external_call_sites = (
                report / "lean" / "StageA" / "RelationalExternalCallSites.lean"
            ).read_text(encoding="utf-8")
            closure = (
                report / "lean" / "StageA" / "RelationalProofClosureBase.lean"
            ).read_text(encoding="utf-8")
            pullback = (
                report / "lean" / "StageA" / "RelationalMemoryPullbackChunk0.lean"
            ).read_text(encoding="utf-8")
            segment_refinement = (
                report / "lean" / "StageA" / "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            proof_ir = json.loads(
                (report / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            product_graph = json.loads(
                (report / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
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
            self.assertIn("import StageA.RelationalRegionChunk0", direct)
            self.assertNotIn("import StageA.RelationalRegionChunks\n", direct)
            self.assertIn("import StageA.RelationalDefinitionsShard0", region_chunk)
            self.assertIn("def regionChunk0", region_chunk)
            self.assertIn("import StageA.RelationalRegionChunk0", region_chunks)
            self.assertIn(
                "import StageA.RelationalEnvironment", external_call_sites
            )
            self.assertIn(
                "externalCallSitesStructurallyValid", external_call_sites
            )
            self.assertIn("structuralChecked", closure)
            self.assertNotIn("RelationalProofDirectChunk", bundle)
            self.assertNotIn("allDirectRegionsChecked", bundle)
            self.assertIn("candidateRelationalEvidenceBundle", bundle)
            self.assertNotIn("RelationalImageCertificate proofBundle", bundle)
            self.assertIn("staticProofContextChecked", static_context)
            self.assertIn("StaticProofContext.StructurallyValid staticProofContext", bundle)
            self.assertIn("allRegionsUseStaticContextChecked", static_usage)
            self.assertIn("regionChunk0UsesStaticContextChecked", static_usage)
            self.assertIn("staticUsageLeaf0Checked", static_usage_leaf)
            self.assertIn("regionChunk0StaticUsagePartition", static_usage_chunk)
            self.assertIn("regionIndexChunk0", region_index_data)
            self.assertIn("def originalCoverage", original_coverage_data)
            self.assertIn("def candidateCoverage", candidate_coverage_data)
            self.assertIn(
                "import StageA.RelationalProofOriginalCoverageData", closure_data
            )
            self.assertIn(
                "import StageA.RelationalProofCandidateCoverageData", closure_data
            )
            self.assertNotIn("SortedSpanCertificate := {", closure_data)
            self.assertNotIn("def allRegionIndex", closure_data)
            self.assertLess(len(closure_data), 5000)
            self.assertIn("segmentRefinementEdge0Checked", segment_refinement)
            self.assertIn("RelationalSegmentRefinement", segment_refinement)
            self.assertIn("localCodeTargetIds := [0]", segment_refinement)
            self.assertIn("localValueTargetIds := []", segment_refinement)
            self.assertIn("LocalCodeTargetsResolved", segment_refinement)
            self.assertIn("codeMap.resolveIds", segment_refinement)
            self.assertIn(
                "import StageA.RelationalStaticContextBase", segment_refinement
            )
            self.assertNotIn(
                "import StageA.RelationalStaticContext\n", segment_refinement
            )
            segment_certificate = (
                report / "lean" / "StageA" /
                "RelationalSegmentRefinementCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalSegmentRefinementChunk0",
                segment_certificate,
            )
            self.assertIn(
                "generatedSegmentRefinementCertificateChecked",
                segment_certificate,
            )
            self.assertIn(
                "import StageA.RelationalSegmentRefinementCertificate",
                bundle,
            )
            self.assertIn("GeneratedSegmentRefinementCertificate", bundle)
            self.assertIn(
                "import StageA.RelationalProductNodeCoverageCertificate", bundle
            )
            product_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductGraphCertificate.lean"
            ).read_text(encoding="utf-8")
            edge_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductEdgeRefinementCertificate.lean"
            ).read_text(encoding="utf-8")
            node_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductNodeCoverageCertificate.lean"
            ).read_text(encoding="utf-8")
            edge_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductEdgeRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            node_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductNodeCoverageChunk0.lean"
            ).read_text(encoding="utf-8")
            reachability_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductReachabilityCertificate.lean"
            ).read_text(encoding="utf-8")
            reachability_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductReachabilityChunk0.lean"
            ).read_text(encoding="utf-8")
            decoded_control_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductDecodedControlCertificate.lean"
            ).read_text(encoding="utf-8")
            decoded_control_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductDecodedControlChunk0.lean"
            ).read_text(encoding="utf-8")
            reachable_local_certificate = (
                report / "lean" / "StageA" /
                "RelationalReachableProductLocalCertificate.lean"
            ).read_text(encoding="utf-8")
            reachable_node_chunk = (
                report / "lean" / "StageA" /
                "RelationalReachableProductNodeChunk0.lean"
            ).read_text(encoding="utf-8")
            reachable_edge_chunk = (
                report / "lean" / "StageA" /
                "RelationalReachableProductEdgeChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertNotIn("segmentRefinementEdge0Spec", product_certificate)
            self.assertIn(
                "CompleteProductEdgeRefinementCertificate", edge_certificate
            )
            self.assertIn("allProductEdgesRefinedChecked", edge_certificate)
            self.assertIn(
                "GeneratedPartialProductEdgeRefinementCertificate", edge_certificate
            )
            self.assertIn("productEdge0Refined", edge_chunk)
            self.assertIn(
                "GeneratedPartialProductNodeCoverageCertificate", node_certificate
            )
            self.assertIn("allCoveredProductNodesChecked", node_certificate)
            self.assertIn("productNode0UnconditionalBehaviorCovered", node_chunk)
            self.assertIn(
                "GeneratedDeclaredGraphReachabilityCertificate",
                reachability_certificate,
            )
            self.assertIn("productReachabilityNodesChecked", reachability_certificate)
            self.assertIn("nodeClosedAt", reachability_chunk)
            self.assertIn(
                "GeneratedPartialDecodedControlCompletenessCertificate",
                decoded_control_certificate,
            )
            self.assertIn(
                "productNode0DecodedControlEdgesComplete", decoded_control_chunk
            )
            self.assertIn("originalBehavior0CheckedDecoded", decoded_control_chunk)
            self.assertIn(
                "GeneratedPartialReachableProductLocalCertificate",
                reachable_local_certificate,
            )
            self.assertIn(
                "def reachableProductLocalCertificate",
                reachable_local_certificate,
            )
            self.assertIn(
                "productNode0DecodedControlEdgesComplete",
                reachable_node_chunk,
            )
            self.assertIn("productEdge0Refined", reachable_edge_chunk)
            self.assertIn(
                "generatedPartialReachableProductLocalCertificateChecked",
                bundle,
            )
            self.assertEqual(
                product_graph["counts"],
                {
                    "covered_nodes": 1,
                    "declared_reachability_control_closed": True,
                    "decoded_control_complete_nodes": 1,
                    "decoded_control_incomplete_nodes": 0,
                    "edges": 1,
                    "external_proved_edges": 0,
                    "incomplete_edges": 0,
                    "locally_refined_edges": 1,
                    "nodes": 1,
                    "proved_edges": 1,
                    "declared_reachable_covered_nodes": 1,
                    "declared_reachable_nodes": 1,
                    "declared_reachable_uncovered_nodes": 0,
                    "outside_declared_reachability_nodes": 0,
                    "potential_reachable_nodes": 1,
                    "potential_reachable_feasible_edges": 1,
                    "potential_unrepresented_control_edges": 0,
                    "terminating_call_continuations": 0,
                    "reachability_truncated_by_control_frontier": False,
                    "reachable_decoded_control_frontier_nodes": 0,
                    "reachable_feasible_edges": 1,
                    "reachable_local_refinement_frontier_edges": 0,
                    "reachable_locally_refined_edges": 1,
                    "reachable_product_local_complete": True,
                    "roots": 1,
                    "uncovered_nodes": 0,
                },
            )
            self.assertTrue(product_graph["evidence"]["complete"])
            self.assertEqual(product_graph["evidence"]["covered_node_ids"], [0])
            self.assertEqual(
                product_graph["evidence"]["declared_reachable_node_ids"], [0]
            )
            self.assertEqual(
                product_graph["evidence"]["declared_reachable_bits"], [True]
            )
            self.assertEqual(
                product_graph["evidence"]["decoded_control_complete_node_ids"], [0]
            )
            self.assertTrue(
                product_graph["evidence"]["reachable_product_local_complete"]
            )
            self.assertEqual(
                product_graph["evidence"][
                    "reachable_decoded_control_frontier_node_ids"
                ],
                [],
            )
            self.assertEqual(
                product_graph["edges"][0]["original_guard"],
                {"op": "bool_constant", "value": True},
            )
            self.assertEqual(
                product_graph["edges"][0]["candidate_guard"],
                {"op": "bool_constant", "value": True},
            )
            self.assertEqual(
                proof_ir["product_graph_summary"]["proved_edges"], 1
            )
            self.assertEqual(
                proof_ir["segment_refinement_summary"],
                {
                    "certificate_format": "stage-a-relational-segment-certificate-v1",
                    "edges": 1,
                    "incomplete": 0,
                    "incomplete_reason_counts": {},
                    "interface": "StageA.Relational.RelationalSegmentRefinement",
                    "proved": 1,
                },
            )
            self.assertFalse(
                (report / "lean" / "StageA" / "RelationalProofGoalChunk0.lean").exists()
            )

            negative = report / "lean" / "StageA" / "RelationalStaticContextNegative.lean"
            negative.write_text(
                "import StageA.RelationalStaticContext\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "def ambiguousCodeMap : StaticCodeMap := {\n"
                "  entries := #[\n"
                "    { id := 0, regionIndex := 0, originalRva := 4096, candidateRva := 4096 },\n"
                "    { id := 1, regionIndex := 0, originalRva := 4096, candidateRva := 4096 }]\n"
                "  originalAddresses := #[\n"
                "    { targetId := 0, kind := .canonical },\n"
                "    { targetId := 1, kind := .canonical }]\n"
                "  candidateAddresses := #[\n"
                "    { targetId := 0, kind := .canonical },\n"
                "    { targetId := 1, kind := .canonical }]\n"
                "}\n\n"
                "theorem ambiguousCodeMapRejected :\n"
                "    ambiguousCodeMap.valid originalPe candidatePe = false := by decide\n\n"
                "def compatibleOverlappingDataMap : StaticDataMap := {\n"
                "  entries := #[\n"
                "    { id := 0, originalValue := 4198400, candidateValue := 4198400, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 },\n"
                "    { id := 1, originalValue := 4198400, candidateValue := 4198400, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 }]\n"
                "  originalOrder := [0, 1]\n"
                "  candidateOrder := [0, 1]\n"
                "}\n\n"
                "def ambiguousOverlappingDataMap : StaticDataMap := {\n"
                "  entries := #[\n"
                "    { id := 0, originalValue := 4198400, candidateValue := 4198400, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 },\n"
                "    { id := 1, originalValue := 4198400, candidateValue := 4198404, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 }]\n"
                "  originalOrder := [0, 1]\n"
                "  candidateOrder := [0, 1]\n"
                "}\n\n"
                "theorem compatibleOverlappingDataMapAccepted :\n"
                "    compatibleOverlappingDataMap.valid originalPe candidatePe = true := by decide\n\n"
                "theorem ambiguousOverlappingDataMapRejected :\n"
                "    ambiguousOverlappingDataMap.valid originalPe candidatePe = false := by decide\n\n"
                "end StageA.GeneratedRelational\n",
                encoding="utf-8",
            )
            negative_result = _run_lean_relational(
                report / "lean", bundle="RelationalStaticContextNegative"
            )
            self.assertEqual(negative_result["status"], "checked", negative_result)

            product_negative = (
                report / "lean" / "StageA" /
                "RelationalProductGraphNegative.lean"
            )
            product_negative.write_text(
                "import StageA.RelationalProductNodeCoverageCertificate\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "def omittedReachableProductEdgeGraph : RelationalProductGraph := {\n"
                "  relationalProductGraph with\n"
                "  nodes := #[{ id := 0, targetId := 0, root := true, "
                "outgoingEdgeIds := [] }]\n"
                "}\n\n"
                "theorem omittedReachableProductEdgeRejected :\n"
                "    omittedReachableProductEdgeGraph.edgeAtValid 0 = false := by decide\n\n"
                "theorem omittedDecodedControlExitRejected :\n"
                "    decodedControlEdgesMatch omittedReachableProductEdgeGraph 0 region0\n"
                "      originalBehavior0 candidateBehavior0 = false := by decide\n\n"
                "def falseGuardProductGraph : RelationalProductGraph := {\n"
                "  relationalProductGraph with\n"
                "  edges := #[{ relationalProductGraph.edges[0] with\n"
                "    originalGuard := .equal (.constant 0) (.constant 1) }]\n"
                "}\n\n"
                "theorem falseGuardCoverageRejected :\n"
                "    ¬ UnconditionalProductNodeBehaviorCovered staticProofContext\n"
                "      falseGuardProductGraph 0 0 segmentRefinementEdge0Spec\n"
                "      region0.inputInvariant region0.inputInvariant := by\n"
                "  intro covered\n"
                "  unfold UnconditionalProductNodeBehaviorCovered at covered\n"
                "  have nodeResolved : falseGuardProductGraph.getNode? 0 =\n"
                "      some falseGuardProductGraph.nodes[0] := by decide\n"
                "  have edgeResolved : falseGuardProductGraph.getEdge? 0 =\n"
                "      some falseGuardProductGraph.edges[0] := by decide\n"
                "  rw [nodeResolved, edgeResolved] at covered\n"
                "  rcases covered with ⟨_, _, guard, _⟩\n"
                "  have guardDiffers : falseGuardProductGraph.edges[0].originalGuard ≠\n"
                "      unconditionalProductGuard := by decide\n"
                "  exact guardDiffers guard\n\n"
                "theorem falseGuardDecodedControlExitRejected :\n"
                "    decodedControlEdgesMatch falseGuardProductGraph 0 region0\n"
                "      originalBehavior0 candidateBehavior0 = false := by decide\n\n"
                "def omittedReachableTargetGraph : RelationalProductGraph := {\n"
                "  nodes := #[\n"
                "    { id := 0, targetId := 0, root := true, outgoingEdgeIds := [0] },\n"
                "    { id := 1, targetId := 0, root := false, outgoingEdgeIds := [] }]\n"
                "  edges := #[RelationalProductEdge.mk 0 0 1 0 0 .jump\n"
                "    unconditionalProductGuard unconditionalProductGuard false]\n"
                "  rootNodeIds := [0]\n"
                "}\n\n"
                "def omittedReachableTargetEvidence :\n"
                "    RelationalProductReachabilityEvidence := {\n"
                "  reachable := #[true, false]\n"
                "}\n\n"
                "theorem omittedReachableTargetRejected :\n"
                "    RelationalProductReachabilityEvidence.nodeClosedAt\n"
                "      omittedReachableTargetGraph omittedReachableTargetEvidence 0 = false :=\n"
                "  by decide\n\n"
                "end StageA.GeneratedRelational\n",
                encoding="utf-8",
            )
            product_negative_result = _run_lean_relational(
                report / "lean", bundle="RelationalProductGraphNegative"
            )
            self.assertEqual(
                product_negative_result["status"],
                "checked",
                product_negative_result,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_whole_program_equivalence_kernel_checks_without_sorry(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            source = (stage_a / "RelationalCertificates.lean").read_text(
                encoding="utf-8"
            )
            self.assertIn("theorem pe32ProgramsEquivalent", source)
            self.assertIn("ProductStepRefinement", source)
            self.assertIn("def PE32ConsoleLaunchWorldV1.Valid", source)
            self.assertIn("structure PE32ConsoleLaunchStateRel", source)
            self.assertIn("originalImageMapped : PreferredBaseImageMemory", source)
            self.assertIn("candidateImageMapped : PreferredBaseImageMemory", source)
            self.assertNotIn("sorry", source)
            result = _run_lean_relational(
                lean_dir, bundle="RelationalCertificates"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for instruction adequacy proofs")
    def test_instruction_semantics_adequacy_rejects_ambiguous_pe_fetch(self):
        valid = bytearray(_pe32_image(b"\xeb\xfe"))
        overlapping = bytearray(valid)
        struct.pack_into("<H", overlapping, 0x86, 2)
        first_section = 0x80 + 4 + 20 + 224
        overlapping[first_section + 40:first_section + 80] = overlapping[
            first_section:first_section + 40
        ]

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "InstructionSemanticsAdequacy.lean").write_text(
                "import StageA.RelationalPEExecution\n\n"
                "namespace StageA.InstructionSemanticsAdequacyTests\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\n"
                "set_option maxHeartbeats 0\n\n"
                f"def validImage : Bytes := {list(valid)}\n\n"
                f"def overlappingImage : Bytes := {list(overlapping)}\n\n"
                "def instructionAdequate (bytes : Bytes) : Bool :=\n"
                "  match parsePE32 bytes with\n"
                "  | none => false\n"
                "  | some pe =>\n"
                "      match parseImports pe with\n"
                "      | none => false\n"
                "      | some imports =>\n"
                "          regionInstructionAdequateChecked pe imports\n"
                "            { start := 0x1000, size := 2 }\n\n"
                "def bulkRegionDecodes (bytes : Bytes) : Bool :=\n"
                "  match parsePE32 bytes with\n"
                "  | none => false\n"
                "  | some pe =>\n"
                "      match parseImports pe with\n"
                "      | none => false\n"
                "      | some imports =>\n"
                "          (regionBehaviorWithImports pe imports\n"
                "            { start := 0x1000, size := 2 }).isSome\n\n"
                "example : instructionAdequate validImage = true := by decide\n\n"
                "example : bulkRegionDecodes overlappingImage = true := by decide\n\n"
                "example : instructionAdequate overlappingImage = false := by decide\n\n"
                "end StageA.InstructionSemanticsAdequacyTests\n",
                encoding="utf-8",
            )

            lean = _run_lean_relational(
                lean_dir, bundle="InstructionSemanticsAdequacy"
            )

        self.assertEqual(lean["status"], "checked", lean)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for instruction adequacy proofs")
    def test_instruction_adequacy_aggregate_rejects_tampered_region_span(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xeb\xfe")
            candidate = self._write_pe(root / "candidate.exe", b"\xeb\xfe")
            contract = self._write_contract(
                root / "relation.json", region_size=2
            )
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared", result)
            chunk_path = (
                prepared / "lean" / "StageA" /
                "RelationalProofOriginalInstructionAdequacyChunk0.lean"
            )
            chunk_source = chunk_path.read_text(encoding="utf-8")
            expected = (
                "RegionInstructionAdequate originalPe originalImports "
                "region0.original :=\n"
                "  regionInstructionAdequate_of_checked originalPe "
                "originalImports region0.original (by decide)"
            )
            replacement = (
                "RegionInstructionAdequate originalPe originalImports "
                "{ start := region0.original.start, size := 1 } :=\n"
                "  regionInstructionAdequate_of_checked originalPe "
                "originalImports "
                "{ start := region0.original.start, size := 1 } (by decide)"
            )
            self.assertIn(expected, chunk_source)
            chunk_path.write_text(
                chunk_source.replace(expected, replacement, 1),
                encoding="utf-8",
            )

            lean = _run_lean_relational(
                prepared / "lean",
                bundle="RelationalInstructionAdequacyCertificate",
            )

            self.assertNotEqual(lean["status"], "checked", lean)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for instruction adequacy proofs")
    def test_instruction_adequacy_aggregate_composes_multiple_chunks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(
                root / "original.exe", b"\xeb\x00\xeb\xfc"
            )
            candidate = self._write_pe(
                root / "candidate.exe", b"\xeb\x00\xeb\xfc"
            )
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
                    {"id": 1, "original_rva": 0x1002, "candidate_rva": 0x1002},
                ],
                "regions": [
                    {
                        "id": "first-jump",
                        "root": True,
                        "original": {"rva": 0x1000, "size": 2},
                        "candidate": {"rva": 0x1000, "size": 2},
                        "inputs": pairs,
                        "outputs": pairs,
                    },
                    {
                        "id": "second-jump",
                        "root": False,
                        "original": {"rva": 0x1002, "size": 2},
                        "candidate": {"rva": 0x1002, "size": 2},
                        "inputs": pairs,
                        "outputs": pairs,
                    },
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            with patch.dict(os.environ, {
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PROOF_SHARD": "1",
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_DECODE_CHUNKS": "2",
            }):
                result = stage_a_prepare_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=prepared,
                )

            self.assertEqual(result["status"], "prepared", result)
            module_graph = json.loads(
                (prepared / "module-graph.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                module_graph["counts"]["instruction_adequacy_modules"], 5
            )

            lean = _run_lean_relational(
                prepared / "lean",
                bundle="RelationalInstructionAdequacyCertificate",
            )

            self.assertEqual(lean["status"], "checked", lean)

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
            self.assertEqual(launch_node["resource_class"], "light")
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

    def test_nonidentical_launch_uses_checked_memory_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = _pe32_image(b"\xeb\xfe")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(image)
            changed = bytearray(image)
            changed[2] = 1
            candidate.write_bytes(changed)
            contract = self._write_contract(root / "relation.json", region_size=2)
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["theorem"], RELATIONAL_ACCEPTANCE_THEOREM
            )
            self.assertEqual(result["acceptance"]["blockers"], [])
            self.assertEqual(
                result["acceptance"]["launch_realizability"]["profile"],
                "paired-preferred-base-import-stack-v1",
            )
            launch = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchContext.lean"
            ).read_text(encoding="utf-8")
            launch_definition = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchDefinition.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalStaticContextBase",
                launch_definition,
            )
            self.assertNotIn(
                "import StageA.RelationalProductGraphContext",
                launch_definition,
            )
            self.assertIn("def consoleLaunch", launch_definition)
            self.assertIn(
                "import StageA.RelationalLaunchDefinition",
                launch,
            )
            self.assertNotIn("RelationalAcceptanceContext", launch)
            self.assertIn(
                "def consoleLaunchOriginalMemory", launch
            )
            self.assertIn(
                "def consoleLaunchCandidateMemory", launch
            )
            self.assertIn(
                "ordinaryMemoryCandidateProjection", launch
            )

    def test_launch_realizability_accepts_related_word_self_registers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = _pe32_image(b"\xeb\xfe")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(image)
            candidate.write_bytes(image)
            contract_path = self._write_contract(
                root / "relation.json", region_size=2
            )
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            relations = [
                {
                    "original": register,
                    "candidate": register,
                    "relation": "related_word",
                }
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            contract["regions"][0]["input_relations"] = relations
            contract["regions"][0]["output_relations"] = relations
            contract_path.write_text(json.dumps(contract), encoding="utf-8")

            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract_path,
                out=prepared,
            )

            self.assertIn("launch_realizability", result["acceptance"], result)
            self.assertNotIn(
                "launch_realizability_certificate_unsupported",
                {
                    blocker["code"]
                    for blocker in result["acceptance"]["blockers"]
                },
            )
            self.assertTrue(
                (
                    prepared / "lean" / "StageA" /
                    "RelationalLaunchRealizabilityCertificate.lean"
                ).exists()
            )
            graph_context = (
                prepared / "lean" / "StageA" /
                "RelationalProductGraphContext.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalStaticContextBase\n", graph_context
            )
            self.assertNotIn(
                "import StageA.RelationalStaticContext\n", graph_context
            )
            launch_definition = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchDefinition.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalStaticContextBase\n",
                launch_definition,
            )
            self.assertNotIn(
                "import StageA.RelationalProductGraphContext\n",
                launch_definition,
            )
            launch_certificate = (
                prepared / "lean" / "StageA" /
                "RelationalLaunchRealizabilityCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalProductGraphContext\n",
                launch_certificate,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for canonical-region proofs")
    def test_whole_program_theorem_rejects_noncanonical_reachable_region(self):
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

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            chunk_path = (
                prepared / "lean" / "StageA" /
                "RelationalReachableProductNodeChunk0.lean"
            )
            chunk_source = chunk_path.read_text(encoding="utf-8")
            chunk_source = chunk_source.replace(
                "def reachableProductNodeChunk0Ids : List Nat := [0]",
                "def tamperedRegion0 : RegionRelation := "
                "{ region0 with root := false }\n\n"
                "theorem tamperedRegion0DecodedControlEdgesComplete :\n"
                "    NodeControlEdgesComplete relationalProductGraph 0 "
                "staticProofContext\n"
                "      tamperedRegion0 originalBehavior0 candidateBehavior0 := by\n"
                "  simpa [tamperedRegion0] using "
                "productNode0DecodedControlEdgesComplete\n\n"
                "def reachableProductNodeChunk0Ids : List Nat := [0]",
            )
            chunk_source = chunk_source.replace(
                "0 region0 originalBehavior0 candidateBehavior0 (by decide) "
                "(by decide) productNode0DecodedControlEdgesComplete",
                "0 tamperedRegion0 originalBehavior0 candidateBehavior0 "
                "(by decide) (by decide) "
                "tamperedRegion0DecodedControlEdgesComplete",
            )
            chunk_path.write_text(chunk_source, encoding="utf-8")

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertNotEqual(lean["status"], "checked", lean)
            self.assertIn(
                "regionById allRegions tamperedRegion0.id = some tamperedRegion0",
                lean["stdout"],
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for coverage proofs")
    def test_whole_program_theorem_rejects_tampered_executable_partition(self):
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

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            acceptance_source = (
                prepared / "lean" / "StageA" / "RelationalAcceptance.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("imageBundle := proofBundle", acceptance_source)
            self.assertIn("executableImagesCovered :=", acceptance_source)

            coverage_path = (
                prepared / "lean" / "StageA" /
                "RelationalProofOriginalCoverageData.lean"
            )
            coverage_source = coverage_path.read_text(encoding="utf-8")
            declaration = "def originalCoverage : SortedSpanCertificate := "
            start = coverage_source.index(declaration) + len(declaration)
            stop = coverage_source.index("\n\n", start)
            coverage_path.write_text(
                coverage_source[:start] + "{}" + coverage_source[stop:],
                encoding="utf-8",
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertNotEqual(lean["status"], "checked", lean)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for alias proofs")
    def test_whole_program_theorem_requires_semantic_code_alias_bridges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
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
                "code_targets": [{
                    "id": 0,
                    "original_rva": 0x1002,
                    "candidate_rva": 0x1002,
                    "original_aliases": [0x1000],
                    "candidate_aliases": [0x1000],
                }],
                "regions": [{
                    "id": "entry-loop",
                    "root": True,
                    "original": {"rva": 0x1002, "size": 2},
                    "candidate": {"rva": 0x1002, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                }],
                "padding": [{
                    "id": "entry-alias-bridge",
                    "side": "both",
                    "rva": 0x1000,
                    "size": 2,
                }],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")

            def write_image(path: Path, bridge: bytes) -> Path:
                image = bytearray(_pe32_image(bridge + b"\xeb\xfe"))
                struct.pack_into("<I", image, 0xA8, 0x1002)
                path.write_bytes(image)
                return path

            valid_original = write_image(root / "valid-original.exe", b"\x90\x90")
            valid_candidate = write_image(root / "valid-candidate.exe", b"\x90\x90")
            valid = root / "valid"
            valid_result = stage_a_prepare_relational(
                original=valid_original,
                candidate=valid_candidate,
                relation_contract=contract,
                out=valid,
            )
            self.assertEqual(valid_result["acceptance"]["status"], "ready", valid_result)
            valid_lean = _run_lean_relational(
                valid / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(valid_lean["status"], "checked", valid_lean)

            invalid_original = write_image(root / "invalid-original.exe", b"\x00\x00")
            invalid_candidate = write_image(root / "invalid-candidate.exe", b"\x00\x00")
            invalid = root / "invalid"
            invalid_result = stage_a_prepare_relational(
                original=invalid_original,
                candidate=invalid_candidate,
                relation_contract=contract,
                out=invalid,
            )
            self.assertEqual(
                invalid_result["acceptance"]["status"], "ready", invalid_result
            )
            invalid_lean = _run_lean_relational(
                invalid / "lean", bundle="RelationalAcceptance"
            )
            self.assertNotEqual(invalid_lean["status"], "checked", invalid_lean)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for launch-profile proofs")
    def test_tls_directory_is_parsed_and_rejected_by_console_launch_v1(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_tls_image(()))
            candidate.write_bytes(_pe32_tls_image(()))

            contract = self._write_contract(
                root / "relation.json", region_size=1
            )
            prepared = root / "prepared"
            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertEqual(result["acceptance"]["status"], "incomplete")
            self.assertIn(
                "pre_entry_tls_profile_unmet",
                {
                    blocker["code"]
                    for blocker in result["acceptance"]["blockers"]
                },
            )
            self.assertEqual(
                result["acceptance"]["launch"]["tls_callback_target_ids"], []
            )
            original_source = (
                prepared / "lean" / "StageA" / "RelationalProofOriginal.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("tlsDirectoryRva := 8192", original_source)
            self.assertIn("tlsDirectorySize := 24", original_source)

            negative = (
                prepared / "lean" / "StageA" / "RelationalTlsLaunchNegative.lean"
            )
            negative.write_text(
                "import StageA.RelationalCertificates\n"
                "import StageA.RelationalStaticContext\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Relational\n\n"
                "theorem tlsDirectoryParsedFromPeBytes :\n"
                "    originalPe.tlsDirectoryRva = 8192 ∧\n"
                "      originalPe.tlsDirectorySize = 24 := by decide\n\n"
                "theorem tlsConsoleLaunchV1Rejected :\n"
                "    PE32ConsoleLaunchV1.preEntryTlsAbsent staticProofContext = false :=\n"
                "  by decide\n\n"
                "end StageA.GeneratedRelational\n",
                encoding="utf-8",
            )
            checked = _run_lean_relational(
                prepared / "lean", bundle="RelationalTlsLaunchNegative"
            )
            self.assertEqual(checked["status"], "checked", checked)

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
    def test_local_proof_driver_passes_only_on_replayable_acceptance_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xeb\xfe")
            candidate = self._write_pe(root / "candidate.exe", b"\xeb\xfe")
            contract = self._write_contract(root / "relation.json", region_size=2)
            report = root / "report"

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(
                result["proof"]["theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )
            self.assertTrue(
                result["claim_scope"]["whole_program_observational_equivalence"]
            )
            self.assertTrue(result["claim_scope"]["acceptance_eligible"])
            graph = _validate_relational_module_graph(report)
            self.assertEqual(graph["root_module"], "RelationalAcceptance")
            self.assertEqual(
                graph["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )

            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "pass", replay)
            self.assertEqual(
                replay["lean_check"]["theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )

            acceptance_source = (
                report / "lean" / "StageA" / "RelationalAcceptance.lean"
            )
            acceptance_source.write_text(
                acceptance_source.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            tampered = stage_a_check_relational_proof(report=report)
            self.assertEqual(tampered["status"], "incomplete")
            self.assertFalse(tampered["checks"]["module_graph_valid"])

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

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_external_call_loop_checks_paired_environment_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = b"\xff\x15" + struct.pack("<I", iat_address) + b"\xeb\xf8"
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount",
            ))
            candidate.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount",
            ))
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
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1006, "candidate_rva": 0x1006},
                ],
                "regions": [
                    {
                        "id": "import-call", "root": True,
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
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {
                        "dll": "kernel32.dll", "symbol": "GetTickCount",
                    },
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "result_register_relations": [{
                        "register": "eax", "relation": "exact",
                    }],
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
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

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"], "paired-external-call-v1"
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["external_call", "jump"],
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for allocation proofs")
    def test_external_allocation_and_dynamic_write_close_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image_base = 0x400000
            iat_address = image_base + 0x2000 + 0x40
            code = (
                b"\xc7\x04\x24\x04\x00\x00\x00"
                + b"\xff\x15" + struct.pack("<I", iat_address)
                + b"\x89\x18\xeb\xfc"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, dll="TEST.dll", symbol="AllocateWord",
            ))
            candidate.write_bytes(_pe32_import_image(
                code, dll="TEST.dll", symbol="AllocateWord",
            ))
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
                    {"id": 1, "original_rva": 0x100d, "candidate_rva": 0x100d},
                ],
                "regions": [
                    {
                        "id": "allocate", "root": True,
                        "original": {"rva": 0x1000, "size": 13},
                        "candidate": {"rva": 0x1000, "size": 13},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "write-loop", "root": False,
                        "original": {"rva": 0x100d, "size": 4},
                        "candidate": {"rva": 0x100d, "size": 4},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "test.dll", "symbol": "AllocateWord"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "result_register_relations": [{
                        "register": "eax",
                        "relation": "dynamic_range_base",
                        "size": {"kind": "argument", "argument": 0, "scale": 1},
                        "minimum_size": 4,
                        "required_words": [{
                            "offset": 0, "relation": "related_word",
                        }],
                        "nullable": False,
                    }],
                    "memory_effect": "newDynamicRanges",
                    "memory_footprints": [],
                    "world_effect": "dynamicRanges",
                }],
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

            self.assertIn("acceptance", result, result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"], "paired-external-call-v1",
            )
            external_results = json.loads(
                (prepared / "relational-external-result-invariants.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(external_results["counts"], {
                "attached": 1, "rejected": 0,
            })
            self.assertEqual(
                external_results["attached"][0]["relation"]["required_words"],
                [{"offset": 0, "kind": "relatedWord"}],
            )
            self.assertEqual(
                external_results["attached"][0]["relation"]["active_words"],
                [],
            )
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            self.assertTrue(any(
                any(
                    write.get("kind") == "dynamic_word"
                    for write in (
                        ((obligation.get("analysis") or {}).get("certificate") or {})
                        .get("paired_prepared_writes_claim", {})
                        .get("writes", [])
                    )
                )
                for obligation in proof_ir["obligations"]
            ), proof_ir)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for protocol proofs")
    def test_protocol_call_and_callback_return_close_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xff\x15" + struct.pack("<I", iat_address)
                + b"\x31\xc0\xc3"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="ProtocolStep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="ProtocolStep"))
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
                    {"id": 1, "original_rva": 0x1006, "candidate_rva": 0x1006},
                ],
                "protocol_callback_control": {
                    "format": PROTOCOL_CALLBACK_CONTROL_FORMAT,
                    "states": [{
                        "target_id": 1,
                        "active_frame_offset": {
                            "original_register": "esp", "original": 0,
                            "candidate_register": "esp", "candidate": 0,
                        },
                        "return_invariant": {"kind": "terminal"},
                    }],
                },
                "regions": [
                    {
                        "id": "protocol-call", "root": True,
                        "original": {"rva": 0x1000, "size": 6},
                        "candidate": {"rva": 0x1000, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callback-return", "root": False,
                        "original": {"rva": 0x1006, "size": 3},
                        "candidate": {"rva": 0x1006, "size": 3},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {
                        "dll": "kernel32.dll", "symbol": "ProtocolStep",
                    },
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "disposition": "protocol",
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
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

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["external_protocol", "terminate"],
            )
            self.assertEqual(
                result["acceptance"]["protocol_callback_node_ids"], [1]
            )
            self.assertEqual(
                _validate_prepared_relational(prepared)["acceptance"]["status"],
                "ready",
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

            repeated = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "prepared-repeated",
            )
            self.assertEqual(
                repeated["acceptance"]["protocol_callback_states"],
                result["acceptance"]["protocol_callback_states"],
            )
            self.assertEqual(
                repeated["interface_manifest_sha256"],
                result["interface_manifest_sha256"],
            )

            region_input_contract = json.loads(contract.read_text(encoding="utf-8"))
            region_input_contract["protocol_callback_control"]["states"][0][
                "return_invariant"
            ] = {"kind": "region_input", "target_id": 1}
            region_input_path = root / "region-input-relation.json"
            region_input_path.write_text(
                json.dumps(region_input_contract), encoding="utf-8"
            )
            region_input = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=region_input_path,
                out=root / "prepared-region-input",
            )
            self.assertEqual(region_input["acceptance"]["status"], "incomplete")
            self.assertIn(
                "callback_return_invariant_profile_incomplete",
                {
                    blocker["code"]
                    for blocker in region_input["acceptance"]["blockers"]
                },
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for import-thunk proofs")
    def test_nested_direct_import_thunk_preserves_outer_runtime_frame_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xf7"
                b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount", dll="kernel32.dll"
            ))
            candidate.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount", dll="kernel32.dll"
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            continuation_pairs = pairs
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x100C, "candidate_rva": 0x100C},
                    {"id": 4, "original_rva": 0x100E, "candidate_rva": 0x100E},
                ],
                "regions": [
                    {
                        "id": "root-caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "root-continuation-loop", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": continuation_pairs,
                        "outputs": continuation_pairs,
                    },
                    {
                        "id": "wrapper-call-import", "root": False,
                        "original": {"rva": 0x1007, "size": 5},
                        "candidate": {"rva": 0x1007, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "wrapper-continuation-jump", "root": False,
                        "original": {"rva": 0x100C, "size": 2},
                        "candidate": {"rva": 0x100C, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "get-tick-count-import-thunk", "root": False,
                        "original": {"rva": 0x100E, "size": 6},
                        "candidate": {"rva": 0x100E, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {
                        "dll": "kernel32.dll", "symbol": "GetTickCount",
                    },
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
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

            self.assertEqual(result.get("status"), "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "jump", "call", "jump", "external_jump"],
            )
            thunk_step = result["acceptance"]["node_steps"][4]
            self.assertEqual(thunk_step["control_state"]["calls"], [3, 1])
            self.assertEqual(
                len(thunk_step["return_slot_external_jump_transfer_claims"]), 1
            )
            claim = thunk_step["return_slot_external_jump_transfer_claims"][0]
            self.assertEqual(claim["source"]["locations"][0]["original"], 4)
            transfer = claim["transfers"][0]
            self.assertEqual(transfer["boundary_target"]["original"], 0)
            self.assertEqual(claim["target"]["locations"][0]["original"], 0)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_nested_external_call_preserves_internal_runtime_frame_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\x83\xec\x04"
                b"\xc7\x04\x24\x00\x00\x00\x00"
                b"\xff\x15" + struct.pack("<I", iat_address)
                + b"\xc3"
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            pairs = [
                {"original": register, "candidate": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            ]
            preserved_pairs = [
                pair for pair in pairs
                if pair["original"] in {"ebx", "esi", "edi", "ebp"}
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x1017, "candidate_rva": 0x1017},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": preserved_pairs, "outputs": preserved_pairs,
                    },
                    {
                        "id": "callee-import-call", "root": False,
                        "original": {"rva": 0x1007, "size": 16},
                        "candidate": {"rva": 0x1007, "size": 16},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x1017, "size": 1},
                        "candidate": {"rva": 0x1017, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
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

            self.assertEqual(result.get("status"), "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "jump", "external_call", "return"],
            )
            external_step = result["acceptance"]["node_steps"][2]
            self.assertEqual(len(external_step["control_state"]["calls"]), 1)
            self.assertEqual(
                len(external_step["return_slot_external_transfer_claims"]), 1
            )
            claim = external_step["return_slot_external_transfer_claims"][0]
            self.assertEqual(claim["source"]["locations"][0]["original"], 0)
            transfer = claim["transfers"][0]
            self.assertEqual(transfer["internal_target"]["original"], 4)
            self.assertEqual(claim["target"]["locations"][0]["original"], 0)
            self.assertEqual(
                len(transfer["memory_claim"]["original_write_witnesses"]), 1
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for import-thunk proofs")
    def test_direct_import_thunk_checks_runtime_frame_and_environment_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            candidate.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
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
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "get-tick-count-import-thunk", "root": False,
                        "original": {"rva": 0x1007, "size": 6},
                        "candidate": {"rva": 0x1007, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
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

            self.assertEqual(result["acceptance"]["status"], "ready", result)
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
                result,
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "jump", "external_jump"],
            )
            sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(sites["counts"], {"candidates": 1, "gaps": 0})
            self.assertEqual(
                sites["candidates"][0]["dispatch_profile"],
                "checked_direct_import_thunk",
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
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for callback proofs")
    def test_tail_jump_import_wrapper_registers_mapped_callback_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                + b"\xeb\xfe"
                + b"\xe8\x02\x00\x00\x00"
                + b"\xeb\xf7"
                + b"\xe9\x00\x00\x00\x00"
                + b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="atexit", dll="msvcrt.dll",
            ))
            candidate.write_bytes(original.read_bytes())
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
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                    {"id": 3, "original_rva": 0x100C, "candidate_rva": 0x100C},
                    {"id": 4, "original_rva": 0x100E, "candidate_rva": 0x100E},
                    {"id": 5, "original_rva": 0x1013, "candidate_rva": 0x1013},
                ],
                "regions": [
                    {
                        "id": "outer-caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "registered-callback-continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "register-callback", "root": False,
                        "original": {"rva": 0x1007, "size": 5},
                        "candidate": {"rva": 0x1007, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "registration-continuation", "root": False,
                        "original": {"rva": 0x100C, "size": 2},
                        "candidate": {"rva": 0x100C, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "atexit-tail-wrapper", "root": False,
                        "original": {"rva": 0x100E, "size": 5},
                        "candidate": {"rva": 0x100E, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "atexit-import-thunk", "root": False,
                        "original": {"rva": 0x1013, "size": 6},
                        "candidate": {"rva": 0x1013, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "msvcrt.dll", "symbol": "atexit"},
                    "abi_template": "pe32-cdecl-v1",
                    "argument_words": 1,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "callbackRegistration",
                    "world_effect_argument": 0,
                }],
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

            self.assertEqual(result.get("status"), "prepared", result)
            self.assertEqual(result["acceptance"]["status"], "ready", result)
            sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(sites["counts"], {"candidates": 1, "gaps": 0})
            site = sites["candidates"][0]
            self.assertEqual(site["source_region_index"], 5)
            self.assertEqual(site["call_target_region_index"], 4)
            self.assertEqual(site["tail_jump_region_indices"], [4])
            self.assertEqual(len(site["tail_jump_edge_indices"]), 1)
            self.assertEqual(site["machine_contract_id"], 0)
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for external termination proofs")
    def test_nonreturning_import_thunk_terminates_whole_program_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="_amsg_exit", dll="msvcrt.dll",
            ))
            candidate.write_bytes(original.read_bytes())
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
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "syntactic-continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "amsg-exit-import-thunk", "root": False,
                        "original": {"rva": 0x1007, "size": 6},
                        "candidate": {"rva": 0x1007, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "msvcrt.dll", "symbol": "_amsg_exit"},
                    "abi_template": "pe32-cdecl-v1",
                    "argument_words": 1,
                    "disposition": "terminates",
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
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

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "external_terminate"],
            )
            terminal_step = next(
                step for step in result["acceptance"]["node_steps"]
                if step["kind"] == "external_terminate"
            )
            self.assertEqual(terminal_step["control_state"]["calls"], [1])
            self.assertEqual(
                terminal_step["machine_contract"]["disposition"], "terminates"
            )
            product_graph = json.loads(
                (prepared / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                product_graph["evidence"]["runtime_call_continuations"],
                [{"source_node_id": 0, "continuation_node_ids": [1]}],
            )
            self.assertEqual(
                product_graph["evidence"]["terminating_call_continuations"],
                [{
                    "source_node_id": 0,
                    "continuation_node_id": 1,
                    "continuation_target_id": 1,
                    "call_edge_id": 0,
                    "call_target_node_id": 2,
                    "external_jump_node_id": 2,
                    "external_site_id": int(terminal_step["external_site"]["id"]),
                    "machine_contract_id": 0,
                }],
            )
            self.assertEqual(
                product_graph["evidence"]["declared_reachable_node_ids"],
                [0, 2],
            )
            self.assertEqual(
                product_graph["evidence"]["potential_reachable_node_ids"],
                [0, 2],
            )
            self.assertEqual(
                product_graph["evidence"]["reachable_feasible_edge_ids"],
                [0],
            )
            self.assertEqual(
                result["composition_progress"]["reachability"]["rooted_node_ids"],
                [0, 2],
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            call_edge = next(
                edge for edge in register_relations["edges"]
                if edge["source_region_index"] == 0
                and edge["target_region_index"] == 2
            )
            self.assertNotIn(
                "returning_external_thunk_contract_id", call_edge
            )
            normalized_contract = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            semantic_ir = json.loads(
                (prepared / "relational-semantic-ir.json").read_text(
                    encoding="utf-8"
                )
            )
            external_sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )["candidates"]
            direct_sites = [
                site for site in external_sites
                if site.get("site_kind") == "direct_import_thunk"
            ]
            self.assertEqual(len(direct_sites), 1)
            ambiguous_graph = _relational_product_graph(
                normalized_contract,
                [
                    {
                        "original_ir": region["original"],
                        "candidate_ir": region["candidate"],
                    }
                    for region in semantic_ir["regions"]
                ],
                register_relations,
                [],
                original_image_base=0x400000,
                candidate_image_base=0x400000,
                external_call_candidates=[
                    *external_sites,
                    {**direct_sites[0], "id": int(direct_sites[0]["id"]) + 100},
                ],
            )
            self.assertEqual(
                ambiguous_graph["evidence"]["terminating_call_continuations"],
                [],
            )
            self.assertEqual(
                ambiguous_graph["evidence"]["declared_reachable_node_ids"],
                [0, 1, 2],
            )
            callsite = json.loads(
                (prepared / "relational-callsite-preservation.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(callsite["counts"]["proposal_edges"], 0)
            self.assertEqual(
                terminal_step["control_state"]["frame_offsets"][0].get(
                    "import_relations", []
                ),
                [],
            )
            self.assertEqual(
                terminal_step["control_state"]["frame_offsets"][0].get(
                    "register_relations", []
                ),
                [],
            )
            self.assertEqual(
                result["acceptance"]["launch_realizability"]["profile"],
                "paired-preferred-base-import-stack-v1",
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

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

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for relational preparation")
    def test_prepare_emits_valid_source_only_derivation_graph_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x8b\x03\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8b\x03\xeb\xfc")
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
            progress = json.loads(
                (prepared / "composition-progress.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["composition_progress"], progress)
            self.assertEqual(progress["status"], "incomplete")
            self.assertEqual(
                progress["metric_policy"]["primary"],
                "rooted_product_composition",
            )
            self.assertTrue(
                progress["metric_policy"]["local_proof_counts_are_secondary"]
            )
            graph = _validate_prepared_relational(prepared)
            self.assertEqual(graph["lean"]["trust"], 0)
            self.assertEqual(graph["root_module"], "RelationalBundle")
            self.assertIsNone(graph["expected_final_theorem"])
            self.assertEqual(graph["acceptance"]["status"], "incomplete")
            self.assertEqual(
                graph["acceptance"]["required_theorem"],
                "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
            )
            self.assertEqual(
                graph["acceptance"]["blockers"][0]["code"],
                "reachable_product_local_incomplete",
            )
            self.assertEqual(graph["acceptance"]["blockers"][0]["count"], 1)
            self.assertEqual(
                graph["modules"]["RelationalDecode"]["imports"],
                ["Formal", "RelationalX87Decode"],
            )
            self.assertIn(
                "RelationalDecode", graph["modules"]["RelationalMachine"]["imports"]
            )
            self.assertIn(
                "RelationalMachine", graph["modules"]["Relational"]["imports"]
            )
            self.assertIn(
                "RelationalStaticContext", graph["modules"]
            )
            self.assertIn("RelationalSegment", graph["modules"])
            self.assertIn("RelationalComposition", graph["modules"])
            self.assertIn("RelationalEnvironment", graph["modules"])
            self.assertIn("RelationalCertificates", graph["modules"])
            self.assertIn(
                "RelationalSegmentRefinementCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductGraphCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductEdgeRefinementCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductNodeCoverageCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductReachabilityCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductDecodedControlCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductLocalCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductLocalEvidence", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductNodeCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductEdgeCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductNodeChunk0", graph["modules"]
            )
            for module in (
                "RelationalProofRequiredInputsData",
                "RelationalProofPaddingData",
                "RelationalProofRegionIndexChunk0",
                "RelationalProofRegionIndexData",
                "RelationalProofRegionInventoryData",
                "RelationalProofStaticUsageLeaf0",
                "RelationalProofStaticUsageChunk0",
                "RelationalProofStaticUsageCertificate",
                "RelationalProofOriginalCoverageData",
                "RelationalProofCandidateCoverageData",
                "RelationalProofClosureData",
            ):
                self.assertIn(module, graph["modules"])
            self.assertNotIn(
                "RelationalSegment",
                graph["modules"]["RelationalStaticContextBase"]["imports"],
            )
            nodes = {node["id"]: node for node in graph["nodes"]}
            static_closure: set[str] = set()

            def include_static(node_id: str) -> None:
                if node_id in static_closure:
                    return
                static_closure.add(node_id)
                for dependency in nodes[node_id]["dependencies"]:
                    include_static(dependency)

            include_static("relationalstaticcontext")
            self.assertNotIn("relationalsegment", static_closure)
            segment_node = nodes["relationalsegmentrefinementcertificate"]
            self.assertNotIn(
                "relationalsegmentrefinementchunk0",
                segment_node["dependencies"],
            )
            self.assertEqual(segment_node["dependencies"], ["relationalsegment"])
            product_node = nodes["relationalproductgraphcertificate"]
            self.assertIn("relationalproductgraphchunk0", product_node["dependencies"])
            edge_node = nodes["relationalproductedgerefinementcertificate"]
            self.assertNotIn(
                "relationalproductedgerefinementchunk0",
                edge_node["dependencies"],
            )
            coverage_node = nodes["relationalproductnodecoveragecertificate"]
            self.assertNotIn(
                "relationalproductnodecoveragechunk0",
                coverage_node["dependencies"],
            )
            reachability_node = nodes["relationalproductreachabilitycertificate"]
            self.assertIn(
                "relationalproductreachabilitychunk0",
                reachability_node["dependencies"],
            )
            decoded_control_node = nodes[
                "relationalproductdecodedcontrolcertificate"
            ]
            self.assertIn(
                "relationalproductdecodedcontrolchunk0",
                decoded_control_node["dependencies"],
            )
            reachable_local_node = nodes[
                "relationalreachableproductlocalcertificate"
            ]
            self.assertIn(
                "relationalreachableproductlocalevidence",
                reachable_local_node["dependencies"],
            )
            self.assertIn(
                "relationalreachableproductnodecertificate",
                reachable_local_node["dependencies"],
            )
            self.assertIn(
                "relationalreachableproductedgecertificate",
                reachable_local_node["dependencies"],
            )
            self.assertNotIn(
                "relationalproductdecodedcontrolcertificate",
                reachable_local_node["dependencies"],
            )
            self.assertEqual(
                reachable_local_node["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalreachableproductnodechunk0"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalreachableproductedgecertificate"]["resource_class"],
                "high-memory",
            )
            self.assertNotIn("relationalproductedgerefinementchunk0", nodes)
            self.assertNotIn("relationalproductnodecoveragechunk0", nodes)
            self.assertEqual(
                nodes["relationalproductreachabilitychunk0"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalproductdecodedcontrolchunk0"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalprooforiginalcoveragedata"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalproofcandidatecoveragedata"]["resource_class"],
                "high-memory",
            )
            static_usage_pack = next(
                node for node in graph["nodes"]
                if "RelationalProofStaticUsageLeaf0" in node["modules"]
            )
            self.assertTrue(static_usage_pack["id"].startswith("static-usage-pack-"))
            self.assertEqual(static_usage_pack["resource_class"], "high-memory")
            self.assertEqual(
                nodes["relationalproofstaticusagechunk0"]["resource_class"],
                "medium",
            )
            self.assertIn(
                static_usage_pack["id"],
                nodes["relationalproofstaticusagechunk0"]["dependencies"],
            )
            self.assertEqual(
                nodes["relationalproofregionindexchunk0"]["resource_class"],
                "medium",
            )
            closure_node = nodes["relationalproofclosuredata"]
            self.assertIn(
                "relationalprooforiginalcoveragedata",
                closure_node["dependencies"],
            )
            self.assertIn(
                "relationalproofcandidatecoveragedata",
                closure_node["dependencies"],
            )
            with self.assertRaisesRegex(StageAInputError, "has no node"):
                stage_a_build_relational(
                    prepared=prepared,
                    out=root / "missing-node",
                    target_node="does-not-exist",
                )
            existing_node = graph["nodes"][0]["id"]
            with self.assertRaisesRegex(StageAInputError, "contains duplicates"):
                stage_a_build_relational(
                    prepared=prepared,
                    out=root / "duplicate-nodes",
                    target_nodes=[existing_node, existing_node],
                )
            full_build = stage_a_build_relational(
                prepared=prepared,
                out=root / "full-build",
            )
            self.assertEqual(full_build["status"], "incomplete")
            self.assertFalse(full_build["checks"]["whole_program_acceptance_ready"])
            self.assertFalse(full_build["checks"]["nix_graph_built"])
            self.assertGreater(graph["counts"]["derivations"], 1)
            self.assertTrue(any(node["id"].startswith("definitions-pack-") for node in graph["nodes"]))
            proof_packs = [
                node for node in graph["nodes"]
                if node["id"].startswith("local-proof-pack-")
            ]
            proof_shards = [
                module for module in graph["modules"]
                if module.startswith("RelationalProofShard")
                and module.removeprefix("RelationalProofShard").isdigit()
            ]
            self.assertEqual(bool(proof_packs), bool(proof_shards))
            self.assertTrue(all(
                node["resource_class"] == "medium" for node in proof_packs
            ))
            semantic_ir = json.loads(
                (prepared / "relational-semantic-ir.json").read_text(encoding="utf-8")
            )
            self.assertEqual(semantic_ir["format"], "stage-a-relational-semantic-ir-v1")
            self.assertEqual(semantic_ir["trust"]["role"], "analysis_and_proof_proposal_only")
            self.assertEqual(len(semantic_ir["regions"]), 1)
            extracted = semantic_ir["regions"][0]
            self.assertEqual(extracted["original"]["format"], "stage-a-normalized-behavior-v1")
            self.assertEqual(extracted["original"]["registers"]["eax"]["op"], "read32")
            self.assertEqual(
                extracted["original"]["registers"]["eax"]["address"],
                {"op": "input_reg", "reg": "ebx"},
            )
            self.assertEqual(extracted["original"]["outcome"]["op"], "jump")
            self.assertEqual(extracted["original"]["outcome"]["target"], 0)
            memory_contracts = json.loads(
                (prepared / "relational-memory-contracts.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                memory_contracts["format"], "stage-a-relational-memory-contracts-v1"
            )
            self.assertEqual(memory_contracts["counts"]["regions"], 1)
            self.assertEqual(memory_contracts["counts"]["read_observations"], 1)
            self.assertEqual(
                memory_contracts["counts"]["exact_pullback_pair_claims"], 1
            )
            self.assertEqual(
                memory_contracts["counts"]["edges_with_exact_pullback_pair_claims"], 1
            )
            read = memory_contracts["regions"][0]["reads"][0]
            self.assertEqual(read["status"], "paired_shape")
            self.assertEqual(
                read["original"]["pullback_support"], "lean_pullback_supported"
            )
            self.assertEqual(
                read["candidate"]["pullback_support"], "lean_pullback_supported"
            )
            self.assertEqual(
                memory_contracts["counts"]["pullback"]["original"],
                {
                    "ordinary_observations": 1,
                    "lean_pullback_supported": 1,
                    "regions_all_ordinary_reads_supported": 1,
                },
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                register_relations["format"],
                "stage-a-relational-register-relations-v1",
            )
            self.assertTrue(register_relations["converged"])
            self.assertTrue(register_relations["dataflow_complete"])
            dataflow_graph = json.loads(
                (prepared / "relational-register-dataflow-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                dataflow_graph["format"],
                "stage-a-register-dataflow-graph-v1",
            )
            self.assertFalse(dataflow_graph["acceptance_authority"])
            transfer_table = json.loads(
                (prepared / "relational-register-transfer-table.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                transfer_table["format"],
                "stage-a-register-transfer-table-v1",
            )
            self.assertEqual(
                transfer_table["graph_sha256"], dataflow_graph["graph_sha256"]
            )
            self.assertFalse(transfer_table["acceptance_authority"])
            program_graph = json.loads(
                (
                    prepared
                    / "relational-register-program-dataflow-graph.json"
                ).read_text(encoding="utf-8")
            )
            transfer_programs = json.loads(
                (
                    prepared / "relational-register-transfer-programs.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                transfer_programs["format"],
                "stage-a-register-transfer-programs-v1",
            )
            self.assertEqual(
                transfer_programs["graph_sha256"],
                program_graph["graph_sha256"],
            )
            self.assertEqual(
                program_graph, register_relations["dataflow_graph"]
            )
            self.assertEqual(transfer_programs["region_count"], 1)
            self.assertEqual(
                len(transfer_programs["propagation"]["regions"]), 1,
            )
            self.assertFalse(transfer_programs["acceptance_authority"])
            self.assertFalse(
                (prepared / "relational-register-dataflow-problem.json").exists()
            )
            dataflow_problem_seed = json.loads(
                (
                    prepared
                    / "relational-register-dataflow-problem-seed.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                dataflow_problem_seed["format"],
                "stage-a-register-dataflow-problem-seed-v2",
            )
            self.assertEqual(
                dataflow_problem_seed["original_sha256"],
                transfer_programs["original_sha256"],
            )
            self.assertEqual(
                dataflow_problem_seed["candidate_sha256"],
                transfer_programs["candidate_sha256"],
            )
            self.assertFalse(dataflow_problem_seed["acceptance_authority"])
            self.assertEqual(
                register_relations["trust"]["role"],
                "analysis_and_proof_proposal_only",
            )
            self.assertEqual(
                register_relations["counts"]["lean_exact_output_claims"], 7
            )
            self.assertEqual(
                register_relations["regions"][0]["outputs"][0]["relation"],
                "exact",
            )
            self.assertEqual(
                register_relations["counts"]["register_output_claims"], 8
            )
            self.assertEqual(
                register_relations["counts"]["fully_supported_output_regions"], 1
            )
            self.assertEqual(
                {
                    claim["register"]
                    for claim in register_relations["regions"][0][
                        "exact_output_claims"
                    ]
                },
                {"ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"},
            )
            pullback_module = (
                prepared / "lean" / "StageA" / "RelationalMemoryPullbackChunk0.lean"
            )
            self.assertTrue(pullback_module.is_file())
            pullback_source = pullback_module.read_text(encoding="utf-8")
            self.assertIn("MemoryReadPullbackEdgeClosed", pullback_source)
            self.assertIn("memoryReadPullbackEdgeClosed_of_checked", pullback_source)
            self.assertIn("ExactMemoryReadPullbackPairEdgeClosed", pullback_source)
            self.assertIn(
                "exactMemoryReadPullbackPairEdgeClosed_of_checked", pullback_source
            )
            register_module = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalRegisterRelationsChunk0.lean"
            )
            register_source = register_module.read_text(encoding="utf-8")
            self.assertIn("RegisterOutputClaim.exactMemory", register_source)
            self.assertIn(
                "import StageA.RelationalGlobalMappingContext", register_source
            )
            self.assertIn("globalCodeTargets globalValueTargets", register_source)
            global_context = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalGlobalMappingContext.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("import StageA.RelationalMachine", global_context)
            self.assertNotIn("import StageA.Relational\n", global_context)
            self.assertIn("def globalCodeTargets", global_context)
            self.assertIn("def globalValueTargets", global_context)
            global_node = next(
                node
                for node in graph["nodes"]
                if node["id"] == "relationalglobalmappingcontext"
            )
            register_node = next(
                node
                for node in graph["nodes"]
                if node["id"] == "relationalregisterrelationschunk0"
            )
            self.assertIn(global_node["id"], register_node["dependencies"])
            bundle = (
                prepared / "lean" / "StageA" / "RelationalBundle.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "GeneratedOrdinaryMemoryReadPullbackCertificate", bundle
            )
            self.assertIn(
                "import StageA.RelationalMemoryPullbackChunk0", bundle
            )
            register_module = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalRegisterRelationsChunk0.lean"
            )
            self.assertTrue(register_module.is_file())
            register_source = register_module.read_text(encoding="utf-8")
            self.assertIn("ExactRegisterOutputClaim", register_source)
            self.assertIn("allExactRegisterOutputClaims_of_checked", register_source)
            self.assertIn(
                "GeneratedExactRegisterRelationCertificate", bundle
            )
            self.assertIn(
                "import StageA.RelationalRegisterRelationsChunk0", bundle
            )

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
            self.assertEqual(
                (prepared / "relational-semantic-ir.json").read_bytes(),
                (second / "relational-semantic-ir.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "relational-memory-contracts.json").read_bytes(),
                (second / "relational-memory-contracts.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "relational-static-word-relations.json").read_bytes(),
                (second / "relational-static-word-relations.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "relational-register-relations.json").read_bytes(),
                (second / "relational-register-relations.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "composition-progress.json").read_bytes(),
                (second / "composition-progress.json").read_bytes(),
            )

            progress_path = prepared / "composition-progress.json"
            progress_bytes = progress_path.read_bytes()
            progress_path.write_bytes(progress_bytes + b"\n")
            with self.assertRaisesRegex(
                StageAInputError, "composition-progress.json"
            ):
                _validate_prepared_relational(prepared)
            progress_path.write_bytes(progress_bytes)

            manifest_path = prepared / "prepared-proof.json"
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            manifest["composition_progress"]["status"] = "inconsistent"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                StageAInputError, "composition progress does not match"
            ):
                _validate_prepared_relational(prepared)
            manifest_path.write_bytes(manifest_bytes)

            memory_contract_path = prepared / "relational-memory-contracts.json"
            memory_contract_bytes = memory_contract_path.read_bytes()
            memory_contract_path.write_bytes(memory_contract_bytes + b"\n")
            with self.assertRaisesRegex(
                StageAInputError, "relational-memory-contracts.json"
            ):
                _validate_prepared_relational(prepared)
            memory_contract_path.write_bytes(memory_contract_bytes)

            static_relations_path = (
                prepared / "relational-static-word-relations.json"
            )
            static_relations_bytes = static_relations_path.read_bytes()
            static_relations_path.write_bytes(static_relations_bytes + b"\n")
            with self.assertRaisesRegex(
                StageAInputError, "relational-static-word-relations.json"
            ):
                _validate_prepared_relational(prepared)
            static_relations_path.write_bytes(static_relations_bytes)

            source = prepared / "lean" / "StageA" / "RelationalBundle.lean"
            source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "source hash does not match"):
                _validate_prepared_relational(prepared)

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
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
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
            self.assertEqual(transition["status"], "proved")
            self.assertEqual(
                transition["evidence"]["kind"],
                "lean_checked_exact_memory_pullback_transition",
            )
            memory_contracts = json.loads(
                (report / "relational-memory-contracts.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                memory_contracts["counts"]["exact_memory_transition_edges"], 1
            )

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
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=root / "report",
                )

            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
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

    @unittest.skipUnless(
        shutil.which("lean") and shutil.which("nix") and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 to run the Nix derivation graph",
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

            self.assertEqual(result["status"], "incomplete", result)
            self.assertTrue(result["checks"]["lean_trust_zero"])
            self.assertEqual(result["lean_audit"]["unexpected_axioms"], [])
            self.assertGreater(result["provenance"]["node_derivations"], 1)
            self.assertEqual(result["provenance"]["nix_paths"], 1)
            self.assertGreater(result["provenance"]["dependency_pack_bytes"], 0)
            provenance = json.loads(
                (root / "report" / "nix-provenance.json").read_text(encoding="utf-8")
            )
            self.assertTrue(provenance["nodes"])
            self.assertNotIn("out_path", provenance["nodes"][0])
            self.assertRegex(
                provenance["nodes"][0]["outputs"][0]["olean_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                provenance["dependency_pack"]["node_count"],
                result["provenance"]["node_derivations"] - 1,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for process cancellation")
    def test_relational_lean_process_is_terminated_on_cancellation(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
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
