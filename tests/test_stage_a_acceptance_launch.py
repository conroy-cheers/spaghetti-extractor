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


class StageAAcceptanceLaunchTests(StageARelationalTestBase):
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
            self.assertEqual(writable_result["status"], "incomplete", writable_result)
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
                result["acceptance"]["theorem"], RELATIONAL_LINKED_ACCEPTANCE_THEOREM
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
