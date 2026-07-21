import copy

from tests.stage_a_relational_support import *
from spaghetti_extractor.relational.contract import (
    _padding_alias_bridge_bytes,
    _terminal_return_address_pairs,
)
from spaghetti_extractor.relational.analyses.segments import (
    _direct_call_stack_writes_claim,
)
from spaghetti_extractor.relational.executor import (
    _compile_formal_kernel,
    _precompiled_kernel_olean,
)
from spaghetti_extractor.relational.schema import PROTOCOL_CALLBACK_CONTROL_FORMAT


class StageARelationalContractTests(StageARelationalTestBase):
    def test_padding_alias_bridge_language_excludes_traps_and_zero_fill(self):
        self.assertTrue(_padding_alias_bridge_bytes(b"\x90\x66\x90"))
        self.assertTrue(_padding_alias_bridge_bytes(b"\x90\xeb\x02\xcc\xcc"))
        self.assertFalse(_padding_alias_bridge_bytes(b"\xcc\xcc"))
        self.assertFalse(_padding_alias_bridge_bytes(b"\x00\x00"))

    def test_relation_generator_only_promotes_executable_transparent_padding(self):
        for name, bridge, expected_aliases in (
            ("nop", b"\x90\x90", [0x1001]),
            ("int3", b"\xcc\xcc", []),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = self._write_pe(
                    root / "original.exe", b"\xc3" + bridge + b"\xeb\xfe",
                )
                candidate = self._write_pe(
                    root / "candidate.exe", b"\xc3" + bridge + b"\xeb\xfe",
                )
                mapping = root / "mapping.json"
                mapping.write_text(json.dumps({"blocks": [
                    {
                        "id": "return",
                        "kind": "code",
                        "original": {"rva": 0x1000, "size": 1},
                        "candidate": {"rva": 0x1000, "size": 1},
                    },
                    {
                        "id": "alignment",
                        "kind": "padding",
                        "original": {"rva": 0x1001, "size": 2},
                        "candidate": {"rva": 0x1001, "size": 2},
                    },
                    {
                        "id": "loop",
                        "kind": "code",
                        "original": {"rva": 0x1003, "size": 2},
                        "candidate": {"rva": 0x1003, "size": 2},
                    },
                ]}), encoding="utf-8")
                contract = root / "relation.json"

                generated = stage_a_generate_relation_contract(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    out=contract,
                )

                self.assertEqual(generated["status"], "generated", generated)
                payload = json.loads(contract.read_text(encoding="utf-8"))
                target = next(
                    target for target in payload["code_targets"]
                    if target["original_rva"] == 0x1003
                )
                self.assertEqual(target["original_aliases"], expected_aliases)
                self.assertEqual(target["candidate_aliases"], expected_aliases)

    def test_contract_preflight_rejects_nontransparent_padding_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", b"\xcc\xcc\xeb\xfe")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", b"\xcc\xcc\xeb\xfe")
            )
            contract = json.loads(self._write_contract(
                root / "relation.json", region_size=2, target_rva=0x1002,
            ).read_text(encoding="utf-8"))
            contract["code_targets"][0]["original_aliases"] = [0x1000]
            contract["code_targets"][0]["candidate_aliases"] = [0x1000]
            contract["regions"][0]["original"]["rva"] = 0x1002
            contract["regions"][0]["candidate"]["rva"] = 0x1002
            contract["padding"] = [{
                "id": "trap-padding",
                "side": "both",
                "rva": 0x1000,
                "size": 2,
            }]

            _normalized, issues = _normalize_contract(
                contract, original, candidate,
            )

            rejected = [
                issue for issue in issues
                if issue["category"] == "code_target_alias_not_verified_padding"
            ]
            self.assertEqual(len(rejected), 2, issues)

    def test_terminal_return_address_pairs_require_paired_direct_calls_and_padding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            call = b"\xe8\xfb\xff\xff\xff"
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", call + b"\x90\x90\xc3")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", call + b"\x90" * 6 + b"\xc3")
            )
            regions = [{
                "original": {"rva": 0x1000, "size": len(call)},
                "candidate": {"rva": 0x1000, "size": len(call)},
            }]
            targets = [{
                "id": 0,
                "original_rva": 0x1000,
                "candidate_rva": 0x1000,
            }]
            padding = [
                {"side": "original", "rva": 0x1005, "size": 2},
                {"side": "candidate", "rva": 0x1005, "size": 6},
            ]

            pairs = _terminal_return_address_pairs(
                regions, targets, padding, original, candidate,
            )

            self.assertEqual(pairs, [{
                "id": 0,
                "caller_region_index": 0,
                "callee_target_id": 0,
                "original_rva": 0x1005,
                "candidate_rva": 0x1005,
                "original_padding_size": 2,
                "candidate_padding_size": 6,
            }])

            self.assertEqual(
                _terminal_return_address_pairs(
                    regions, targets, padding[:-1], original, candidate,
                ),
                [],
            )

    def test_terminal_return_address_contract_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", b"\xc3")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", b"\xc3")
            )
            contract = json.loads(self._write_contract(
                root / "relation.json", region_size=1,
            ).read_text(encoding="utf-8"))
            pair = {
                "id": 0,
                "original_rva": 0x1001,
                "candidate_rva": 0x1001,
                "original_padding_size": 3,
                "candidate_padding_size": 7,
            }
            contract["terminal_return_addresses"] = [pair]

            normalized, issues = _normalize_contract(contract, original, candidate)

            self.assertEqual(issues, [])
            self.assertEqual(normalized["terminal_return_addresses"], [pair])

            malformed = copy.deepcopy(contract)
            malformed["terminal_return_addresses"][0]["original_padding_size"] = 0
            _normalized, malformed_issues = _normalize_contract(
                malformed, original, candidate,
            )
            self.assertIn(
                "malformed_terminal_return_address",
                {issue["category"] for issue in malformed_issues},
            )

    def test_parameterized_region_relations_are_normalized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", b"\xc3")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", b"\xc3")
            )
            contract_path = self._write_contract(
                root / "relation.json", region_size=1,
            )
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            relations = [
                {"original": "eax", "candidate": "eax", "relation": "exact"},
                {
                    "original": "ebx", "candidate": "ebx",
                    "relation": "code_pointer",
                },
                {
                    "original": "ecx", "candidate": "ecx",
                    "relation": "data_pointer",
                },
                {
                    "original": "edx", "candidate": "edx",
                    "relation": "related_word",
                },
                {
                    "original": "esi", "candidate": "esi",
                    "relation": "fixed_code_pointer", "target_id": 0,
                },
                {
                    "original": "edi", "candidate": "edi",
                    "relation": "fixed_word", "value": 0x12345678,
                },
            ]
            contract["regions"][0]["input_relations"] = relations
            contract["regions"][0]["output_relations"] = relations

            normalized, issues = _normalize_contract(contract, original, candidate)

            self.assertEqual(issues, [])
            self.assertEqual(normalized["regions"][0]["input_relations"], relations)
            self.assertEqual(normalized["regions"][0]["output_relations"], relations)

    def test_fixed_word_region_relations_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", b"\xc3")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", b"\xc3")
            )
            contract_path = self._write_contract(
                root / "relation.json", region_size=1,
            )
            base = json.loads(contract_path.read_text(encoding="utf-8"))
            valid = {
                "original": "edx", "candidate": "edx",
                "relation": "fixed_word", "value": 0x80,
            }
            malformed = {
                "missing": {key: value for key, value in valid.items()
                            if key != "value"},
                "negative": {**valid, "value": -1},
                "overflow": {**valid, "value": 2**32},
                "boolean": {**valid, "value": True},
                "target_id": {**valid, "target_id": 0},
                "value_on_exact": {**valid, "relation": "exact"},
            }
            for name, relation in malformed.items():
                with self.subTest(name=name):
                    contract = json.loads(json.dumps(base))
                    contract["regions"][0]["input_relations"] = [relation]
                    _normalized, issues = _normalize_contract(
                        contract, original, candidate,
                    )
                    self.assertIn(
                        "register_relation_invalid",
                        {issue["category"] for issue in issues},
                    )

    def test_fixed_code_pointer_region_relations_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", b"\xc3")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", b"\xc3")
            )
            contract_path = self._write_contract(
                root / "relation.json", region_size=1,
            )
            base = json.loads(contract_path.read_text(encoding="utf-8"))
            valid = {
                "original": "esi", "candidate": "esi",
                "relation": "fixed_code_pointer", "target_id": 0,
            }

            malformed_relations = {
                "missing": {key: value for key, value in valid.items()
                            if key != "target_id"},
                "unknown": {**valid, "target_id": 1},
                "negative": {**valid, "target_id": -1},
            }
            for relation in (
                "exact", "code_pointer", "data_pointer", "related_word",
            ):
                malformed_relations[f"target on {relation}"] = {
                    **valid, "relation": relation,
                }
            for name, relation in malformed_relations.items():
                with self.subTest(name=name):
                    contract = json.loads(json.dumps(base))
                    contract["regions"][0]["input_relations"] = [relation]
                    _normalized, issues = _normalize_contract(
                        contract, original, candidate,
                    )
                    self.assertIn(
                        "register_relation_invalid",
                        {issue["category"] for issue in issues},
                    )

            duplicate = json.loads(json.dumps(base))
            duplicate["code_targets"].append({
                "id": 0,
                "original_rva": 0x1000,
                "candidate_rva": 0x1000,
            })
            duplicate["regions"][0]["input_relations"] = [valid]
            _normalized, duplicate_issues = _normalize_contract(
                duplicate, original, candidate,
            )
            duplicate_categories = {
                issue["category"] for issue in duplicate_issues
            }
            self.assertIn("malformed_code_target", duplicate_categories)

            noncanonical = json.loads(json.dumps(base))
            noncanonical["code_targets"][0]["id"] = 222
            noncanonical["regions"][0]["input_relations"] = [{
                **valid, "target_id": 222,
            }]
            _normalized, noncanonical_issues = _normalize_contract(
                noncanonical, original, candidate,
            )
            self.assertIn(
                "register_relation_invalid",
                {issue["category"] for issue in noncanonical_issues},
            )

    def test_protocol_callback_control_schema_is_explicit_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = _parse_stage_a_pe(
                self._write_pe(root / "original.exe", b"\xc3")
            )
            candidate = _parse_stage_a_pe(
                self._write_pe(root / "candidate.exe", b"\xc3")
            )
            contract_path = self._write_contract(root / "relation.json", region_size=1)
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            callback_state = {
                "target_id": 0,
                "active_frame_offset": {
                    "original_register": "esp", "original": 0,
                    "candidate_register": "esp", "candidate": 0,
                },
                "return_invariant": {"kind": "terminal"},
            }
            contract["protocol_callback_control"] = {
                "format": PROTOCOL_CALLBACK_CONTROL_FORMAT,
                "states": [callback_state],
            }

            normalized, issues = _normalize_contract(contract, original, candidate)

            self.assertEqual(issues, [])
            self.assertEqual(
                normalized["protocol_callback_control"],
                contract["protocol_callback_control"],
            )

            duplicate = json.loads(json.dumps(contract))
            duplicate["protocol_callback_control"]["states"].append(callback_state)
            _normalized, duplicate_issues = _normalize_contract(
                duplicate, original, candidate
            )
            self.assertIn(
                "protocol_callback_control_state_invalid",
                {issue["category"] for issue in duplicate_issues},
            )

            malformed = json.loads(json.dumps(contract))
            malformed["protocol_callback_control"]["states"][0][
                "active_frame_offset"
            ]["original_register"] = "eip"
            _normalized, malformed_issues = _normalize_contract(
                malformed, original, candidate
            )
            self.assertIn(
                "protocol_callback_control_state_invalid",
                {issue["category"] for issue in malformed_issues},
            )

            legacy = json.loads(json.dumps(contract))
            legacy.pop("protocol_callback_control")
            legacy["protocol_callback_target_ids"] = [0]
            _normalized, legacy_issues = _normalize_contract(
                legacy, original, candidate
            )
            self.assertIn(
                "unknown_relation_contract_fields",
                {issue["category"] for issue in legacy_issues},
            )

    def test_paired_stack_word_write_proposal_fails_closed(self):
        source = {
            "stack_windows": [{
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 0,
                "bytes_above": 16,
            }],
        }

        def behavior(amount: int, candidate_value: int = 7) -> dict[str, object]:
            def write(value: int) -> dict[str, object]:
                return {
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": "esp"},
                        "right": {"op": "constant", "value": amount},
                    },
                    "value": {"op": "constant", "value": value},
                }

            return {
                "original_ir": {"writes": [write(7)]},
                "candidate_ir": {"writes": [write(candidate_value)]},
            }

        claim = _paired_stack_word_write_claim(source, behavior(8))
        self.assertIsNotNone(claim)
        self.assertEqual(claim["amount"], 8)
        self.assertIsNone(_paired_stack_word_write_claim(source, behavior(2)))
        self.assertIsNone(
            _paired_stack_word_write_claim(source, behavior(8, candidate_value=9))
        )

        def writes_behavior(
            amounts: list[int], *, candidate_value: int = 7,
        ) -> dict[str, object]:
            def address(amount: int) -> dict[str, object]:
                if amount == 0:
                    return {"op": "input_reg", "reg": "esp"}
                return {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": "esp"},
                    "right": {"op": "constant", "value": amount},
                }

            return {
                "original_ir": {"writes": [{
                    "address": address(amount),
                    "value": {"op": "constant", "value": 7},
                } for amount in amounts]},
                "candidate_ir": {"writes": [{
                    "address": address(amount),
                    "value": {
                        "op": "constant",
                        "value": candidate_value if index == 0 else 7,
                    },
                } for index, amount in enumerate(amounts)]},
            }

        writes_claim = _paired_stack_word_writes_claim(
            source, writes_behavior([0, 4, 8])
        )
        self.assertIsNotNone(writes_claim)
        self.assertEqual(
            [write["amount"] for write in writes_claim["writes"]],
            [0, 4, 8],
        )
        self.assertIsNone(
            _paired_stack_word_writes_claim(source, writes_behavior([8]))
        )
        self.assertIsNone(
            _paired_stack_word_writes_claim(source, writes_behavior([0, 2]))
        )
        self.assertIsNone(_paired_stack_word_writes_claim(
            source, writes_behavior([0, 4], candidate_value=9)
        ))

        related_source = {
            **source,
            "input_relations": [{
                "original": "eax",
                "candidate": "ecx",
                "relation": "related_word",
            }],
        }

        def related_behavior(*, offset: int = 0) -> dict[str, object]:
            def value(register: str) -> dict[str, object]:
                expression: dict[str, object] = {
                    "op": "input_reg",
                    "reg": register,
                }
                if offset:
                    expression = {
                        "op": "add",
                        "left": expression,
                        "right": {"op": "constant", "value": offset},
                    }
                return expression

            def write(register: str) -> dict[str, object]:
                return {
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": "esp"},
                        "right": {"op": "constant", "value": 8},
                    },
                    "value": value(register),
                }

            return {
                "original_ir": {"writes": [write("eax")]},
                "candidate_ir": {"writes": [write("ecx")]},
            }

        related_claim = _paired_stack_word_write_claim(
            related_source, related_behavior()
        )
        self.assertIsNotNone(related_claim)
        self.assertEqual(
            related_claim["value"]["profile"], "register_argument_v1"
        )
        self.assertEqual(
            related_claim["value"]["claim"]["relation"],
            related_source["input_relations"][0],
        )
        self.assertIsNone(_paired_stack_word_write_claim(
            related_source, related_behavior(offset=4)
        ))

        mapped_source = {
            **source,
            "code_targets": [{
                "id": 3,
                "original_rva": 0x1000,
                "candidate_rva": 0x1020,
            }],
            "values": [{
                "id": 5,
                "original_value": 0x402000,
                "candidate_value": 0x403000,
            }],
        }

        def mapped_behavior(
            original_value: int, candidate_value: int,
        ) -> dict[str, object]:
            def write(value: int) -> dict[str, object]:
                return {
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": "esp"},
                        "right": {"op": "constant", "value": 8},
                    },
                    "value": {"op": "constant", "value": value},
                }

            return {
                "original_ir": {"writes": [write(original_value)]},
                "candidate_ir": {"writes": [write(candidate_value)]},
            }

        code_pointer = _paired_stack_word_write_claim(
            mapped_source, mapped_behavior(0x401000, 0x401020),
            0x400000, 0x400000,
        )
        self.assertEqual(code_pointer["value"], {
            "profile": "mapped_code_target_v1",
            "original": {"op": "constant", "value": 0x401000},
            "candidate": {"op": "constant", "value": 0x401020},
            "target_id": 3,
        })
        data_pointer = _paired_stack_word_write_claim(
            mapped_source, mapped_behavior(0x402000, 0x403000),
            0x400000, 0x400000,
        )
        self.assertEqual(data_pointer["value"]["profile"], "mapped_data_target_v1")
        self.assertEqual(data_pointer["value"]["target_id"], 5)
        self.assertIsNone(_paired_stack_word_write_claim(
            mapped_source, mapped_behavior(0x401000, 0x401020)
        ))
        ambiguous_source = {
            **mapped_source,
            "values": [
                *mapped_source["values"],
                {**mapped_source["values"][0], "id": 6},
            ],
        }
        self.assertIsNone(_paired_stack_word_write_claim(
            ambiguous_source, mapped_behavior(0x402000, 0x403000),
            0x400000, 0x400000,
        ))

    def test_direct_call_exact_word_seed_uses_last_nonoverwritten_scalar(self):
        source = {
            "stack_windows": [{
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 4,
                "bytes_above": 16,
            }],
        }

        def address(offset: int) -> dict[str, object]:
            return {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": offset % 2**32},
            }

        writes = [
            {"address": address(4), "value": {"op": "constant", "value": 1}},
            {"address": address(4), "value": {"op": "constant", "value": 2}},
            {
                "address": address(-4),
                "value": {"op": "constant", "value": 0x40100D},
            },
        ]
        behavior = {
            "original_ir": {"writes": writes},
            "candidate_ir": {"writes": writes},
        }
        call_claim = {
            "original_stack_address": address(-4),
            "candidate_stack_address": address(-4),
            "callee_target_id": 2,
            "continuation_target_id": 1,
            "original_return_address": 0x40100D,
            "candidate_return_address": 0x40100D,
        }

        claim = _direct_call_stack_writes_claim(source, behavior, call_claim)

        self.assertIsNotNone(claim)
        seeds = claim["exact_word_seeds"]
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["selected"]["value"]["original"]["value"], 2)
        self.assertEqual(len(seeds[0]["before"]), 1)
        self.assertEqual(seeds[0]["after"], [])
        self.assertEqual(
            seeds[0]["exact_word"],
            {"original_offset": 8, "candidate_offset": 8},
        )

    def test_acceptance_blockers_are_compacted_without_losing_counts(self):
        compact = _compact_acceptance_blockers([
            {
                "code": "return_node_profile_unmet",
                "message": f"return node {node_id} is incomplete",
                "next_action": "close the runtime frame",
            }
            for node_id in range(12)
        ] + [{
            "code": "environment_pending",
            "message": "the external edge is incomplete",
            "next_action": "close environment refinement",
        }])

        self.assertEqual([item["code"] for item in compact], [
            "return_node_profile_unmet", "environment_pending",
        ])
        self.assertEqual(compact[0]["count"], 12)
        self.assertEqual(len(compact[0]["examples"]), 10)
        self.assertEqual(compact[0]["omitted_examples"], 2)
        self.assertEqual(compact[1]["count"], 1)
        self.assertEqual(compact[1]["message"], "the external edge is incomplete")

    def test_potential_reachability_expands_unresolved_indirect_control(self):
        regions = [
            {
                "id": "indirect",
                "numeric_id": 0,
                "root": True,
                "original": {"rva_start": 0x1000},
                "candidate": {"rva_start": 0x1000},
            },
            {
                "id": "target",
                "numeric_id": 1,
                "root": False,
                "original": {"rva_start": 0x1010},
                "candidate": {"rva_start": 0x1020},
            },
            {
                "id": "other-target",
                "numeric_id": 2,
                "root": False,
                "original": {"rva_start": 0x1030},
                "candidate": {"rva_start": 0x1040},
            },
        ]
        contract = {
            "regions": regions,
            "code_targets": [
                {
                    "id": 0, "region_index": 0,
                    "original_rva": 0x1000, "candidate_rva": 0x1000,
                },
                {
                    "id": 1, "region_index": 1,
                    "original_rva": 0x1010, "candidate_rva": 0x1020,
                },
                {
                    "id": 2, "region_index": 2,
                    "original_rva": 0x1030, "candidate_rva": 0x1040,
                },
            ],
        }
        indirect_outcome = {
            "op": "indirect_call",
            "target": {"op": "input_reg", "reg": "eax"},
            "continuation": 1,
        }
        returned_outcome = {
            "op": "returned",
            "target": {"op": "input_reg", "reg": "eax"},
        }
        graph = _relational_product_graph(
            contract,
            [
                {
                    "original_ir": {"outcome": indirect_outcome},
                    "candidate_ir": {"outcome": indirect_outcome},
                },
                {
                    "original_ir": {"outcome": returned_outcome},
                    "candidate_ir": {"outcome": returned_outcome},
                },
                {
                    "original_ir": {"outcome": returned_outcome},
                    "candidate_ir": {"outcome": returned_outcome},
                },
            ],
            {"edges": []},
            [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        self.assertEqual(graph["evidence"]["declared_reachable_node_ids"], [0])
        self.assertEqual(
            graph["evidence"]["potential_reachable_node_ids"], [0, 1, 2]
        )
        self.assertEqual(graph["evidence"]["potential_control_cuts"], [{
            "node_id": 0,
            "operations": ["indirect_call"],
            "reason": (
                "unresolved_indirect_control_"
                "register_word_without_producer_certificate"
            ),
            "provenance": ["register_word_without_producer_certificate"],
            "potential_target_count": 3,
            "potential_target_node_ids": [0, 1, 2],
            "target_scope": "all_canonical_code_targets",
        }])
        self.assertTrue(
            graph["counts"]["reachability_truncated_by_control_frontier"]
        )
        self.assertEqual(graph["counts"]["potential_reachable_nodes"], 3)
        self.assertEqual(
            graph["counts"]["potential_unrepresented_control_edges"], 3
        )
        progress = _composition_progress(
            graph,
            {
                "status": "supported", "issues": [],
                "counts": {"issues": 0, "by_category": {}},
            },
            {
                "format": "stage-a-relational-external-call-sites-v1",
                "status": "candidate_requires_lean_replay",
                "candidates": [], "gaps": [],
                "counts": {"candidates": 0, "gaps": 0},
            },
            {
                "status": "incomplete", "profile": None, "theorem": None,
                "blockers": [{
                    "code": "unresolved_control",
                    "next_action": "classify the indirect target",
                }],
            },
        )
        self.assertEqual(progress["status"], "incomplete")
        self.assertEqual(progress["counts"]["rooted_reachable_nodes"], 1)
        self.assertEqual(progress["counts"]["potential_reachable_nodes"], 3)
        self.assertEqual(
            progress["counts"]["unresolved_indirect_control_nodes"], 1
        )
        self.assertTrue(progress["reachability"]["truncated_by_control_frontier"])
        assurance = progress["reachability_assurance"]
        self.assertEqual(assurance["status"], "incomplete")
        self.assertEqual(
            assurance["represented_rooted_reachability"]["node_ids"], [0]
        )
        self.assertEqual(
            assurance["conservative_potential_reachability"]["node_ids"],
            [0, 1, 2],
        )
        self.assertEqual(
            assurance["truncation"]["potential_only_node_ids"], [1, 2]
        )
        self.assertEqual(
            assurance["frontiers"]["conservative_control_cuts"],
            graph["evidence"]["potential_control_cuts"],
        )
        self.assertFalse(assurance["blocker_totals"]["comparable"])
        self.assertFalse(assurance["blocker_totals"]["coverage_bearing"])
        self.assertEqual(
            assurance["blocker_totals"]["non_comparability_reasons"],
            [
                "represented_decoded_control_frontier",
                "conservative_control_frontier",
                "represented_reachability_truncated",
            ],
        )
        self.assertEqual(
            [item["category"] for item in progress["next_work"]],
            ["unresolved_indirect_control"],
        )
        malformed_targets = copy.deepcopy(graph)
        malformed_targets["evidence"]["potential_control_cuts"][0][
            "potential_target_node_ids"
        ] = [0, 1]
        with self.assertRaisesRegex(
            StageAInputError, "inconsistent conservative control cut"
        ):
            _composition_progress(
                malformed_targets,
                {
                    "status": "supported", "issues": [],
                    "counts": {"issues": 0, "by_category": {}},
                },
                {
                    "format": "stage-a-relational-external-call-sites-v1",
                    "status": "candidate_requires_lean_replay",
                    "candidates": [], "gaps": [],
                    "counts": {"candidates": 0, "gaps": 0},
                },
                {"status": "incomplete", "blockers": []},
            )
        frame_progress = _composition_progress(
            graph,
            {
                "status": "supported", "issues": [],
                "counts": {"issues": 0, "by_category": {}},
            },
            {
                "format": "stage-a-relational-external-call-sites-v1",
                "status": "candidate_requires_lean_replay",
                "candidates": [], "gaps": [],
                "counts": {"candidates": 0, "gaps": 0},
            },
            {
                "status": "incomplete", "profile": None, "theorem": None,
                "blockers": [],
            },
            {
                "frontier": [{
                    "region_index": 0,
                    "original_register": "esp",
                    "candidate_register": "esp",
                    "bytes_below": 4,
                    "bytes_above": 8,
                    "reason":
                        "nonzero_stack_delta_cycle_requires_relational_frame",
                }],
            },
        )
        self.assertEqual(
            frame_progress["counts"]
            ["rooted_relational_call_frame_frontier_nodes"],
            1,
        )
        self.assertEqual(
            [item["category"] for item in frame_progress["next_work"]],
            ["unresolved_indirect_control", "relational_call_frame_frontier"],
        )

    def test_reachability_assurance_closes_scope_without_making_blockers_coverage(self):
        contract = {
            "regions": [{
                "id": "root", "numeric_id": 0, "root": True,
                "original": {"rva_start": 0x1000},
                "candidate": {"rva_start": 0x1000},
            }],
            "code_targets": [{
                "id": 0, "region_index": 0,
                "original_rva": 0x1000, "candidate_rva": 0x1000,
            }],
        }
        returned = {
            "op": "returned", "target": {"op": "input_reg", "reg": "eax"},
        }
        graph = _relational_product_graph(
            contract,
            [{
                "original_ir": {"outcome": returned},
                "candidate_ir": {"outcome": returned},
            }],
            {"edges": []},
            [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        acceptance = {
            "status": "incomplete", "profile": None, "theorem": None,
            "blockers": [{
                "code": "remaining_proof_work", "count": 2,
                "next_action": "close the remaining proof work",
            }],
        }
        external = {
            "format": "stage-a-relational-external-call-sites-v1",
            "status": "candidate_requires_lean_replay",
            "candidates": [], "gaps": [],
            "counts": {"candidates": 0, "gaps": 0},
        }
        preflight = {
            "status": "supported", "issues": [],
            "counts": {"issues": 0, "by_category": {}},
        }

        progress = _composition_progress(graph, preflight, external, acceptance)
        assurance = progress["reachability_assurance"]

        self.assertEqual(assurance["status"], "control_closed")
        self.assertFalse(assurance["truncation"]["present"])
        self.assertEqual(assurance["frontiers"]["conservative_control_cuts"], [])
        self.assertEqual(assurance["blocker_totals"]["reported_total"], 2)
        self.assertTrue(assurance["blocker_totals"]["comparable"])
        self.assertFalse(assurance["blocker_totals"]["coverage_bearing"])
        self.assertEqual(
            assurance["blocker_totals"]["non_comparability_reasons"], []
        )
        self.assertEqual(
            json.dumps(progress, sort_keys=True, separators=(",", ":")),
            json.dumps(
                _composition_progress(graph, preflight, external, acceptance),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )

        malformed_bits = copy.deepcopy(graph)
        malformed_bits["evidence"]["declared_reachable_bits"] = [False]
        with self.assertRaisesRegex(
            StageAInputError, "declared reachability does not equal recomputed closure"
        ):
            _composition_progress(
                malformed_bits, preflight, external, acceptance
            )

        relocated_identity = copy.deepcopy(graph)
        relocated_identity["evidence"]["canonical_node_inventory"][0].update({
            "original_rva_start": 0x9000,
            "original_rva_end": 0x9001,
        })
        relocated_progress = _composition_progress(
            relocated_identity, preflight, external, acceptance
        )
        self.assertNotEqual(
            assurance["blocker_totals"]["reachability_inventory_sha256"],
            relocated_progress["reachability_assurance"]["blocker_totals"]
            ["reachability_inventory_sha256"],
        )

        aliases_a = copy.deepcopy(graph)
        aliases_b = copy.deepcopy(graph)
        aliases_a["evidence"]["canonical_node_inventory"][0][
            "original_entry_aliases"
        ] = [0x1004, 0x1008]
        aliases_b["evidence"]["canonical_node_inventory"][0][
            "original_entry_aliases"
        ] = [0x1008, 0x1004]
        aliases_a_progress = _composition_progress(
            aliases_a, preflight, external, acceptance
        )
        aliases_b_progress = _composition_progress(
            aliases_b, preflight, external, acceptance
        )
        self.assertEqual(
            aliases_a_progress["reachability_assurance"]["blocker_totals"]
            ["reachability_inventory_sha256"],
            aliases_b_progress["reachability_assurance"]["blocker_totals"]
            ["reachability_inventory_sha256"],
        )

        rootless_contract = json.loads(json.dumps(contract))
        rootless_contract["regions"][0]["root"] = False
        rootless_graph = _relational_product_graph(
            rootless_contract,
            [{
                "original_ir": {"outcome": returned},
                "candidate_ir": {"outcome": returned},
            }],
            {"edges": []},
            [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        rootless_progress = _composition_progress(
            rootless_graph,
            preflight,
            external,
            {
                "status": "ready", "profile": "test", "theorem": "test",
                "blockers": [],
            },
        )
        self.assertEqual(rootless_progress["status"], "incomplete")
        rootless_assurance = rootless_progress["reachability_assurance"]
        self.assertEqual(rootless_assurance["status"], "incomplete")
        self.assertFalse(
            rootless_assurance["represented_rooted_reachability"]["control_closed"]
        )
        self.assertFalse(rootless_assurance["blocker_totals"]["comparable"])
        self.assertEqual(
            rootless_assurance["blocker_totals"]["non_comparability_reasons"],
            ["no_root_nodes"],
        )

    def test_reachability_assurance_rejects_omitted_feasible_successor(self):
        true_guard = {"op": "bool_constant", "value": True}
        contract = {
            "regions": [
                {
                    "id": "root", "numeric_id": 0, "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                },
                {
                    "id": "successor", "numeric_id": 1, "root": False,
                    "original": {"rva_start": 0x1010},
                    "candidate": {"rva_start": 0x1010},
                },
            ],
            "code_targets": [
                {
                    "id": index, "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(2)
            ],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {"op": "jump", "target": 1}},
                "candidate_ir": {"outcome": {"op": "jump", "target": 1}},
            },
            {
                "original_ir": {"outcome": {
                    "op": "returned",
                    "target": {"op": "input_reg", "reg": "eax"},
                }},
                "candidate_ir": {"outcome": {
                    "op": "returned",
                    "target": {"op": "input_reg", "reg": "eax"},
                }},
            },
        ]
        graph = _relational_product_graph(
            contract,
            behaviors,
            {"edges": [{
                "source_region_index": 0,
                "target_region_index": 1,
                "kind": "jump",
                "original_guard": true_guard,
                "candidate_guard": true_guard,
            }]},
            [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        malformed = copy.deepcopy(graph)
        malformed["evidence"]["declared_reachable_node_ids"] = [0]
        malformed["evidence"]["declared_reachable_bits"] = [True, False]
        malformed["counts"]["declared_reachable_nodes"] = 1

        with self.assertRaisesRegex(
            StageAInputError, "declared reachability does not equal recomputed closure"
        ):
            _composition_progress(
                malformed,
                {"status": "supported", "issues": []},
                {"candidates": [], "gaps": []},
                {"status": "incomplete", "blockers": []},
            )

    def test_dynamic_indirect_call_adds_exact_guarded_code_map_fanout(self):
        contract = {
            "regions": [
                {
                    "id": "indirect", "numeric_id": 0, "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                },
                {
                    "id": "target", "numeric_id": 1, "root": False,
                    "original": {"rva_start": 0x1010},
                    "candidate": {"rva_start": 0x1020},
                },
            ],
            "code_targets": [
                {
                    "id": 0, "region_index": 0,
                    "original_rva": 0x1000, "candidate_rva": 0x1000,
                    "original_aliases": [0x1004],
                    "candidate_aliases": [0x1008],
                },
                {
                    "id": 1, "region_index": 1,
                    "original_rva": 0x1010, "candidate_rva": 0x1020,
                    "original_aliases": [], "candidate_aliases": [],
                },
            ],
        }
        original_target = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "ebx"},
                "right": {"op": "constant", "value": 4},
            },
        }
        candidate_target = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esi"},
                "right": {"op": "constant", "value": 4},
            },
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "indirect_call", "target": original_target,
                    "continuation": 1,
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_call", "target": candidate_target,
                    "continuation": 1,
                }},
            },
            {
                "original_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "eax"},
                }},
                "candidate_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "eax"},
                }},
            },
        ]
        dynamic_candidate = {
            "profile": "dynamic_range_code_pointer_call_v1",
            "source_region_index": 0,
            "range_relation": {
                "original": "ebx", "candidate": "esi",
                "original_offset": 8, "candidate_offset": 8,
                "required_words": [{"offset": 12, "kind": "codePointer"}],
            },
            "word_offset": 4,
            "continuation_target_id": 1,
        }
        graph = _relational_product_graph(
            contract, behaviors, {"edges": []}, [],
            original_image_base=0x400000,
            candidate_image_base=0x500000,
            dynamic_call_candidates=[dynamic_candidate],
        )

        self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0, 1])
        self.assertEqual(
            [edge["target_target_id"] for edge in graph["edges"]], [0, 1]
        )
        self.assertEqual(
            graph["edges"][0]["original_guard"],
            {
                "op": "or",
                "left": {
                    "op": "equal", "left": original_target,
                    "right": {"op": "constant", "value": 0x401004},
                },
                "right": {
                    "op": "equal", "left": original_target,
                    "right": {"op": "constant", "value": 0x401000},
                },
            },
        )
        self.assertEqual(
            graph["evidence"]["dynamic_range_indirect_call_edge_groups"],
            [{"source_node_id": 0, "candidate_index": 0, "edge_ids": [0, 1]}],
        )
        self.assertEqual(graph["evidence"]["declared_reachable_node_ids"], [0, 1])
        self.assertEqual(
            graph["evidence"]["decoded_control_complete_node_ids"], [0, 1]
        )
        self.assertEqual(graph["evidence"]["potential_control_cuts"], [])

        with self.assertRaisesRegex(StageAInputError, "duplicate dynamic"):
            _relational_product_graph(
                contract, behaviors, {"edges": []}, [],
                original_image_base=0x400000,
                candidate_image_base=0x500000,
                dynamic_call_candidates=[dynamic_candidate, dynamic_candidate],
            )

    def test_direct_call_reachability_includes_runtime_continuation_without_symbols(self):
        true_guard = {"op": "bool_constant", "value": True}
        regions = [
            {
                "id": name, "numeric_id": index, "root": index == 0,
                "original": {"rva_start": 0x1000 + index * 0x10},
                "candidate": {"rva_start": 0x1000 + index * 0x10},
            }
            for index, name in enumerate(("caller", "continuation", "callee"))
        ]
        contract = {
            "regions": regions,
            "code_targets": [
                {
                    "id": index, "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(3)
            ],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "call", "target": 2, "continuation": 1,
                }},
                "candidate_ir": {"outcome": {
                    "op": "call", "target": 2, "continuation": 1,
                }},
            },
            {
                "original_ir": {"outcome": {"op": "jump", "target": 0}},
                "candidate_ir": {"outcome": {"op": "jump", "target": 0}},
            },
            {
                "original_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "esp"},
                }},
                "candidate_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "esp"},
                }},
            },
        ]
        register_relations = {
            "edges": [
                {
                    "source_region_index": 0,
                    "target_region_index": 2,
                    "kind": "call",
                    "original_guard": true_guard,
                    "candidate_guard": true_guard,
                    "direct_call_push_claim": {
                        "continuation_region_index": 1,
                    },
                },
                {
                    "source_region_index": 1,
                    "target_region_index": 0,
                    "kind": "jump",
                    "original_guard": true_guard,
                    "candidate_guard": true_guard,
                    "direct_call_push_claim": None,
                },
            ],
        }

        graph = _relational_product_graph(
            contract, behaviors, register_relations, [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        self.assertEqual(
            graph["evidence"]["declared_reachable_node_ids"], [0, 1, 2]
        )
        self.assertEqual(graph["evidence"]["runtime_call_continuations"], [{
            "source_node_id": 0,
            "continuation_node_ids": [1],
        }])
        self.assertNotIn("callReturn", [edge["kind"] for edge in graph["edges"]])

    def test_reachable_product_local_certificate_is_fail_closed_and_external_exact(self):
        base_evidence = {
            "declared_reachable_node_ids": [0],
            "decoded_control_complete_node_ids": [],
            "decoded_control_candidates": [],
            "reachable_locally_refined_edge_ids": [],
            "proved_edge_ids": [],
            "reachable_product_local_complete": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            (lean_dir / "StageA").mkdir()
            _write_reachable_product_local_certificate(
                lean_dir,
                {"evidence": base_evidence},
                [],
                [],
            )
            incomplete = (
                lean_dir / "StageA" /
                "RelationalReachableProductLocalCertificate.lean"
            ).read_text(encoding="utf-8")
            incomplete_evidence = (
                lean_dir / "StageA" /
                "RelationalReachableProductLocalEvidence.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "relationalProductLocalDecodedNodeIdsIncreasingChecked",
                incomplete_evidence,
            )
            self.assertNotIn(
                "RelationalProductGraphContext",
                incomplete_evidence,
            )
            self.assertNotIn("def reachableProductLocalCertificate", incomplete)

            external_evidence = {
                **base_evidence,
                "decoded_control_complete_node_ids": [0],
                "decoded_control_candidates": [{
                    "node_id": 0,
                    "region_index": 0,
                }],
                "reachable_locally_refined_edge_ids": [7],
                "reachable_product_local_complete": True,
            }
            _write_reachable_product_local_certificate(
                lean_dir,
                {"evidence": external_evidence},
                [],
                [{
                    "module": "RelationalExternalCallRefinementEdge7",
                    "edge_id": 7,
                    "source_region_index": 0,
                    "theorem": "externalCallEdge7ProductRefinementChecked",
                }],
            )
            external = (
                lean_dir / "StageA" /
                "RelationalReachableProductLocalCertificate.lean"
            ).read_text(encoding="utf-8")
            external_edge_chunk = (
                lean_dir / "StageA" /
                "RelationalReachableProductEdgeChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalExternalCallRefinementEdge7",
                external_edge_chunk,
            )
            self.assertIn(
                "externalCallEdge7ProductRefinementChecked",
                external_edge_chunk,
            )
            self.assertIn(
                "reachableProductEdgeChunk0ValidityChecked",
                external_edge_chunk,
            )
            self.assertIn("def reachableProductLocalCertificate", external)

            with self.assertRaisesRegex(
                StageAInputError,
                "lacks generated external refinement modules for 7",
            ):
                _write_reachable_product_local_certificate(
                    lean_dir,
                    {"evidence": external_evidence},
                    [],
                    [],
                )

    def test_external_register_argument_claims_fail_closed_on_affine_related_words(self):
        exact_source = {
            "input_relations": [{
                "original": "ebx", "candidate": "esi", "relation": "exact",
            }],
        }
        related_source = {
            "input_relations": [{
                "original": "ebx", "candidate": "esi", "relation": "related_word",
            }],
        }
        original = {
            "op": "add", "left": {"op": "input_reg", "reg": "ebx"},
            "right": {"op": "constant", "value": 32},
        }
        candidate = {
            "op": "add", "left": {"op": "input_reg", "reg": "esi"},
            "right": {"op": "constant", "value": 32},
        }

        claims, blocker = _external_argument_relation_claims(
            exact_source, [original], [candidate]
        )
        self.assertIsNone(blocker)
        self.assertEqual(claims, [{
            "kind": "register_word",
            "relation": exact_source["input_relations"][0],
            "offset": 32,
            "original_expression": original,
            "candidate_expression": candidate,
        }])

        claims, blocker = _external_argument_relation_claims(
            related_source, [original], [candidate]
        )
        self.assertIsNone(claims)
        self.assertIn("checked mapped-range witness", blocker)

    def test_external_stack_word_argument_claim_is_explicit_and_bounded(self):
        address = {
            "op": "add",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 4},
        }
        direct = {"op": "read32", "address": address}
        assembled = _semantic_affine_word_read("esp", 4)
        window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 0,
            "bytes_above": 16,
        }
        source = {"stack_windows": [window]}

        claims, blocker = _external_argument_relation_claims(
            source, [direct], [assembled]
        )

        self.assertIsNone(blocker)
        self.assertEqual(claims, [{
            "kind": "stack_word_read",
            "window": window,
            "offset": 4,
            "original_assembled_read": False,
            "candidate_assembled_read": True,
            "original_expression": direct,
            "candidate_expression": assembled,
        }])

        claims, blocker = _external_argument_relation_claims(
            {"stack_windows": [{**window, "bytes_above": 7}]},
            [direct], [assembled],
        )
        self.assertIsNone(claims)
        self.assertIn("lacks one checked source stack-window relation", blocker)

        negative_address = {
            "op": "sub",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 8},
        }
        negative_read = {"op": "read32", "address": negative_address}
        claims, blocker = _external_argument_relation_claims(
            {"stack_windows": [{**window, "bytes_below": 4}]},
            [negative_read], [negative_read],
        )
        self.assertIsNone(claims)
        self.assertIn("lacks one unambiguous source dynamic-range relation", blocker)

        claims, blocker = _external_argument_relation_claims(
            {"stack_windows": [{**window, "bytes_below": 8}]},
            [negative_read], [negative_read],
        )
        self.assertIsNone(blocker)
        self.assertEqual(claims[0]["kind"], "stack_word_read")
        self.assertEqual(claims[0]["offset"], -8)

    def test_persistent_olean_cache_tracks_compiled_dependency_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source = stage_a / "Consumer.lean"
            dependency_source = stage_a / "Dependency.lean"
            dependency_olean = stage_a / "Dependency.olean"
            (stage_a / "Formal.lean").write_text("def formal := 1\n")
            source.write_text("import StageA.Dependency\n")
            dependency_source.write_text("def dependency := 1\n")
            dependency_olean.write_bytes(b"compiled-v1")
            with patch.dict(os.environ, {
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE": str(root / "cache"),
            }):
                first = _persistent_olean_path(
                    root, "Consumer", source, [dependency_olean]
                )
                dependency_olean.write_bytes(b"compiled-v2")
                second = _persistent_olean_path(
                    root, "Consumer", source, [dependency_olean]
                )
                self.assertNotEqual(first, second)

                dependency_source.write_text(
                    "import StageA.Transitive\ndef dependency := transitive\n"
                )
                transitive_source = stage_a / "Transitive.lean"
                transitive_source.write_text("def transitive := 1\n")
                third = _persistent_olean_path(
                    root, "Consumer", source, [dependency_olean]
                )
                transitive_source.write_text("def transitive := 2\n")
                fourth = _persistent_olean_path(
                    root, "Consumer", source, [dependency_olean]
                )
                self.assertNotEqual(third, fourth)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for cache replay")
    def test_formal_kernel_cache_restores_imported_oleans(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "lean" / "StageA"
            stage_a.mkdir(parents=True)
            (stage_a / "Dependency.lean").write_text(
                "namespace StageA\ndef dependency := 1\nend StageA\n",
                encoding="utf-8",
            )
            (stage_a / "Formal.lean").write_text(
                "import StageA.Dependency\nnamespace StageA\n"
                "def formal := dependency\nend StageA\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE": str(root / "cache"),
            }):
                first = _compile_formal_kernel(root / "lean")
                self.assertEqual(first["status"], "checked", first)
                (stage_a / "Dependency.olean").unlink()
                (stage_a / "Formal.olean").unlink()

                second = _compile_formal_kernel(root / "lean")

            self.assertEqual(second["status"], "checked", second)
            self.assertTrue((stage_a / "Dependency.olean").is_file())
            self.assertTrue((stage_a / "Formal.olean").is_file())

    def test_precompiled_kernel_cache_requires_exact_source_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "work" / "StageA" / "Formal.lean"
            source.parent.mkdir(parents=True)
            source.write_text("def formal := 1\n", encoding="utf-8")
            precompiled = root / "precompiled" / "StageA"
            precompiled.mkdir(parents=True)
            cached_source = precompiled / "Formal.lean"
            cached_output = precompiled / "Formal.olean"
            cached_source.write_bytes(source.read_bytes())
            cached_output.write_bytes(b"compiled")

            with patch.dict(os.environ, {
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_PRECOMPILED_KERNEL": str(
                    precompiled.parent
                ),
            }):
                self.assertEqual(
                    _precompiled_kernel_olean(source, "Formal"), cached_output
                )
                cached_source.write_text("def formal := 2\n", encoding="utf-8")
                self.assertIsNone(_precompiled_kernel_olean(source, "Formal"))
                cached_source.write_bytes(source.read_bytes())
                cached_output.unlink()
                self.assertIsNone(_precompiled_kernel_olean(source, "Formal"))

    def test_relational_cache_uses_tmpdir_for_nix_sandbox_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(
                os.environ,
                {
                    "HOME": "/homeless-shelter",
                    "TMPDIR": temporary,
                },
                clear=False,
            ):
                os.environ.pop("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_CACHE", None)
                os.environ.pop("XDG_CACHE_HOME", None)
                self.assertEqual(
                    _relational_cache_dir(),
                    Path(temporary) / "spaghetti-extractor-cache" / "stage-a-relational-v1",
                )

    def test_relational_nix_build_command_disables_local_jobs_for_builders_file(self):
        builders_file = Path("/tmp/stage-a-builders")

        remote_command = _relational_nix_build_command("proof-expression", builders_file)
        local_command = _relational_nix_build_command("proof-expression", None)

        self.assertEqual(
            remote_command[:10],
            [
                "nix", "build", "--max-jobs", "0", "--cores", "2", "--builders",
                "@/tmp/stage-a-builders", "--no-link", "--json",
            ],
        )
        self.assertNotIn("--max-jobs", local_command)
        self.assertNotIn("--builders", local_command)

    def test_relational_nix_graph_does_not_prefer_local_derivations(self):
        evaluator = (
            Path(__file__).parents[1] / "nix" / "stage-a-lean-graph.nix"
        ).read_text(encoding="utf-8")

        self.assertNotIn("preferLocalBuild = true", evaluator)
        self.assertGreaterEqual(evaluator.count("preferLocalBuild = false"), 3)
        self.assertEqual(evaluator.count("lean -j 2"), 2)
        self.assertIn(
            'leanJobs = if node.resource_class == "high-memory" then "1" else "2";',
            evaluator,
        )
        self.assertIn("lean -j ${leanJobs}", evaluator)
        self.assertEqual(
            evaluator.count("ulimit -s unlimited 2>/dev/null || true"), 2
        )
        high_memory_scheduler = evaluator.split(
            'node.resource_class == "high-memory"', 1
        )[1].split("''}", 1)[0]
        self.assertIn("compile_jobs=1", high_memory_scheduler)
        self.assertNotIn("compile_jobs=2", high_memory_scheduler)
        self.assertNotIn("dependencyClosures", evaluator)
        self.assertIn("node.dependencies", evaluator)
        self.assertIn("inherited-olean-index", evaluator)
        self.assertIn("inherited-node-result-index", evaluator)
        detached = evaluator.split("selectedNodeResults =", 1)[1].split(
            "\nin\n", 1
        )[0]
        self.assertIn("-detached", detached)
        self.assertIn('cp -L "${source}"/StageA/*.olean', detached)
        self.assertIn('cp "${source}/module-result.json"', detached)
        self.assertNotIn("inherited-olean-index", detached)
        self.assertNotIn("inherited-node-result-index", detached)

    def test_nix_finalization_requires_the_whole_program_theorem(self):
        proof_ir = {
            "status": "incomplete",
            "families": [],
            "obligations": [
                {
                    "id": "external-call-edge:7",
                    "kind": "external_call_product_edge_refinement",
                    "status": "pending_lean",
                    "edge_id": 7,
                },
                {
                    "id": "external-call-edge:8",
                    "kind": "external_call_product_edge_refinement",
                    "status": "incomplete",
                    "edge_id": 8,
                    "blocker": "missing contract",
                },
            ],
        }

        finalized = _finalize_nix_proof_ir(
            proof_ir,
            theorem_checked=True,
            theorem="StageA.GeneratedRelational.candidateRelationalEvidenceBundle",
            result_path=Path("/nix/store/stage-a-test"),
        )

        checked, gap = finalized["obligations"]
        self.assertEqual(checked["status"], "pending_lean")
        self.assertIsNone(checked.get("evidence"))
        self.assertEqual(gap["status"], "incomplete")
        self.assertEqual(finalized["status"], "incomplete")
        external_family = next(
            family for family in finalized["families"]
            if family["family"] == "paired_external_environment_refinement"
        )
        self.assertEqual(external_family["status"], "incomplete")

        intermediate_only = _finalize_nix_proof_ir(
            {**proof_ir, "obligations": [proof_ir["obligations"][0]]},
            theorem_checked=True,
            theorem="StageA.GeneratedRelational.candidateRelationalEvidenceBundle",
            result_path=Path("/nix/store/stage-a-test"),
        )
        intermediate_family = next(
            family for family in intermediate_only["families"]
            if family["family"] == "paired_external_environment_refinement"
        )
        self.assertEqual(intermediate_family["status"], "incomplete")
        self.assertEqual(intermediate_only["status"], "incomplete")

    def test_behavior_cache_hash_is_owned_by_decode_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "RelationalDecode.lean"
            source.write_text(
                "def decoderVersion := 1\n",
                encoding="utf-8",
            )
            initial = _relational_extraction_semantics_sha256(source)
            proof_source = Path(temporary) / "Relational.lean"
            proof_source.write_text("def proofVersion := 1\n", encoding="utf-8")
            proof_source.write_text("def proofVersion := 2\n", encoding="utf-8")
            self.assertEqual(
                _relational_extraction_semantics_sha256(source), initial
            )
            source.write_text(
                "def decoderVersion := 2\n",
                encoding="utf-8",
            )
            self.assertNotEqual(
                _relational_extraction_semantics_sha256(source), initial
            )

    def test_dynamic_range_indirect_call_requires_unique_typed_word(self):
        def read_target(register: str, offset: int) -> dict:
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": offset},
                },
            }

        behaviors = [{
            "original_ir": {
                "outcome": {
                    "op": "indirect_call", "target": read_target("ebx", 4),
                    "continuation": 9,
                },
            },
            "candidate_ir": {
                "outcome": {
                    "op": "indirect_call", "target": read_target("esi", 4),
                    "continuation": 9,
                },
            },
        }]
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 8, "candidate_offset": 8,
            "required_words": [{"offset": 12, "kind": "codePointer"}],
            "active_words": [{"offset": 12, "kind": "codePointer"}],
        }
        contract = {"regions": [{
            "id": "callback", "input_dynamic_range_relations": [relation],
        }]}

        candidates = _dynamic_range_indirect_call_candidates(contract, behaviors)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["word_offset"], 4)
        self.assertEqual(candidates[0]["range_relation"], relation)
        inactive = json.loads(json.dumps(contract))
        inactive["regions"][0]["input_dynamic_range_relations"][0][
            "active_words"
        ] = []
        self.assertEqual(
            _dynamic_range_indirect_call_candidates(inactive, behaviors), []
        )
        missing = {"regions": [{
            "id": "callback", "input_dynamic_range_relations": [],
        }]}
        self.assertEqual(
            _dynamic_range_indirect_call_candidates(missing, behaviors), []
        )
        ambiguous = json.loads(json.dumps(contract))
        duplicate = json.loads(json.dumps(relation))
        duplicate["required_words"].append({"offset": 16, "kind": "dataPointer"})
        ambiguous["regions"][0]["input_dynamic_range_relations"].append(duplicate)
        self.assertEqual(
            _dynamic_range_indirect_call_candidates(ambiguous, behaviors), []
        )
        mismatched = json.loads(json.dumps(behaviors))
        mismatched[0]["candidate_ir"]["outcome"]["target"] = read_target("esi", 8)
        self.assertEqual(
            _dynamic_range_indirect_call_candidates(contract, mismatched), []
        )

    def test_dynamic_range_relation_validation_fails_closed(self):
        valid = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 8, "kind": "codePointer"},
                {"offset": 4, "kind": "relatedWord"},
            ],
        }
        issues = []
        self.assertEqual(
            _dynamic_range_relations([valid], issues, "region", "input"),
            [{
                **valid,
                "required_words": list(reversed(valid["required_words"])),
                "active_words": list(reversed(valid["required_words"])),
            }],
        )
        self.assertEqual(issues, [])

        for malformed in (
            {**valid, "required_words": [{"offset": 4, "kind": "unknown"}]},
            {**valid, "required_words": [
                {"offset": 4, "kind": "relatedWord"},
                {"offset": 4, "kind": "codePointer"},
            ]},
            {**valid, "original_offset": 2**32},
        ):
            malformed_issues = []
            self.assertEqual(
                _dynamic_range_relations(
                    [malformed], malformed_issues, "region", "input"
                ),
                [],
            )
            self.assertEqual(malformed_issues[0]["severity"], "hard")

        inactive_issues = []
        self.assertEqual(
            _dynamic_range_relations([{
                **valid,
                "active_words": [{"offset": 12, "kind": "relatedWord"}],
            }], inactive_issues, "region", "input"),
            [],
        )
        self.assertEqual(inactive_issues[0]["severity"], "hard")

        duplicate_issues = []
        self.assertEqual(
            len(_dynamic_range_relations(
                [valid, valid], duplicate_issues, "region", "input"
            )),
            1,
        )
        self.assertEqual(duplicate_issues[0]["severity"], "hard")

    def test_static_dynamic_pointer_slot_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_path = root / "original.exe"
            candidate_path = root / "candidate.exe"
            original_path.write_bytes(_pe32_image_with_relocated_data(0x3000))
            candidate_path.write_bytes(_pe32_image_with_relocated_data(0x3000))
            original = _parse_stage_a_pe(original_path)
            candidate = _parse_stage_a_pe(candidate_path)
            valid = {
                "id": 3,
                "original_address": 0x403000,
                "candidate_address": 0x403000,
                "required_words": [
                    {"offset": 4, "kind": "codePointer"},
                    {"offset": 8, "kind": "nullableDynamicPointer"},
                ],
            }

            issues: list[dict] = []
            self.assertEqual(
                _static_dynamic_pointer_slots([valid], original, candidate, issues),
                [valid],
            )
            self.assertEqual(issues, [])

            malformed_cases = (
                ({**valid, "original_address": 0x401000},
                 "static_dynamic_pointer_slot_not_writable_data"),
                ({**valid, "required_words": [
                    {"offset": 4, "kind": "codePointer"},
                    {"offset": 6, "kind": "dataPointer"},
                ]}, "static_dynamic_pointer_slot_invalid"),
                ([valid, {**valid, "id": 4}],
                 "static_dynamic_pointer_slot_overlap"),
            )
            for malformed, category in malformed_cases:
                malformed_issues: list[dict] = []
                rows = malformed if isinstance(malformed, list) else [malformed]
                _static_dynamic_pointer_slots(
                    rows, original, candidate, malformed_issues
                )
                self.assertIn(
                    category, {issue["category"] for issue in malformed_issues}
                )
                self.assertTrue(all(
                    issue.get("severity") == "hard" for issue in malformed_issues
                ))

            iat_import = StageAImport(
                dll="fixture.dll", symbol="fixture", ordinal=None,
                thunk_rva=0x3000,
            )
            iat_issues: list[dict] = []
            _static_dynamic_pointer_slots(
                [valid], replace(original, imports=(iat_import,)), candidate,
                iat_issues,
            )
            self.assertIn(
                "static_dynamic_pointer_slot_overlaps_iat",
                {issue["category"] for issue in iat_issues},
            )

    def test_static_word_relation_slots_are_checked_and_inferred(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "fixture.exe"
            image.write_bytes(_pe32_image_with_relocated_data(0x3000))
            original = _parse_stage_a_pe(image)
            candidate = _parse_stage_a_pe(image)
            valid = {
                "id": 0,
                "original_address": 0x403000,
                "candidate_address": 0x403000,
                "relation": "exact",
            }
            issues: list[dict] = []
            self.assertEqual(
                _static_word_relation_slots(
                    [valid], [], original, candidate, issues
                ),
                [valid],
            )
            self.assertEqual(issues, [])

            pointer_slot = {
                "id": 4,
                "original_address": 0x403000,
                "candidate_address": 0x403000,
                "required_words": [{"offset": 0, "kind": "relatedWord"}],
            }
            overlap_issues: list[dict] = []
            self.assertEqual(
                _static_word_relation_slots(
                    [valid], [pointer_slot], original, candidate, overlap_issues
                ),
                [],
            )
            self.assertIn(
                "static_word_relation_slot_overlap",
                {issue["category"] for issue in overlap_issues},
            )

            contract = {
                "regions": [{
                    "id": "static-write",
                    "input_relations": [],
                    "code_targets": [],
                    "values": [],
                }],
                "static_word_relation_slots": [],
            }
            behavior = {
                "original_ir": {"writes": [{
                    "address": {"op": "constant", "value": 0x403000},
                    "value": {"op": "constant", "value": 1},
                }]},
                "candidate_ir": {"writes": [{
                    "address": {"op": "constant", "value": 0x403000},
                    "value": {"op": "constant", "value": 1},
                }]},
            }
            inferred, analysis = _attach_static_word_relation_slots(
                contract, [behavior], original, candidate
            )
            self.assertEqual(analysis["counts"], {
                "existing": 0, "inferred": 1, "rejected": 0,
            })
            self.assertEqual(inferred["static_word_relation_slots"], [valid])

            related_contract = json.loads(json.dumps(contract))
            related_contract["regions"][0]["input_relations"] = [{
                "original": "eax", "candidate": "ebx",
                "relation": "related_word",
            }]
            related_behavior = json.loads(json.dumps(behavior))
            related_behavior["original_ir"]["writes"][0]["value"] = {
                "op": "input_reg", "reg": "eax",
            }
            related_behavior["candidate_ir"]["writes"][0]["value"] = {
                "op": "input_reg", "reg": "ebx",
            }
            related, related_analysis = _attach_static_word_relation_slots(
                related_contract, [related_behavior], original, candidate
            )
            self.assertEqual(related_analysis["counts"]["inferred"], 1)
            self.assertEqual(
                related["static_word_relation_slots"][0]["relation"],
                "related_word",
            )

            cursor_contract = json.loads(json.dumps(contract))
            cursor_value = {
                "op": "add",
                "left": {
                    "op": "read32",
                    "address": {"op": "constant", "value": 0x403000},
                },
                "right": {"op": "constant", "value": 4},
            }
            cursor_behavior = {
                "original_ir": {"writes": [{
                    "address": {"op": "constant", "value": 0x403000},
                    "value": cursor_value,
                }]},
                "candidate_ir": {"writes": [{
                    "address": {"op": "constant", "value": 0x403000},
                    "value": cursor_value,
                }]},
            }
            cursor, cursor_analysis = _attach_static_word_relation_slots(
                cursor_contract, [cursor_behavior], original, candidate
            )
            self.assertEqual(cursor_analysis["counts"], {
                "existing": 0, "inferred": 1, "rejected": 0,
            })
            self.assertEqual(cursor["static_word_relation_slots"], [valid])

    def test_machine_import_call_contract_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "fixture.exe"
            image.write_bytes(_pe32_image_with_relocated_data(0x3000))
            binary = replace(
                _parse_stage_a_pe(image),
                imports=(StageAImport(
                    dll="KERNEL32.dll", symbol="EnterCriticalSection",
                    ordinal=None, thunk_rva=0x3010,
                ),),
            )
            write_footprint = {
                "access": "write",
                "base_argument": 0,
                "offset": 0,
                "size": {"kind": "fixed", "bytes": 24},
                "nullable": False,
            }
            valid = {
                "id": 4,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "stack_argument_offsets": [0],
                "stack_result_delta": 4,
                "preserved_registers": ["ebx", "esi", "edi", "ebp"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "result_register_relations": [
                    {"register": "eax", "relation": "exact"},
                    {"register": "edx", "relation": "related_word"},
                ],
                "memory_effect": "argumentRanges",
                "memory_footprints": [write_footprint],
                "world_effect": "opaqueResources",
            }
            issues: list[dict] = []
            normalized = _machine_import_call_contracts(
                [valid], binary, binary, issues
            )
            self.assertEqual(issues, [])
            self.assertEqual(normalized[0]["import"], {
                "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
            })
            self.assertEqual(
                normalized[0]["memory_footprints"], [write_footprint]
            )
            self.assertEqual(normalized[0]["result_register_relations"], [
                {"register": "eax", "relation": "exact"},
                {"register": "edx", "relation": "related_word"},
            ])

            dynamic_result = {
                **valid,
                "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "fixed", "bytes": 12},
                    "minimum_size": 12,
                    "required_words": [
                        {"offset": 0, "relation": "related_word"},
                        {"offset": 8, "relation": "nullable_dynamic_pointer"},
                    ],
                    "nullable": True,
                }],
                "world_effect": "dynamicRanges",
            }
            dynamic_issues: list[dict] = []
            normalized_dynamic = _machine_import_call_contracts(
                [dynamic_result], binary, binary, dynamic_issues
            )
            self.assertEqual(dynamic_issues, [])
            self.assertEqual(
                normalized_dynamic[0]["result_register_relations"],
                [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "fixed", "bytes": 12},
                    "minimum_size": 12,
                    "required_words": [
                        {"offset": 0, "relation": "related_word"},
                        {"offset": 8, "relation": "nullable_dynamic_pointer"},
                    ],
                    "nullable": True,
                }],
            )

            product_result = {
                **valid,
                "stack_argument_offsets": [0, 4],
                "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {
                        "kind": "product",
                        "left_argument": 0,
                        "right_argument": 1,
                    },
                    "minimum_size": 12,
                    "required_words": [
                        {"offset": 0, "relation": "related_word"},
                        {"offset": 4, "relation": "data_pointer"},
                        {"offset": 8, "relation": "nullable_dynamic_pointer"},
                    ],
                    "nullable": True,
                }],
                "world_effect": "dynamicRanges",
            }
            product_issues: list[dict] = []
            normalized_product = _machine_import_call_contracts(
                [product_result], binary, binary, product_issues
            )
            self.assertEqual(product_issues, [])
            self.assertEqual(
                normalized_product[0]["result_register_relations"][0]["size"],
                {
                    "kind": "product",
                    "left_argument": 0,
                    "right_argument": 1,
                },
            )

            zero_sized_result = {
                **dynamic_result,
                "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "argument", "argument": 0, "scale": 1},
                    "minimum_size": 0,
                    "required_words": [],
                    "nullable": True,
                }],
                "memory_effect": "newDynamicRanges",
                "memory_footprints": [],
            }
            zero_sized_issues: list[dict] = []
            normalized_zero_sized = _machine_import_call_contracts(
                [zero_sized_result], binary, binary, zero_sized_issues
            )
            self.assertEqual(zero_sized_issues, [])
            self.assertEqual(
                normalized_zero_sized[0]["result_register_relations"][0][
                    "minimum_size"
                ],
                0,
            )

            optional = {
                **valid,
                "memory_footprints": [{**write_footprint, "nullable": True}],
            }
            optional_issues: list[dict] = []
            normalized_optional = _machine_import_call_contracts(
                [optional], binary, binary, optional_issues
            )
            self.assertEqual(optional_issues, [])
            self.assertTrue(
                normalized_optional[0]["memory_footprints"][0]["nullable"]
            )

            templated = {
                "id": 4,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "memory_effect": "argumentRanges",
                "memory_footprints": [write_footprint],
                "world_effect": "opaqueResources",
            }
            template_issues: list[dict] = []
            normalized_template = _machine_import_call_contracts(
                [templated], binary, binary, template_issues
            )
            self.assertEqual(template_issues, [])
            self.assertEqual(
                normalized_template[0]["stack_argument_offsets"], [0]
            )
            self.assertEqual(normalized_template[0]["stack_result_delta"], 4)
            self.assertEqual(
                normalized_template[0]["preserved_registers"],
                ["ebp", "ebx", "edi", "esi"],
            )
            self.assertEqual(
                normalized_template[0]["clobbered_registers"],
                ["eax", "ecx", "edx"],
            )
            self.assertNotIn("abi_template", normalized_template[0])
            self.assertNotIn("argument_words", normalized_template[0])
            replay_issues: list[dict] = []
            self.assertEqual(
                _machine_import_call_contracts(
                    normalized_template, binary, binary, replay_issues
                ),
                normalized_template,
            )
            self.assertEqual(replay_issues, [])

            cdecl = {
                **templated,
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 3,
            }
            cdecl_issues: list[dict] = []
            normalized_cdecl = _machine_import_call_contracts(
                [cdecl], binary, binary, cdecl_issues
            )
            self.assertEqual(cdecl_issues, [])
            self.assertEqual(
                normalized_cdecl[0]["stack_argument_offsets"], [0, 4, 8]
            )
            self.assertEqual(normalized_cdecl[0]["stack_result_delta"], 0)

            free_binary = replace(
                binary,
                imports=(StageAImport(
                    dll="msvcrt.dll", symbol="free", ordinal=None,
                    thunk_rva=0x3010,
                ),),
            )
            release = {
                "id": 9,
                "import": {"dll": "msvcrt.dll", "symbol": "free"},
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 1,
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "dynamicRangeRelease",
                "world_effect_argument": 0,
            }
            release_issues: list[dict] = []
            normalized_release = _machine_import_call_contracts(
                [release], free_binary, free_binary, release_issues
            )
            self.assertEqual(release_issues, [])
            self.assertEqual(
                normalized_release[0]["world_effect"], "dynamicRangeRelease"
            )
            self.assertEqual(normalized_release[0]["world_effect_argument"], 0)

            callback_binary = replace(
                binary,
                imports=(StageAImport(
                    dll="msvcrt.dll", symbol="atexit", ordinal=None,
                    thunk_rva=0x3010,
                ),),
            )
            callback_registration = {
                "id": 10,
                "import": {"dll": "msvcrt.dll", "symbol": "atexit"},
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 1,
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "callbackRegistration",
                "world_effect_argument": 0,
            }
            callback_issues: list[dict] = []
            normalized_callback = _machine_import_call_contracts(
                [callback_registration], callback_binary, callback_binary,
                callback_issues,
            )
            self.assertEqual(callback_issues, [])
            self.assertEqual(
                normalized_callback[0]["world_effect"], "callbackRegistration"
            )
            self.assertEqual(
                normalized_callback[0]["world_effect_argument"], 0
            )

            for malformed_callback in (
                {key: value for key, value in callback_registration.items()
                 if key != "world_effect_argument"},
                {**callback_registration, "world_effect_argument": 1},
                {**callback_registration, "world_effect": "none"},
            ):
                callback_failure_issues: list[dict] = []
                self.assertEqual(
                    _machine_import_call_contracts(
                        [malformed_callback], callback_binary, callback_binary,
                        callback_failure_issues,
                    ),
                    [],
                )
                self.assertEqual(
                    callback_failure_issues[0]["category"],
                    "machine_import_call_contract_invalid",
                )

            terminal_binary = replace(
                binary,
                imports=(StageAImport(
                    dll="msvcrt.dll", symbol="_amsg_exit", ordinal=None,
                    thunk_rva=0x3010,
                ),),
            )
            terminal = {
                "id": 10,
                "import": {"dll": "msvcrt.dll", "symbol": "_amsg_exit"},
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 1,
                "disposition": "terminates",
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }
            terminal_issues: list[dict] = []
            normalized_terminal = _machine_import_call_contracts(
                [terminal], terminal_binary, terminal_binary, terminal_issues
            )
            self.assertEqual(terminal_issues, [])
            self.assertEqual(normalized_terminal[0]["disposition"], "terminates")
            self.assertEqual(normalized_terminal[0]["stack_result_delta"], 0)

            protocol_binary = replace(
                binary,
                imports=(StageAImport(
                    dll="msvcrt.dll", symbol="exit", ordinal=None,
                    thunk_rva=0x3010,
                ),),
            )
            protocol = {
                "id": 11,
                "import": {"dll": "msvcrt.dll", "symbol": "exit"},
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 1,
                "disposition": "protocol",
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }
            protocol_issues: list[dict] = []
            normalized_protocol = _machine_import_call_contracts(
                [protocol], protocol_binary, protocol_binary, protocol_issues
            )
            self.assertEqual(protocol_issues, [])
            self.assertEqual(normalized_protocol[0]["disposition"], "protocol")

            malformed_protocol_issues: list[dict] = []
            self.assertEqual(
                _machine_import_call_contracts(
                    [{**protocol, "world_effect": "opaqueResources"}],
                    protocol_binary, protocol_binary, malformed_protocol_issues,
                ),
                [],
            )
            self.assertEqual(
                malformed_protocol_issues[0]["category"],
                "machine_import_call_contract_invalid",
            )

            for malformed_terminal in (
                {**terminal, "disposition": "sometimes"},
                {**terminal, "world_effect": "opaqueResources"},
                {**terminal, "result_register_relations": [{
                    "register": "eax", "relation": "exact",
                }]},
                {**terminal, "memory_effect": "readOnly", "memory_footprints": [{
                    "access": "read",
                    "base_argument": 0,
                    "offset": 0,
                    "size": {"kind": "fixed", "bytes": 4},
                    "nullable": False,
                }]},
            ):
                terminal_failure_issues: list[dict] = []
                self.assertEqual(
                    _machine_import_call_contracts(
                        [malformed_terminal], terminal_binary, terminal_binary,
                        terminal_failure_issues,
                    ),
                    [],
                )
                self.assertEqual(
                    terminal_failure_issues[0]["category"],
                    "machine_import_call_contract_invalid",
                )

            for malformed_release in (
                {key: value for key, value in release.items()
                 if key != "world_effect_argument"},
                {**release, "world_effect_argument": 1},
                {**release, "world_effect": "none"},
            ):
                release_failure_issues: list[dict] = []
                self.assertEqual(
                    _machine_import_call_contracts(
                        [malformed_release], free_binary, free_binary,
                        release_failure_issues,
                    ),
                    [],
                )
                self.assertEqual(
                    release_failure_issues[0]["category"],
                    "machine_import_call_contract_invalid",
                )

            malformed_cases = (
                {**valid, "stack_argument_offsets": [2]},
                {**valid, "preserved_registers": ["ebx"]},
                {**valid, "memory_effect": "anything"},
                {**valid, "memory_effect": "opaqueStatic"},
                {**valid, "memory_footprints": []},
                {**valid, "memory_footprints": [{
                    **write_footprint, "base_argument": 1,
                }]},
                {**valid, "memory_footprints": [{
                    **write_footprint,
                    "size": {"kind": "fixed", "bytes": 0},
                }]},
                {**valid, "memory_footprints": [{
                    **write_footprint, "nullable": 1,
                }]},
                {**valid, "memory_footprints": [
                    write_footprint, write_footprint,
                ]},
                {**valid, "memory_footprints": [
                    write_footprint, {**write_footprint, "nullable": True},
                ]},
                {**valid, "memory_effect": "none"},
                {**valid, "memory_effect": "readOnly"},
                {**valid, "memory_footprints": [{
                    **write_footprint,
                    "size": {
                        "kind": "argument", "argument": 1, "scale": 1,
                    },
                }]},
                {**templated, "abi_template": "pe32-fastcall-v1"},
                {**templated, "memory_effect": None},
                {**templated, "stack_result_delta": 4},
                {**templated, "argument_words": 1025},
                {**valid, "result_register_relations": [{
                    "register": "esp", "relation": "exact",
                }]},
                {**valid, "result_register_relations": [{
                    "register": "ebx", "relation": "exact",
                }]},
                {**valid, "result_register_relations": [
                    {"register": "eax", "relation": "exact"},
                    {"register": "eax", "relation": "related_word"},
                ]},
                {**valid, "result_register_relations": [{
                    "register": "eax", "relation": "symbolic",
                }]},
                {**dynamic_result, "world_effect": "none"},
                {**dynamic_result, "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "fixed", "bytes": 12},
                    "minimum_size": 0,
                    "required_words": [
                        {"offset": 0, "relation": "related_word"},
                    ],
                }]},
                {**dynamic_result, "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "fixed", "bytes": 4},
                    "minimum_size": 4,
                    "required_words": [
                        {"offset": 4, "relation": "related_word"},
                    ],
                }]},
                {**dynamic_result, "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "fixed", "bytes": 8},
                    "minimum_size": 8,
                    "required_words": [
                        {"offset": 0, "relation": "related_word"},
                        {"offset": 0, "relation": "data_pointer"},
                    ],
                }]},
                {**dynamic_result, "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "fixed", "bytes": 4},
                    "minimum_size": 8,
                    "required_words": [],
                }]},
                {**dynamic_result, "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "size": {"kind": "product", "left_argument": 0,
                             "right_argument": 1},
                    "minimum_size": 4,
                    "required_words": [],
                }]},
                {**valid, "result_register_relations": [{
                    "register": "eax",
                    "relation": "exact",
                    "minimum_size": 4,
                }]},
            )
            for malformed in malformed_cases:
                malformed_issues: list[dict] = []
                self.assertEqual(
                    _machine_import_call_contracts(
                        [malformed], binary, binary, malformed_issues
                    ),
                    [],
                )
                self.assertEqual(
                    malformed_issues[0]["category"],
                    "machine_import_call_contract_invalid",
                )
                self.assertEqual(malformed_issues[0]["severity"], "hard")

            missing_issues: list[dict] = []
            missing = {**valid, "import": {
                "dll": "kernel32.dll", "symbol": "TlsGetValue",
            }}
            self.assertEqual(
                _machine_import_call_contracts(
                    [missing], binary, binary, missing_issues
                ),
                [],
            )
            self.assertEqual(
                missing_issues[0]["category"],
                "machine_import_call_contract_import_mismatch",
            )

    def test_bounded_terminated_memory_footprints_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "fixture.exe"
            image.write_bytes(_pe32_image_with_relocated_data(0x3000))
            binary = replace(
                _parse_stage_a_pe(image),
                imports=(StageAImport(
                    dll="KERNEL32.dll", symbol="EnterCriticalSection",
                    ordinal=None, thunk_rva=0x3010,
                ),),
            )

            bounded = {
                "kind": "bounded_terminated",
                "source_argument": 1,
                "source_offset": 4,
                "unit_bytes": 2,
                "sentinel": [0, 0],
                "max_units": 16,
            }
            selected = {
                "kind": "argument_or_bounded_terminated",
                "length_argument": 0,
                "terminated_value": 0xFFFFFFFF,
                "source_argument": 1,
                "source_offset": 4,
                "unit_bytes": 2,
                "sentinel": [0, 0],
                "max_units": 16,
            }

            def footprint(size: dict, *, base: int = 0, offset: int = 0) -> dict:
                return {
                    "access": "read",
                    "base_argument": base,
                    "offset": offset,
                    "size": size,
                    "nullable": False,
                }

            def contract(
                footprints: list[dict],
                *,
                memory_effect: str = "readOnly",
                world_effect: str = "none",
                result_relations: list[dict] | None = None,
            ) -> dict:
                return {
                    "id": 8,
                    "import": {
                        "dll": "kernel32.dll",
                        "symbol": "EnterCriticalSection",
                    },
                    "stack_argument_offsets": [0, 4],
                    "stack_result_delta": 8,
                    "preserved_registers": ["ebx", "esi", "edi", "ebp"],
                    "clobbered_registers": ["eax", "ecx", "edx"],
                    "result_register_relations": result_relations or [],
                    "memory_effect": memory_effect,
                    "memory_footprints": footprints,
                    "world_effect": world_effect,
                }

            footprints = [
                footprint(bounded),
                footprint(selected, base=1, offset=4),
            ]
            issues: list[dict] = []
            normalized = _machine_import_call_contracts(
                [contract(footprints)], binary, binary, issues,
            )
            self.assertEqual(issues, [])
            self.assertEqual(normalized[0]["memory_footprints"], footprints)

            malformed_sizes = {
                "source index": {**bounded, "source_argument": 2},
                "negative source offset": {**bounded, "source_offset": -1},
                "source offset domain": {**bounded, "source_offset": 2**32},
                "source bound domain": {
                    **bounded,
                    "source_offset": 2**32 - 1,
                    "unit_bytes": 1,
                    "sentinel": [0],
                    "max_units": 2,
                },
                "empty sentinel": {**bounded, "sentinel": []},
                "sentinel width": {**bounded, "sentinel": [0]},
                "sentinel byte": {**bounded, "sentinel": [0, 256]},
                "zero unit": {
                    **bounded, "unit_bytes": 0, "sentinel": [],
                },
                "zero bound": {**bounded, "max_units": 0},
                "bound multiplication": {**bounded, "max_units": 2**31},
                "length index": {**selected, "length_argument": 2},
                "malformed selector": {**selected, "length_argument": []},
                "negative terminated value": {
                    **selected, "terminated_value": -1,
                },
                "terminated value domain": {
                    **selected, "terminated_value": 2**32,
                },
                "malformed terminated value": {
                    **selected, "terminated_value": "terminated",
                },
            }
            for name, malformed_size in malformed_sizes.items():
                with self.subTest(name=name):
                    malformed_issues: list[dict] = []
                    self.assertEqual(
                        _machine_import_call_contracts(
                            [contract([footprint(malformed_size)])],
                            binary,
                            binary,
                            malformed_issues,
                        ),
                        [],
                    )
                    self.assertEqual(
                        malformed_issues[0]["category"],
                        "machine_import_call_contract_invalid",
                    )

            for size in (bounded, selected):
                with self.subTest(duplicate=size["kind"]):
                    reordered = {
                        key: size[key] for key in reversed(tuple(size))
                    }
                    duplicate_issues: list[dict] = []
                    self.assertEqual(
                        _machine_import_call_contracts(
                            [contract([footprint(size), footprint(reordered)])],
                            binary,
                            binary,
                            duplicate_issues,
                        ),
                        [],
                    )
                    self.assertEqual(
                        duplicate_issues[0]["category"],
                        "machine_import_call_contract_invalid",
                    )

            for size in (bounded, selected):
                with self.subTest(result_size=size["kind"]):
                    result_issues: list[dict] = []
                    dynamic_result = contract(
                        [],
                        memory_effect="newDynamicRanges",
                        world_effect="dynamicRanges",
                        result_relations=[{
                            "register": "eax",
                            "relation": "dynamic_range_base",
                            "size": size,
                            "minimum_size": 0,
                            "required_words": [],
                            "nullable": False,
                        }],
                    )
                    self.assertEqual(
                        _machine_import_call_contracts(
                            [dynamic_result], binary, binary, result_issues,
                        ),
                        [],
                    )
                    self.assertEqual(
                        result_issues[0]["category"],
                        "machine_import_call_contract_invalid",
                    )

    def test_machine_import_call_analysis_requires_recovered_arguments(self):
        imported = {
            "dll": list(b"kernel32.dll"),
            "name": {"op": "symbol", "bytes": list(b"EnterCriticalSection")},
        }
        contract = {
            "machine_import_call_contracts": [{
                "id": 4,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "stack_argument_offsets": [0],
            }],
            "regions": [{"id": "external"}],
        }
        behavior = {
            "outcome": {
                "op": "external_call", "import": imported,
                "arguments": [{"op": "constant", "value": 0x410064}],
                "continuation": 1,
            },
        }

        recovered = _machine_import_call_contract_analysis(contract, [{
            "original_ir": behavior, "candidate_ir": behavior,
        }])
        missing = _machine_import_call_contract_analysis(
            {**contract, "machine_import_call_contracts": []}, [{
                "original_ir": behavior, "candidate_ir": behavior,
            }],
        )

        self.assertEqual(recovered["counts"]["argument_recovery_candidates"], 1)
        self.assertTrue(recovered["calls"][0]["arguments_recovered"])
        self.assertEqual(missing["counts"]["incomplete_call_sites"], 1)
        self.assertIsNone(missing["calls"][0]["contract_id"])

    def test_machine_import_contract_cache_invalidation_is_region_local(self):
        contract = {
            "import": {
                "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
            },
        }
        imported = {
            "dll": list(b"kernel32.dll"),
            "name": {"op": "symbol", "bytes": list(b"EnterCriticalSection")},
        }
        unrelated = {
            "semantic_ir": {"outcome": {"op": "jump", "target": 1}},
        }
        matching = {
            "semantic_ir": {
                "outcome": {"op": "external_call", "import": imported},
            },
        }

        self.assertFalse(
            _cached_behavior_affected_by_machine_contracts(unrelated, [contract])
        )
        self.assertTrue(
            _cached_behavior_affected_by_machine_contracts(matching, [contract])
        )

    def test_dynamic_range_transfer_requires_unique_identity_preservation(self):
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [{"offset": 4, "kind": "codePointer"}],
            "active_words": [{"offset": 4, "kind": "codePointer"}],
        }
        contract = {"regions": [
            {"input_dynamic_range_relations": [relation]},
            {"input_dynamic_range_relations": [relation]},
        ]}
        identity = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        behaviors = [{
            "original_ir": {"registers": identity},
            "candidate_ir": {"registers": identity},
        }]

        claims = _dynamic_range_transfer_claims(contract, behaviors, 0, 1, {}, {})

        self.assertEqual(claims, [{
            "kind": "preserve",
            "source_relation": relation, "target_relation": relation,
        }])
        missing = json.loads(json.dumps(contract))
        missing["regions"][0]["input_dynamic_range_relations"] = []
        self.assertIsNone(
            _dynamic_range_transfer_claims(missing, behaviors, 0, 1, {}, {})
        )
        ambiguous = json.loads(json.dumps(contract))
        ambiguous["regions"][0]["input_dynamic_range_relations"].append(
            json.loads(json.dumps(relation))
        )
        self.assertIsNone(
            _dynamic_range_transfer_claims(ambiguous, behaviors, 0, 1, {}, {})
        )
        stronger_target = json.loads(json.dumps(contract))
        stronger_target["regions"][1]["input_dynamic_range_relations"][0][
            "required_words"
        ].append({"offset": 8, "kind": "dataPointer"})
        self.assertIsNone(
            _dynamic_range_transfer_claims(
                stronger_target, behaviors, 0, 1, {}, {}
            )
        )

    def test_dynamic_range_transfer_accepts_checked_nullable_next_pointer(self):
        source_relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 4, "kind": "codePointer"},
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
            "active_words": [
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
        }
        target_relation = {**source_relation, "active_words": []}
        contract = {"regions": [
            {"input_dynamic_range_relations": [source_relation]},
            {"input_dynamic_range_relations": [target_relation]},
        ]}

        def read(register):
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": 8},
                },
            }

        def nonzero(value):
            return {
                "op": "not",
                "value": {
                    "op": "equal",
                    "left": {"op": "bit_and", "left": value, "right": value},
                    "right": {"op": "constant", "value": 0},
                },
            }

        original_read = read("ebx")
        candidate_read = read("esi")
        behaviors = [{
            "original_ir": {"registers": {"ebx": original_read}},
            "candidate_ir": {"registers": {"esi": candidate_read}},
        }]
        claims = _dynamic_range_transfer_claims(
            contract, behaviors, 0, 1,
            nonzero(original_read), nonzero(candidate_read),
        )
        self.assertEqual(claims, [{
            "kind": "nullable_pointer",
            "source_relation": source_relation,
            "target_relation": target_relation,
            "pointer_offset": 8,
        }])

        bad_guard = {"op": "constant", "value": True}
        self.assertIsNone(_dynamic_range_transfer_claims(
            contract, behaviors, 0, 1, bad_guard, bad_guard,
        ))

    def test_dynamic_range_transfer_accepts_checked_static_pointer_seed(self):
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 4, "kind": "codePointer"},
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
            "active_words": [],
        }
        slot = {
            "id": 5,
            "original_address": 0x41005C,
            "candidate_address": 0x42006C,
            "required_words": relation["required_words"],
        }
        contract = {
            "static_dynamic_pointer_slots": [slot],
            "regions": [
                {"input_dynamic_range_relations": []},
                {"input_dynamic_range_relations": [relation]},
            ],
        }
        original_read = {
            "op": "read32",
            "address": {"op": "constant", "value": slot["original_address"]},
        }
        candidate_read = {
            "op": "read32",
            "address": {"op": "constant", "value": slot["candidate_address"]},
        }
        original_guard = _nonzero_word_guard(original_read)
        candidate_guard = _nonzero_word_guard(candidate_read)
        behaviors = [{
            "original_ir": {"registers": {"ebx": original_read}},
            "candidate_ir": {"registers": {"esi": candidate_read}},
        }]

        claims = _dynamic_range_transfer_claims(
            contract, behaviors, 0, 1, original_guard, candidate_guard,
        )

        self.assertEqual(claims, [{
            "kind": "static_pointer_seed",
            "slot": slot,
            "target_relation": relation,
        }])
        self.assertEqual(
            _static_dynamic_pointer_slot_guard_claim(
                contract, original_guard, candidate_guard,
            ),
            {
                "profile": "static_dynamic_pointer_guard_v1",
                "kind": "nonzero",
                "slot": slot,
            },
        )
        self.assertEqual(
            _static_dynamic_pointer_slot_guard_claim(
                contract, original_guard["value"], candidate_guard["value"],
            )["kind"],
            "zero",
        )
        self.assertEqual(
            _dynamic_range_register_output_claims(
                {"outputs": [{
                    "original": "ebx", "candidate": "esi",
                    "relation": "related_word",
                }], "output_claims": []},
                claims,
            )[0]["claim"]["kind"],
            "static_pointer_seed",
        )
        missing_slot_contract = json.loads(json.dumps(contract))
        missing_slot_contract["static_dynamic_pointer_slots"] = []
        diagnostic = _static_dynamic_pointer_seed_diagnostic(
            missing_slot_contract, behaviors,
            {"regions": [{"outputs": [{
                "original": "ebx", "candidate": "esi",
                "relation": "related_word",
            }]}]},
            {
                "original_guard": original_guard,
                "candidate_guard": candidate_guard,
            },
            0, 1,
        )
        self.assertEqual(diagnostic["status"], "incomplete")
        self.assertIn(
            "static_dynamic_pointer_slot_not_unique", diagnostic["blockers"]
        )
        self.assertIn("0x0041005c", diagnostic["next_action"])

    def test_dynamic_range_output_bridge_covers_only_matching_missing_word(self):
        output_eax = {
            "original": "eax", "candidate": "eax", "relation": "related_word",
        }
        output_ebx = {
            "original": "ebx", "candidate": "esi", "relation": "related_word",
        }
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
        }
        register_region = {
            "outputs": [output_eax, output_ebx],
            "output_claims": [{"kind": "identity", "output": output_eax}],
        }
        next_claim = {
            "kind": "nullable_pointer",
            "source_relation": relation,
            "target_relation": relation,
            "pointer_offset": 8,
        }
        self.assertEqual(
            _dynamic_range_register_output_claims(register_region, [next_claim]),
            [{"output": output_ebx, "claim": next_claim}],
        )

        unrelated = json.loads(json.dumps(next_claim))
        unrelated["target_relation"]["candidate"] = "ebx"
        self.assertIsNone(
            _dynamic_range_register_output_claims(register_region, [unrelated])
        )
        exact_output = json.loads(json.dumps(register_region))
        exact_output["outputs"][1]["relation"] = "exact"
        self.assertIsNone(
            _dynamic_range_register_output_claims(exact_output, [next_claim])
        )

    def test_dynamic_pointer_feedback_names_missing_range_shape_and_guard(self):
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
        }

        def read(register):
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": 8},
                },
            }

        original_read = read("ebx")
        candidate_read = read("esi")
        behaviors = [{
            "original_ir": {"registers": {"ebx": original_read}},
            "candidate_ir": {"registers": {"esi": candidate_read}},
        }]
        register_relations = {"regions": [{"outputs": [{
            "original": "ebx", "candidate": "esi", "relation": "related_word",
        }]}]}
        self.assertIsNone(_dynamic_pointer_traversal_diagnostic(
            {"regions": [{}, {}]}, behaviors, register_relations,
            {
                "original_guard": _nonzero_word_guard(original_read),
                "candidate_guard": _nonzero_word_guard(candidate_read),
            },
            0, 1,
        ))
        edge = {
            "original_guard": _nonzero_word_guard(original_read),
            "candidate_guard": _nonzero_word_guard(candidate_read),
        }
        missing = _dynamic_pointer_traversal_diagnostic(
            {"regions": [
                {"input_dynamic_range_relations": [relation]},
                {},
            ]},
            behaviors, register_relations, edge, 0, 1,
        )
        self.assertEqual(missing["status"], "incomplete")
        self.assertEqual(missing["word_offset"], 8)
        self.assertEqual(missing["original_source_register"], "ebx")
        self.assertEqual(missing["candidate_output_register"], "esi")
        self.assertEqual(missing["blockers"], [
            "successor_dynamic_range_relation_not_unique",
        ])
        self.assertIn("word offset 8", missing["next_action"])

        edge["original_guard"] = {"op": "bool_constant", "value": True}
        edge["candidate_guard"] = {"op": "bool_constant", "value": True}
        bad_guard = _dynamic_pointer_traversal_diagnostic(
            {"regions": [
                {"input_dynamic_range_relations": [relation]},
                {"input_dynamic_range_relations": [relation]},
            ]},
            behaviors, register_relations, edge, 0, 1,
        )
        self.assertEqual(
            bad_guard["blockers"], ["paired_nonzero_guard_not_exact"]
        )

        edge["original_guard"] = _nonzero_word_guard(original_read)
        edge["candidate_guard"] = _nonzero_word_guard(candidate_read)
        ready = _dynamic_pointer_traversal_diagnostic(
            {"regions": [
                {"input_dynamic_range_relations": [relation]},
                {"input_dynamic_range_relations": [relation]},
            ]},
            behaviors, register_relations, edge, 0, 1,
        )
        self.assertEqual(ready["status"], "ready_for_lean_replay")
        self.assertEqual(ready["blockers"], [])

    def test_dynamic_indirect_call_feedback_identifies_missing_world_evidence(self):
        target = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "ebx"},
                "right": {"op": "constant", "value": 4},
            },
        }
        behaviors = [{
            "original_ir": {"outcome": {
                "op": "indirect_call", "target": target, "continuation": 1,
            }},
            "candidate_ir": {"outcome": {
                "op": "indirect_call", "target": target, "continuation": 1,
            }},
        }]
        attached = _attach_dynamic_indirect_call_analysis(
            {"obligations": [], "families": [], "status": "incomplete"},
            {"regions": [{"id": "dynamic-callback"}]},
            behaviors,
            [],
            {"evidence": {"reachable_decoded_control_frontier_node_ids": [0]}},
        )

        obligation = attached["obligations"][0]
        self.assertEqual(obligation["status"], "incomplete")
        self.assertEqual(
            obligation["repair_class"], "memory_loaded_code_pointer_relation"
        )
        self.assertIn("DynamicRegisterRangeRelation", obligation["next_action"])

    def test_relocated_readonly_function_pointer_call_emits_checked_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(
                _pe32_image_with_immutable_indirect_call(0x2000, callee_rva=0x1030)
            )
            candidate.write_bytes(
                _pe32_image_with_immutable_indirect_call(0x3000, callee_rva=0x1040)
            )
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "indirect-call",
                    "kind": "code",
                    "original": {"rva": 0x1000, "size": 29},
                    "candidate": {"rva": 0x1000, "size": 29},
                },
                {
                    "id": "continuation",
                    "kind": "code",
                    "original": {"rva": 0x101D, "size": 2},
                    "candidate": {"rva": 0x101D, "size": 2},
                },
                {
                    "id": "callee",
                    "kind": "code",
                    "original": {"rva": 0x1030, "size": 1},
                    "candidate": {"rva": 0x1040, "size": 1},
                },
                {
                    "id": "alignment-padding",
                    "kind": "padding",
                    "original": {"rva": 0x101F, "size": 17},
                    "candidate": {"rva": 0x101F, "size": 33},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"
            stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )

            report = root / "report"
            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["status"], "prepared", result)
            indirect = json.loads(
                (report / "relational-indirect-call-targets.json").read_text(
                    encoding="utf-8"
                )
            )["candidates"]
            self.assertEqual(len(indirect), 1)
            self.assertEqual(indirect[0]["profile"],
                             "immutable_relocated_function_pointer_call_v1")
            graph = json.loads(
                (report / "relational-product-graph.json").read_text(encoding="utf-8")
            )
            self.assertIn(
                indirect[0]["source_region_index"],
                graph["evidence"]["decoded_control_complete_node_ids"],
            )
            register_relations = json.loads(
                (report / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            indirect_edges = [
                edge for edge in register_relations["edges"]
                if edge.get("indirect_target_profile") ==
                    "immutable_relocated_function_pointer_call_v1"
            ]
            self.assertEqual(len(indirect_edges), 1)
            indirect_edge = indirect_edges[0]
            self.assertEqual(
                indirect_edge["indirect_call_push_claim"]["profile"],
                "mapped_indirect_call_push_v1",
            )
            self.assertEqual(
                indirect_edge["return_slot_seed"],
                {
                    "profile": "indirect_call_runtime_frame_seed_v1",
                    "target_region_index": indirect[0]["target_region_index"],
                    "offsets": {
                        "original_register": "esp", "original": 0,
                        "candidate_register": "esp", "candidate": 0,
                    },
                },
            )
            self.assertEqual(
                register_relations["counts"]["checked_indirect_call_pushes"], 1
            )
            proof_ir = json.loads(
                (report / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            indirect_push_obligations = [
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "indirect_call_push"
            ]
            self.assertEqual(len(indirect_push_obligations), 1)
            self.assertEqual(
                indirect_push_obligations[0]["status"],
                "candidate_requires_lean_replay",
            )
            generated = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (report / "lean" / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                )
            )
            self.assertIn("immutableIndirectCallTargetsClosed_of_checked", generated)
            self.assertIn("ImmutableIndirectCallTargetsClosed", generated)
            generated_registers = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (report / "lean" / "StageA").glob(
                    "RelationalRegisterRelationsChunk*.lean"
                )
            )
            self.assertIn("IndirectCallPushClaim", generated_registers)
            self.assertIn("IndirectCallPushClosed staticProofContext", generated_registers)
            self.assertIn("apply indirectCallPushClosed_of_checked", generated_registers)
            dynamic_certificate = (
                report
                / "lean"
                / "StageA"
                / "RelationalDynamicRangeIndirectCallCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("import StageA.RelationalComposition", dynamic_certificate)
            self.assertNotIn(
                "import StageA.RelationalProductGraphContext", dynamic_certificate
            )

            semantic = json.loads(
                (report / "relational-semantic-ir.json").read_text(encoding="utf-8")
            )
            behaviors = [
                {"original_ir": row["original"], "candidate_ir": row["candidate"]}
                for row in semantic["regions"]
            ]
            normalized = json.loads(
                (report / "relation-contract.json").read_text(encoding="utf-8")
            )
            normalized["regions"][indirect[0]["source_region_index"]][
                "address_separations"
            ] = []
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    _parse_stage_a_pe(original), _parse_stage_a_pe(candidate),
                    normalized, behaviors,
                ),
                [],
            )

            ambiguous = json.loads(
                (report / "relation-contract.json").read_text(encoding="utf-8")
            )
            duplicate = dict(ambiguous["code_targets"][indirect[0]["target_id"]])
            duplicate["id"] = max(
                target["id"] for target in ambiguous["code_targets"]
            ) + 1
            ambiguous["code_targets"].append(duplicate)
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    _parse_stage_a_pe(original), _parse_stage_a_pe(candidate),
                    ambiguous, behaviors,
                ),
                [],
            )

            writable = root / "writable.exe"
            writable.write_bytes(
                _pe32_image_with_immutable_indirect_call(0x2000, writable=True)
            )
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    _parse_stage_a_pe(writable), _parse_stage_a_pe(candidate),
                    json.loads((report / "relation-contract.json").read_text()),
                    behaviors,
                ),
                [],
            )

    def test_equal_address_writable_relocation_table_is_mapped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1030, writable=True,
            ))
            candidate.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1040, writable=True,
            ))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "indirect-call",
                    "kind": "code",
                    "original": {"rva": 0x1000, "size": 29},
                    "candidate": {"rva": 0x1000, "size": 29},
                },
                {
                    "id": "continuation",
                    "kind": "code",
                    "original": {"rva": 0x101D, "size": 2},
                    "candidate": {"rva": 0x101D, "size": 2},
                },
                {
                    "id": "callee",
                    "kind": "code",
                    "original": {"rva": 0x1030, "size": 1},
                    "candidate": {"rva": 0x1040, "size": 1},
                },
                {
                    "id": "alignment-padding",
                    "kind": "padding",
                    "original": {"rva": 0x101F, "size": 17},
                    "candidate": {"rva": 0x101F, "size": 33},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )

            self.assertEqual(generated["status"], "generated", generated)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["value_targets"]), 1, payload)
            value = payload["value_targets"][0]
            self.assertEqual(value["original_value"], 0x402000)
            self.assertEqual(value["candidate_value"], 0x402000)
            self.assertEqual(value["mapped_size"], 4)
            self.assertEqual(value["relocation_offsets"], [0])
            self.assertIn(value["id"], payload["regions"][0]["value_target_ids"])
            self.assertIn(2, payload["regions"][0]["target_ids"])

    def test_equal_address_readonly_relocated_code_pointer_is_mapped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1030,
            ))
            candidate.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1030,
            ))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "indirect-call",
                    "kind": "code",
                    "original": {"rva": 0x1000, "size": 29},
                    "candidate": {"rva": 0x1000, "size": 29},
                },
                {
                    "id": "continuation",
                    "kind": "code",
                    "original": {"rva": 0x101D, "size": 2},
                    "candidate": {"rva": 0x101D, "size": 2},
                },
                {
                    "id": "callee",
                    "kind": "code",
                    "original": {"rva": 0x1030, "size": 1},
                    "candidate": {"rva": 0x1030, "size": 1},
                },
                {
                    "id": "alignment-padding",
                    "kind": "padding",
                    "original": {"rva": 0x101F, "size": 17},
                    "candidate": {"rva": 0x101F, "size": 17},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping,
                out=contract,
            )

            self.assertEqual(generated["status"], "generated", generated)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["value_targets"]), 1, payload)
            value = payload["value_targets"][0]
            self.assertEqual(value["original_value"], 0x402000)
            self.assertEqual(value["candidate_value"], 0x402000)
            self.assertEqual(value["mapped_size"], 4)
            self.assertEqual(value["relocation_offsets"], [0])
            self.assertIn(value["id"], payload["regions"][0]["value_target_ids"])
            callee_target = next(
                target["id"] for target in payload["code_targets"]
                if target["original_rva"] == 0x1030
                and target["candidate_rva"] == 0x1030
            )
            self.assertIn(callee_target, payload["regions"][0]["target_ids"])

    def test_relocated_readonly_function_pointer_jump_closes_local_proof_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(
                _pe32_image_with_immutable_indirect_call(
                    0x2000, callee_rva=0x1030, jump=True,
                )
            )
            candidate.write_bytes(
                _pe32_image_with_immutable_indirect_call(
                    0x3000, callee_rva=0x1040, jump=True,
                )
            )
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "indirect-jump",
                    "kind": "code",
                    "original": {"rva": 0x1000, "size": 6},
                    "candidate": {"rva": 0x1000, "size": 6},
                },
                {
                    "id": "callee",
                    "kind": "code",
                    "original": {"rva": 0x1030, "size": 1},
                    "candidate": {"rva": 0x1040, "size": 1},
                },
                {
                    "id": "alignment-padding",
                    "kind": "padding",
                    "original": {"rva": 0x1006, "size": 42},
                    "candidate": {"rva": 0x1006, "size": 58},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"
            stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )

            report = root / "report"
            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["status"], "prepared", result)
            candidates = json.loads(
                (report / "relational-indirect-call-targets.json").read_text(
                    encoding="utf-8"
                )
            )["candidates"]
            self.assertEqual(len(candidates), 1)
            self.assertEqual(
                candidates[0]["profile"],
                "immutable_relocated_function_pointer_jump_v1",
            )
            graph = json.loads(
                (report / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(graph["edges"][0]["kind"], "jump")
            self.assertEqual(graph["counts"]["declared_reachable_nodes"], 2)
            self.assertEqual(
                graph["counts"]["reachable_decoded_control_frontier_nodes"], 0
            )
            segment_summary = json.loads(
                (report / "relational-proof-ir.json").read_text(encoding="utf-8")
            )["segment_refinement_summary"]
            self.assertEqual(segment_summary["proved"], 1)
            self.assertEqual(segment_summary["incomplete"], 0)
            acceptance = json.loads(
                (report / "whole-program-acceptance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(acceptance["status"], "incomplete", acceptance)
            self.assertIsNone(acceptance["theorem"])
            self.assertIn(
                "launch_realizability_certificate_unsupported",
                {blocker["code"] for blocker in acceptance["blockers"]},
            )
            progress = json.loads(
                (report / "composition-progress.json").read_text(encoding="utf-8")
            )
            self.assertEqual(progress["frontiers"]["decoded_control_node_ids"], [])
            self.assertEqual(progress["frontiers"]["segment_edge_ids"], [])
            generated = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (report / "lean" / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                )
            )
            self.assertIn(
                "immutableIndirectJumpTargetsClosed_of_checked", generated
            )
            self.assertIn("ImmutableIndirectJumpTargetsClosed", generated)
            generated_segment = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (report / "lean" / "StageA").glob(
                    "RelationalSegmentRefinementChunk*.lean"
                )
            )
            self.assertIn(
                "productNode0ImmutableIndirectJumpClosed", generated_segment
            )
            checked = _run_lean_relational(
                report / "lean", bundle="RelationalBundle"
            )
            self.assertEqual(checked["status"], "checked", checked)

    def test_constant_guard_classifier_fails_closed(self):
        self.assertFalse(_semantic_constant_bool({
            "op": "not",
            "value": {
                "op": "equal",
                "left": {"op": "constant", "value": 0},
                "right": {"op": "constant", "value": 0},
            },
        }))
        self.assertIsNone(_semantic_constant_bool({
            "op": "not", "value": {"op": "input_flag", "index": 6},
        }))
        self.assertIsNone(_semantic_constant_bool({
            "op": "equal",
            "left": {"op": "read32", "address": {"op": "input_reg", "reg": "eax"}},
            "right": {"op": "constant", "value": 0},
        }))

    def test_iat_import_register_seeds_require_unique_matching_imports(self):
        def imported(symbol: str, thunk_rva: int):
            return SimpleNamespace(
                dll="kernel32.dll", symbol=symbol, ordinal=None,
                thunk_rva=thunk_rva,
            )

        original = SimpleNamespace(
            image_base=0x400000,
            imports=(imported("TlsGetValue", 0x2000),),
        )
        candidate = SimpleNamespace(
            image_base=0x500000,
            imports=(imported("TlsGetValue", 0x3000),),
        )
        behaviors = [{
            "original_ir": {"registers": {
                "ebp": {"op": "read32", "address": {
                    "op": "constant", "value": 0x402000,
                }},
            }},
            "candidate_ir": {"registers": {
                "edi": {"op": "read32", "address": {
                    "op": "constant", "value": 0x503000,
                }},
            }},
        }]

        seeds = _iat_import_register_seed_candidates(
            original, candidate, behaviors
        )
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["original_register"], "ebp")
        self.assertEqual(seeds[0]["candidate_register"], "edi")
        self.assertEqual(seeds[0]["import"]["symbol"], "TlsGetValue")

        duplicate = SimpleNamespace(
            image_base=0x400000,
            imports=(
                imported("TlsGetValue", 0x2000),
                imported("TlsGetValue", 0x2000),
            ),
        )
        self.assertEqual(
            _iat_import_register_seed_candidates(duplicate, candidate, behaviors),
            [],
        )
        mismatch = SimpleNamespace(
            image_base=0x500000,
            imports=(imported("GetLastError", 0x3000),),
        )
        self.assertEqual(
            _iat_import_register_seed_candidates(original, mismatch, behaviors),
            [],
        )

    def test_assembled_iat_import_seed_emits_complete_write_separations(self):
        def imported(thunk_rva: int):
            return SimpleNamespace(
                dll="msvcrt.dll", symbol="_errno", ordinal=None,
                thunk_rva=thunk_rva,
            )

        original = SimpleNamespace(
            image_base=0x400000, imports=(imported(0x2000),),
        )
        candidate = SimpleNamespace(
            image_base=0x500000, imports=(imported(0x3000),),
        )

        def assembled(base: int, register: str):
            write = {
                "write_address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": 1152},
                },
                "write_value": {"op": "constant", "value": 0},
            }

            def byte(offset: int, shift: int):
                read = {
                    "op": "read8_after_write",
                    "prior": {
                        "op": "read8",
                        "address": {"op": "constant", "value": base + offset},
                    },
                    **write,
                }
                return read if shift == 0 else {
                    "op": "shift_left", "value": read, "amount": shift,
                }

            return {
                "op": "bit_or",
                "left": {
                    "op": "bit_or", "left": byte(0, 0), "right": byte(1, 8),
                },
                "right": {
                    "op": "bit_or", "left": byte(2, 16), "right": byte(3, 24),
                },
            }

        behaviors = [{
            "original_ir": {"registers": {"ecx": assembled(0x402000, "esp")}},
            "candidate_ir": {"registers": {"ecx": assembled(0x503000, "esp")}},
        }]
        seeds = _iat_import_register_seed_candidates(original, candidate, behaviors)
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["profile"], "assembled_iat_register_seed_v1")
        self.assertTrue(seeds[0]["assembled_read"])
        self.assertEqual(len(seeds[0]["original_writes"]), 1)

        contract = {"regions": [{"address_separations": []}]}
        refined = _attach_import_seed_address_separations(contract, seeds)
        separations = refined["regions"][0]["address_separations"]
        self.assertEqual(len(separations), 16)
        self.assertEqual(
            {
                (row["original_offset"], row["original_address"])
                for row in separations
            },
            {
                (1152 + write_byte, 0x402000 + word_byte)
                for word_byte in range(4) for write_byte in range(4)
            },
        )

        incomplete = json.loads(json.dumps(seeds[0]))
        incomplete["candidate_writes"] = []
        unchanged = _attach_import_seed_address_separations(contract, [incomplete])
        self.assertEqual(unchanged, contract)
