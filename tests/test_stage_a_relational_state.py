from tests.stage_a_relational_support import *
from spaghetti_extractor.relational.analyses.memory import (
    _dynamic_flow_edge_candidates,
)
from spaghetti_extractor.relational.analyses.segments import (
    _paired_stack_relative_guard_claim,
)


class StageARelationalStateTests(StageARelationalTestBase):
    def test_dynamic_range_flow_does_not_cross_call_frames(self):
        relation = {
            "original": "eax", "candidate": "eax",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [],
        }
        contract = {
            "regions": [
                {
                    "inputs": [{"original": "eax", "candidate": "eax"}],
                    "input_dynamic_range_relations": [relation],
                },
                {
                    "inputs": [{"original": "eax", "candidate": "eax"}],
                },
            ],
            "static_dynamic_pointer_slots": [],
        }
        behaviors = [{
            "original_ir": {
                "registers": {"eax": {"op": "input_reg", "reg": "eax"}},
            },
            "candidate_ir": {
                "registers": {"eax": {"op": "input_reg", "reg": "eax"}},
            },
        }, {}]
        edge = {
            "source_region_index": 0,
            "target_region_index": 1,
            "kind": "call",
            "environment_barrier": False,
            "requires_call_stack_proof": False,
        }

        self.assertEqual(
            _dynamic_flow_edge_candidates(contract, behaviors, edge), []
        )
        edge["kind"] = "jump"
        self.assertEqual(
            _dynamic_flow_edge_candidates(contract, behaviors, edge),
            [{
                "relation": {**relation, "active_words": []},
                "kind": "register_preserve",
            }],
        )

    def test_prepared_writes_classify_mixed_stack_and_dynamic_fields(self):
        stack_window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 4,
            "bytes_above": 32,
            "source": "test",
        }
        dynamic_relation = {
            "original": "eax",
            "candidate": "eax",
            "original_offset": 0,
            "candidate_offset": 0,
            "required_words": [{"offset": 0, "kind": "relatedWord"}],
            "active_words": [{"offset": 0, "kind": "relatedWord"}],
        }
        value = {"op": "input_reg", "reg": "edx"}
        stack_address = {
            "op": "add",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 4},
        }
        behavior = {
            "original_ir": {"writes": [
                {"address": stack_address, "value": value},
                {"address": {"op": "input_reg", "reg": "eax"}, "value": value},
            ]},
            "candidate_ir": {"writes": [
                {"address": stack_address, "value": value},
                {"address": {"op": "input_reg", "reg": "eax"}, "value": value},
            ]},
        }
        source = {
            "input_relations": [{
                "original": "edx", "candidate": "edx", "relation": "exact",
            }],
            "stack_windows": [stack_window],
            "input_dynamic_range_relations": [dynamic_relation],
        }

        claim = _paired_prepared_word_writes_claim(source, behavior, [])

        self.assertIsNotNone(claim)
        self.assertEqual(
            [item["kind"] for item in claim["writes"]],
            ["stack", "dynamic_word"],
        )
        self.assertEqual(claim["writes"][1]["source_relation"], dynamic_relation)
        self.assertEqual(
            claim["writes"][1]["relation"],
            {"offset": 0, "kind": "relatedWord"},
        )

        ambiguous_source = {
            **source,
            "input_dynamic_range_relations": [dynamic_relation, dict(dynamic_relation)],
        }
        self.assertIsNone(
            _paired_prepared_word_writes_claim(ambiguous_source, behavior, [])
        )

        dynamic_base = {"op": "input_reg", "reg": "eax"}
        spill_behavior = {
            "original_ir": {"writes": [
                {"address": stack_address, "value": dynamic_base},
                {"address": dynamic_base, "value": value},
            ]},
            "candidate_ir": {"writes": [
                {"address": stack_address, "value": dynamic_base},
                {"address": dynamic_base, "value": value},
            ]},
        }
        spill_prepared = _paired_prepared_word_writes_claim(
            source, spill_behavior, [],
        )
        self.assertEqual(
            spill_prepared["writes"][0]["value"]["profile"],
            "dynamic_range_v1",
        )
        target_relation = {
            "window": stack_window,
            "stack_offset": 4,
            "original_offset": 0,
            "candidate_offset": 0,
            "required_words": [{"offset": 0, "kind": "relatedWord"}],
            "active_words": [{"offset": 0, "kind": "relatedWord"}],
        }
        spill = _prepared_dynamic_stack_spill_claim(
            source,
            {
                "stack_windows": [stack_window],
                "input_dynamic_stack_range_relations": [target_relation],
            },
            spill_prepared,
        )
        self.assertIsNotNone(spill)
        self.assertEqual(spill["source_relation"], dynamic_relation)
        self.assertEqual(spill["target_relation"], target_relation)
        self.assertEqual(
            [item["kind"] for item in spill["suffix"]], ["dynamic_word"],
        )

        second_stack_write = {
            **spill_prepared,
            "writes": [
                *spill_prepared["writes"], spill_prepared["writes"][0],
            ],
        }
        self.assertIsNone(
            _prepared_dynamic_stack_spill_claim(
                source,
                {"input_dynamic_stack_range_relations": [target_relation]},
                second_stack_write,
            )
        )

    def test_dynamic_range_transfer_recovers_a_checked_stack_spill(self):
        window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 0,
            "bytes_above": 8,
        }
        source_relation = {
            "window": window,
            "stack_offset": 4,
            "original_offset": 0,
            "candidate_offset": 0,
            "required_words": [{"offset": 0, "kind": "relatedWord"}],
            "active_words": [{"offset": 0, "kind": "relatedWord"}],
        }
        target_relation = {
            "original": "eax",
            "candidate": "eax",
            "original_offset": 0,
            "candidate_offset": 0,
            "required_words": [{"offset": 0, "kind": "relatedWord"}],
            "active_words": [{"offset": 0, "kind": "relatedWord"}],
        }
        read = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": 4},
            },
        }
        contract = {"regions": [
            {"input_dynamic_stack_range_relations": [source_relation]},
            {"input_dynamic_range_relations": [target_relation]},
        ]}
        behaviors = [{
            "original_ir": {"registers": {"eax": read}},
            "candidate_ir": {"registers": {"eax": read}},
        }]

        claims = _dynamic_range_transfer_claims(
            contract,
            behaviors,
            0,
            1,
            {"op": "bool_constant", "value": True},
            {"op": "bool_constant", "value": True},
        )

        self.assertEqual(claims, [{
            "kind": "stack_reload",
            "source_relation": source_relation,
            "target_relation": target_relation,
        }])

        ambiguous_contract = json.loads(json.dumps(contract))
        ambiguous_contract["regions"][0][
            "input_dynamic_stack_range_relations"
        ].append(dict(source_relation))
        self.assertIsNone(_dynamic_range_transfer_claims(
            ambiguous_contract,
            behaviors,
            0,
            1,
            {"op": "bool_constant", "value": True},
            {"op": "bool_constant", "value": True},
        ))

    def test_stack_windows_follow_checked_frame_pointer_renaming(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        source_window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 4,
            "bytes_above": 1,
            "source": "backward_identity_stack_window",
        }
        target_window = {
            **source_window,
            "original_register": "ebp",
            "candidate_register": "ebp",
            "source": "paired_memory_write_seed",
        }
        frame_pointer = {"op": "input_reg", "reg": "esp"}
        claims = _stack_window_transfer_claims(
            {"stack_windows": [source_window]},
            {"stack_windows": [target_window]},
            {
                "original_ir": {"registers": {"ebp": frame_pointer}},
                "candidate_ir": {"registers": {"ebp": frame_pointer}},
            },
        )
        self.assertEqual(claims, [{
            "source": source_window,
            "target": target_window,
            "adjustment": {"kind": "identity", "amount": 0},
        }])

        stack_write = {
            "address": {
                "op": "sub",
                "left": {"op": "input_reg", "reg": "ebp"},
                "right": {"op": "constant", "value": 4},
            },
            "value": {"op": "constant", "value": 1},
        }
        behaviors = [
            {
                "original_ir": {"registers": {"ebp": frame_pointer}, "writes": []},
                "candidate_ir": {"registers": {"ebp": frame_pointer}, "writes": []},
            },
            {
                "original_ir": {"registers": {}, "writes": [stack_write]},
                "candidate_ir": {"registers": {}, "writes": [stack_write]},
            },
        ]
        contract = {"regions": [
            {"id": "prologue", "address_separations": []},
            {"id": "frame-write", "address_separations": []},
        ]}
        relations = {
            "regions": [{}, {}],
            "edges": [{
                "source_region_index": 0,
                "target_region_index": 1,
                "environment_barrier": False,
            }],
        }
        refined, analysis = _attach_stack_window_invariants(
            contract, behaviors, relations, binary, binary
        )
        self.assertEqual(analysis["windows"], 2)
        self.assertEqual(
            refined["regions"][0]["stack_windows"][0]["original_register"],
            "esp",
        )
        self.assertEqual(
            refined["regions"][1]["stack_windows"][0]["original_register"],
            "ebp",
        )
        self.assertEqual(
            refined["regions"][1]["stack_windows"][0]["bytes_below"], 4
        )

    def test_stack_windows_reject_unanchored_general_register_accesses(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        pointer_write = {
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "eax"},
                "right": {"op": "constant", "value": 16},
            },
            "value": {"op": "constant", "value": 0},
        }
        refined, analysis = _attach_stack_window_invariants(
            {"regions": [{"id": "pointer-write", "address_separations": []}]},
            [{
                "original_ir": {"registers": {}, "writes": [pointer_write]},
                "candidate_ir": {"registers": {}, "writes": [pointer_write]},
            }],
            {"regions": [{}], "edges": []},
            binary,
            binary,
        )
        self.assertEqual(refined["regions"][0]["stack_windows"], [])
        self.assertEqual(analysis["unproven_stack_address_seeds"], 1)
        self.assertIn({
            "region_index": 0,
            "original_register": "eax",
            "candidate_register": "eax",
            "bytes_below": 0,
            "bytes_above": 20,
            "reason": "stack_anchor_provenance_unresolved",
        }, analysis["frontier"])

    def test_stack_read_seeds_follow_only_unique_output_register_mapping(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        stack_read = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": 4},
            },
        }
        behaviors = [{
            "original_ir": {"registers": {"eax": stack_read}},
            "candidate_ir": {"registers": {"ecx": stack_read}},
        }]
        contract = {"regions": [{
            "id": "mapped-read",
            "address_separations": [],
            "outputs": [{"original": "eax", "candidate": "ecx"}],
        }]}

        refined, analysis = _attach_stack_window_invariants(
            contract, behaviors, {"regions": [], "edges": []}, binary, binary
        )
        self.assertEqual(analysis["windows"], 1)
        self.assertEqual(
            refined["regions"][0]["stack_windows"][0]["source"],
            "paired_memory_read_seed",
        )

        ambiguous = json.loads(json.dumps(contract))
        ambiguous["regions"][0]["outputs"].append({
            "original": "edx", "candidate": "ecx",
        })
        refused, refused_analysis = _attach_stack_window_invariants(
            ambiguous, behaviors, {"regions": [], "edges": []}, binary, binary
        )
        self.assertEqual(refused_analysis["windows"], 0)
        self.assertEqual(refused["regions"][0]["stack_windows"], [])

    def test_stack_windows_propagate_identity_edges_and_fail_closed_at_frontier(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        separation = {
            "original_register": "esp", "candidate_register": "esp",
            "original_offset": 1155, "candidate_offset": 1155,
            "original_address": 0x402000, "candidate_address": 0x402000,
        }
        contract = {"regions": [
            {"id": "source", "address_separations": []},
            {"id": "middle", "address_separations": []},
            {"id": "sink", "address_separations": [separation]},
        ]}
        identity = {"op": "input_reg", "reg": "esp"}
        behaviors = [
            {
                "original_ir": {"registers": {"esp": identity}},
                "candidate_ir": {"registers": {"esp": identity}},
            }
            for _ in contract["regions"]
        ]
        edges = {"edges": [
            {"source_region_index": 0, "target_region_index": 1,
             "environment_barrier": False},
            {"source_region_index": 1, "target_region_index": 2,
             "environment_barrier": False},
        ]}
        refined, analysis = _attach_stack_window_invariants(
            contract, behaviors, edges, binary, binary
        )
        self.assertEqual(analysis["windows"], 3)
        self.assertEqual(analysis["separation_claims"], 1)
        self.assertEqual(
            [region["stack_windows"][0]["bytes_above"] for region in refined["regions"]],
            [1156, 1156, 1156],
        )
        self.assertEqual(analysis["frontier"], [{
            "region_index": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 0,
            "bytes_above": 1156,
            "reason": "no_checked_incoming_edge",
        }])

        affine = json.loads(json.dumps(behaviors))
        adjustment = {
            "op": "sub", "left": identity,
            "right": {"op": "constant", "value": 4},
        }
        affine[1]["original_ir"]["registers"]["esp"] = adjustment
        affine[1]["candidate_ir"]["registers"]["esp"] = adjustment
        adjusted, adjusted_analysis = _attach_stack_window_invariants(
            contract, affine, edges, binary, binary
        )
        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in adjusted["regions"]
        ], [(4, 1152), (4, 1152), (0, 1156)])
        self.assertEqual(adjusted_analysis["frontier"][0]["bytes_below"], 4)
        identity_claims = _stack_window_transfer_claims(
            adjusted["regions"][0], adjusted["regions"][1], affine[0]
        )
        self.assertEqual(identity_claims[0]["adjustment"]["kind"], "identity")
        affine_claims = _stack_window_transfer_claims(
            adjusted["regions"][1], adjusted["regions"][2], affine[1]
        )
        self.assertEqual(affine_claims[0]["adjustment"], {
            "kind": "subtract", "amount": 4,
        })

        relation_rows = {
            "regions": [
                {
                    "inputs": [{"original": "esp", "candidate": "esp",
                                "relation": "related_word"}],
                    "outputs": [{"original": "esp", "candidate": "esp",
                                 "relation": "related_word"}],
                    "exact_output_claims": [],
                    "output_claims": [{
                        "kind": "identity",
                        "input": {"original": "esp", "candidate": "esp",
                                  "relation": "related_word"},
                        "output": {"original": "esp", "candidate": "esp",
                                   "relation": "related_word"},
                    }],
                }
                for _ in adjusted["regions"]
            ],
            "edges": edges["edges"],
        }
        for region in adjusted["regions"]:
            region["input_relations"] = [{
                "original": "esp", "candidate": "esp", "relation": "related_word",
            }]
            region["output_relations"] = [{
                "original": "esp", "candidate": "esp", "relation": "related_word",
            }]
        lowered, lowered_rows = _lower_stack_register_relations(
            adjusted, relation_rows
        )
        self.assertEqual(lowered["regions"][1]["input_relations"], [])
        self.assertEqual(lowered_rows["regions"][1]["inputs"], [])
        self.assertEqual(lowered_rows["regions"][1]["outputs"], [])
        self.assertTrue(
            lowered_rows["regions"][1]["fully_supported_output_transfer"]
        )
        self.assertEqual(lowered_rows["regions"][2]["output_claims"], [])
        self.assertFalse(
            lowered_rows["regions"][2]["fully_supported_output_transfer"]
        )

        nonidentity = json.loads(json.dumps(behaviors))
        nonidentity[1]["candidate_ir"]["registers"]["esp"] = {
            "op": "sub", "left": identity,
            "right": {"op": "constant", "value": 4},
        }
        stopped, stopped_analysis = _attach_stack_window_invariants(
            contract, nonidentity, edges, binary, binary
        )
        self.assertEqual(stopped["regions"][0]["stack_windows"], [])
        self.assertEqual(
            stopped_analysis["frontier"][0]["reason"],
            "non_identity_or_environment_stack_transfer",
        )

        outside = json.loads(json.dumps(contract))
        outside["regions"][2]["address_separations"][0]["original_address"] = 0x500000
        ignored, ignored_analysis = _attach_stack_window_invariants(
            outside, behaviors, edges, binary, binary
        )
        self.assertEqual(ignored_analysis["windows"], 0)
        self.assertTrue(all(not region["stack_windows"] for region in ignored["regions"]))

    def test_stack_window_cycles_require_zero_net_stack_delta(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        identity = {"op": "input_reg", "reg": "esp"}

        def adjusted(operation: str, amount: int) -> dict[str, object]:
            return {
                "op": operation,
                "left": identity,
                "right": {"op": "constant", "value": amount},
            }

        def behavior(stack, *, seed=False):
            ir = {"registers": {"esp": stack}}
            if seed:
                ir["writes"] = [{
                    "address": identity,
                    "value": {"op": "constant", "value": 1},
                }]
            return {
                "original_ir": json.loads(json.dumps(ir)),
                "candidate_ir": json.loads(json.dumps(ir)),
            }

        contract = {"regions": [
            {"id": "first", "address_separations": []},
            {"id": "second", "address_separations": []},
        ]}
        edges = {"edges": [
            {"source_region_index": 0, "target_region_index": 1,
             "environment_barrier": False},
            {"source_region_index": 1, "target_region_index": 0,
             "environment_barrier": False},
        ]}

        zero_net, zero_net_analysis = _attach_stack_window_invariants(
            contract,
            [
                behavior(adjusted("sub", 4)),
                behavior(adjusted("add", 4), seed=True),
            ],
            edges, binary, binary,
        )
        self.assertEqual(zero_net_analysis["nonzero_stack_delta_cycle_nodes"], 0)
        self.assertNotIn(
            "nonzero_stack_delta_cycle_requires_relational_frame",
            {row["reason"] for row in zero_net_analysis["frontier"]},
        )
        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in zero_net["regions"]
        ], [(4, 1), (0, 5)])

        nonzero, nonzero_analysis = _attach_stack_window_invariants(
            contract,
            [behavior(adjusted("sub", 4)), behavior(identity, seed=True)],
            edges, binary, binary,
        )
        self.assertEqual(nonzero_analysis["nonzero_stack_delta_cycle_nodes"], 2)
        self.assertEqual(nonzero_analysis["requirement_updates"], 0)
        self.assertEqual(
            {row["reason"] for row in nonzero_analysis["frontier"]},
            {"nonzero_stack_delta_cycle_requires_relational_frame"},
        )
        self.assertEqual(nonzero["regions"][0]["stack_windows"], [])
        self.assertEqual(
            (nonzero["regions"][1]["stack_windows"][0]["bytes_below"],
             nonzero["regions"][1]["stack_windows"][0]["bytes_above"]),
            (0, 4),
        )

    def test_stack_window_seed_recovers_nested_negative_accesses(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        esp = {"op": "input_reg", "reg": "esp"}
        nested = {
            "op": "sub",
            "left": {
                "op": "add",
                "left": esp,
                "right": {"op": "constant", "value": 0xFFFFFFFC},
            },
            "right": {"op": "constant", "value": 24},
        }
        behavior = {
            "original_ir": {
                "registers": {"esp": esp},
                "writes": [{
                    "address": nested,
                    "value": {"op": "constant", "value": 7},
                }],
            },
            "candidate_ir": {
                "registers": {"esp": esp},
                "writes": [{
                    "address": nested,
                    "value": {"op": "constant", "value": 7},
                }],
            },
        }
        refined, analysis = _attach_stack_window_invariants(
            {"regions": [{"id": "negative-write", "address_separations": []}]},
            [behavior], {"edges": []}, binary, binary,
        )
        self.assertEqual(analysis["windows"], 1)
        self.assertEqual(
            refined["regions"][0]["stack_windows"][0],
            {
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 28,
                "bytes_above": 1,
                "source": "paired_memory_write_seed",
            },
        )
        self.assertEqual(
            analysis["frontier"],
            [{
                "region_index": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 28,
                "bytes_above": 1,
                "reason": "no_checked_incoming_edge",
            }],
        )
        transfer_behavior = json.loads(json.dumps(behavior))
        transfer_behavior["original_ir"]["registers"]["esp"] = nested
        transfer_behavior["candidate_ir"]["registers"]["esp"] = nested
        transfer = _stack_window_transfer_claims(
            refined["regions"][0],
            {"stack_windows": [{
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 0,
                "bytes_above": 29,
            }]},
            transfer_behavior,
        )
        self.assertEqual(transfer[0]["adjustment"], {
            "kind": "subtract", "amount": 28,
        })

    def test_stack_windows_propagate_across_machine_call_stack_cleanup(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        imported = {
            "dll": list(b"kernel32.dll"),
            "name": {"op": "symbol", "bytes": list(b"EnterCriticalSection")},
        }
        identity = {"op": "input_reg", "reg": "esp"}

        def subtract(amount):
            return {
                "op": "sub", "left": identity,
                "right": {"op": "constant", "value": amount},
            }

        contract = {
            "machine_import_call_contracts": [{
                "id": 0,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "stack_argument_offsets": [0],
                "stack_result_delta": 4,
            }],
            "regions": [
                {"id": "call", "numeric_id": 0, "address_separations": [],
                 "output_relations": []},
                {"id": "continuation", "numeric_id": 1,
                 "address_separations": []},
                {"id": "sink", "numeric_id": 2,
                 "address_separations": []},
            ],
        }
        call_outcome = {
            "op": "external_call",
            "import": imported,
            "arguments": [{"op": "constant", "value": 1}],
        }
        behaviors = [
            {
                "original_ir": {
                    "registers": {"esp": subtract(28)},
                    "outcome": call_outcome,
                },
                "candidate_ir": {
                    "registers": {"esp": subtract(28)},
                    "outcome": call_outcome,
                },
            },
            {
                "original_ir": {"registers": {"esp": subtract(4)}},
                "candidate_ir": {"registers": {"esp": subtract(4)}},
            },
            {
                "original_ir": {
                    "registers": {"esp": identity},
                    "writes": [{
                        "address": {"op": "add", "left": identity,
                                    "right": {"op": "constant", "value": 0}},
                        "value": {"op": "constant", "value": 1},
                    }],
                },
                "candidate_ir": {
                    "registers": {"esp": identity},
                    "writes": [{
                        "address": {"op": "add", "left": identity,
                                    "right": {"op": "constant", "value": 0}},
                        "value": {"op": "constant", "value": 1},
                    }],
                },
            },
        ]
        unconditional = {"op": "bool_constant", "value": True}
        edges = {
            "regions": [{"output_claims": []}, {}, {}],
            "edges": [
            {"source_region_index": 0, "target_region_index": 1,
             "environment_barrier": True,
             "original_guard": unconditional,
             "candidate_guard": unconditional},
            {"source_region_index": 1, "target_region_index": 2,
             "environment_barrier": False},
        ]}

        refined, analysis = _attach_stack_window_invariants(
            contract, behaviors, edges, binary, binary
        )

        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in refined["regions"]
        ], [(28, 1), (4, 1), (0, 4)])
        self.assertNotIn(
            "unsupported_environment_stack_transfer",
            {item["reason"] for item in analysis["frontier"]},
        )
        sites = _external_call_site_candidates(
            refined, behaviors, edges
        )
        self.assertEqual(sites["counts"], {"candidates": 1, "gaps": 0})
        self.assertEqual(
            sites["candidates"][0]["boundary_invariant"]["stack_windows"][0]
            ["bytes_below"],
            0,
        )
        self.assertEqual(
            sites["candidates"][0]["boundary_invariant"]["stack_windows"][0]
            ["bytes_above"],
            29,
        )
        self.assertEqual(
            sites["candidates"][0]["stack_transfer_claims"][0]["adjustment"],
            {"kind": "subtract", "amount": 28},
        )
        self.assertEqual(
            sites["candidates"][0]["proof_profile"],
            "paired_constant_arguments_external_call_v1",
        )
        attached = _attach_external_call_site_analysis(
            {"obligations": [], "families": []}, sites
        )
        self.assertEqual(
            attached["external_call_summary"], {"candidates": 1, "gaps": 0}
        )
        self.assertEqual(
            attached["obligations"][0]["status"], "pending_lean"
        )
        self.assertEqual(
            attached["obligations"][0]["edge_id"], 0
        )

        unresolved = json.loads(json.dumps(behaviors))
        unresolved_argument = {"op": "input_reg", "reg": "esp"}
        unresolved[0]["original_ir"]["outcome"]["arguments"] = [
            unresolved_argument
        ]
        unresolved[0]["candidate_ir"]["outcome"]["arguments"] = [
            unresolved_argument
        ]
        incomplete = _external_call_site_candidates(
            refined, unresolved, edges
        )
        self.assertEqual(incomplete["counts"], {"candidates": 0, "gaps": 1})
        self.assertEqual(
            incomplete["gaps"][0]["reason"],
            "external argument 0 lacks one unambiguous source register relation",
        )
        incomplete_attached = _attach_external_call_site_analysis(
            {"obligations": [], "families": []}, incomplete
        )
        self.assertEqual(
            incomplete_attached["obligations"][0]["status"], "incomplete"
        )
        self.assertIn(
            "argument expressions related",
            incomplete_attached["obligations"][0]["next_action"],
        )

        uncontracted = json.loads(json.dumps(refined))
        uncontracted["machine_import_call_contracts"] = []
        missing_contract = _external_call_site_candidates(
            uncontracted, behaviors, edges
        )
        self.assertEqual(missing_contract["counts"], {"candidates": 0, "gaps": 1})
        self.assertEqual(missing_contract["gaps"][0]["original_import"], {
            "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
        })
        missing_attached = _attach_external_call_site_analysis(
            {"obligations": [], "families": []}, missing_contract
        )
        self.assertIn(
            "kernel32.dll!EnterCriticalSection",
            missing_attached["obligations"][0]["next_action"],
        )
        self.assertIn(
            "explicitly declare memory and world effects",
            missing_attached["obligations"][0]["next_action"],
        )

    def test_stack_windows_cross_import_thunk_only_with_machine_contract(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        identity = {"op": "input_reg", "reg": "esp"}
        pushed = {
            "op": "add",
            "left": identity,
            "right": {"op": "constant", "value": 2**32 - 16},
        }
        imported = {
            "dll": list(b"msvcrt.dll"),
            "name": {"op": "symbol", "bytes": list(b"opaque_leaf")},
        }
        contract = {
            "machine_import_call_contracts": [{
                "id": 0,
                "import": {"dll": "msvcrt.dll", "symbol": "opaque_leaf"},
                "stack_argument_offsets": [0, 4],
                "stack_result_delta": 0,
            }],
            "regions": [
                {"id": "caller", "numeric_id": 0, "address_separations": []},
                {"id": "continuation", "numeric_id": 1,
                 "address_separations": []},
                {"id": "import-thunk", "numeric_id": 2,
                 "address_separations": []},
            ],
        }
        behaviors = [
            {
                "original_ir": {
                    "registers": {"esp": pushed},
                    "outcome": {"op": "call", "target": 2, "continuation": 1},
                },
                "candidate_ir": {
                    "registers": {"esp": pushed},
                    "outcome": {"op": "call", "target": 2, "continuation": 1},
                },
            },
            {
                "original_ir": {
                    "registers": {"esp": identity},
                    "writes": [{
                        "address": identity,
                        "value": {"op": "constant", "value": 1},
                    }],
                },
                "candidate_ir": {
                    "registers": {"esp": identity},
                    "writes": [{
                        "address": identity,
                        "value": {"op": "constant", "value": 1},
                    }],
                },
            },
            {
                "original_ir": {
                    "registers": {"esp": identity},
                    "outcome": {"op": "external_jump", "import": imported},
                },
                "candidate_ir": {
                    "registers": {"esp": identity},
                    "outcome": {"op": "external_jump", "import": imported},
                },
            },
        ]
        call_edge = {
            "source_region_index": 0,
            "target_region_index": 2,
            "environment_barrier": False,
            "direct_call_push_claim": {"profile": "mapped_direct_call_push_v1"},
        }
        register_relations = {
            "edges": [call_edge],
            "return_slot_analysis": {
                "call_summary_analysis": {"summaries": []},
            },
        }

        refined, analysis = _attach_stack_window_invariants(
            contract, behaviors, register_relations, binary, binary
        )

        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in refined["regions"]
        ], [(16, 1), (0, 4), (0, 12)])
        self.assertIn(
            "import_thunk_boundary_seed",
            refined["regions"][2]["stack_windows"][0]["source"],
        )
        self.assertIn(
            "import_thunk_return_slot_seed",
            refined["regions"][2]["stack_windows"][0]["source"],
        )
        self.assertNotIn(
            "direct_call_window_requires_return_summary",
            {row["reason"] for row in analysis["frontier"]},
        )

        indirect_behaviors = json.loads(json.dumps(behaviors))
        indirect_outcome = {
            "op": "indirect_call",
            "target": {"op": "constant", "value": 0x401000},
            "continuation": 1,
        }
        indirect_behaviors[0]["original_ir"]["outcome"] = indirect_outcome
        indirect_behaviors[0]["candidate_ir"]["outcome"] = indirect_outcome
        indirect_relations = {
            "edges": [{
                "source_region_index": 0,
                "target_region_index": 2,
                "environment_barrier": False,
                "indirect_target_profile":
                    "fixed_static_function_pointer_call_v1",
                "indirect_target_claim": {"target_id": 2},
                "indirect_call_push_claim": {
                    "profile": "mapped_indirect_call_push_v1",
                    "continuation_target_id": 1,
                },
            }],
            "return_slot_analysis": {
                "call_summary_analysis": {"summaries": []},
            },
        }
        indirect_refined, indirect_analysis = _attach_stack_window_invariants(
            contract, indirect_behaviors, indirect_relations, binary, binary
        )
        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in indirect_refined["regions"]
        ], [(16, 1), (0, 4), (0, 12)])
        self.assertNotIn(
            "direct_call_window_requires_return_summary",
            {row["reason"] for row in indirect_analysis["frontier"]},
        )

        uncontracted = json.loads(json.dumps(contract))
        uncontracted["machine_import_call_contracts"] = []
        stopped, stopped_analysis = _attach_stack_window_invariants(
            uncontracted, behaviors, register_relations, binary, binary
        )
        self.assertEqual(stopped["regions"][0]["stack_windows"], [])
        self.assertIn(
            "direct_call_window_requires_return_summary",
            {row["reason"] for row in stopped_analysis["frontier"]},
        )

    def test_direct_import_thunk_sites_are_continuation_specific_and_fail_closed(self):
        stack = {"op": "input_reg", "reg": "esp"}
        argument = {
            "op": "read32",
            "address": {
                "op": "add", "left": stack,
                "right": {"op": "constant", "value": 4},
            },
        }
        imported = {
            "dll": list(b"kernel32.dll"),
            "name": {"op": "symbol", "bytes": list(b"GetLastError")},
        }
        relations = [
            {"original": register, "candidate": register,
             "relation": "related_word"}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        ]
        contract = {
            "machine_import_call_contracts": [{
                "id": 7,
                "import": {"dll": "kernel32.dll", "symbol": "GetLastError"},
                "stack_argument_offsets": [0],
                "stack_result_delta": 0,
                "preserved_registers": ["ebx", "esi", "edi", "ebp"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "memory_effect": "none",
                "world_effect": "none",
            }],
            "regions": [
                {"id": "caller", "numeric_id": 0},
                {"id": "continuation", "numeric_id": 1},
                {
                    "id": "import-thunk", "numeric_id": 2,
                    "input_relations": relations,
                    "input_import_relations": [],
                    "input_dynamic_range_relations": [],
                    "bounds": [], "address_separations": [], "flag_inputs": [],
                    "stack_windows": [{
                        "range_id": 0,
                        "original_register": "esp",
                        "candidate_register": "esp",
                        "bytes_below": 0,
                        "bytes_above": 12,
                    }],
                },
            ],
        }
        caller = {
            "registers": {"esp": stack},
            "writes": [],
            "outcome": {"op": "call", "target": 2, "continuation": 1},
        }
        thunk = {
            "registers": {
                register: {"op": "input_reg", "reg": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            },
            "writes": [], "x87": {}, "flags": {},
            "outcome": {
                "op": "external_jump", "import": imported,
                "arguments": [argument],
            },
        }
        behaviors = [
            {"original_ir": caller, "candidate_ir": caller},
            {"original_ir": {}, "candidate_ir": {}},
            {"original_ir": thunk, "candidate_ir": thunk},
        ]
        output_claims = [
            {"kind": "identity", "input": relation, "output": relation}
            for relation in relations
        ]
        register_relations = {
            "edges": [{
                "source_region_index": 0,
                "target_region_index": 2,
                "direct_call_push_claim": {
                    "profile": "mapped_direct_call_push_v1",
                },
            }],
            "regions": [{}, {}, {"output_claims": output_claims}],
        }

        analysis = _direct_import_thunk_call_candidates(
            contract, behaviors, register_relations, first_site_id=10
        )
        self.assertEqual(len(analysis["candidates"]), 1)
        self.assertEqual(analysis["gaps"], [])
        site = analysis["candidates"][0]
        self.assertEqual(
            (site["id"], site["source_target_id"], site["continuation_target_id"]),
            (10, 2, 1),
        )
        self.assertEqual(
            site["argument_relation_claims"][0]["kind"], "stack_word_read"
        )
        self.assertEqual(
            site["boundary_invariant"]["stack_windows"][0]["bytes_below"], 4
        )
        self.assertEqual(
            site["boundary_invariant"]["stack_windows"][0]["bytes_above"], 8
        )

        tail_contract = json.loads(json.dumps(contract))
        tail_contract["regions"] = [
            tail_contract["regions"][0],
            tail_contract["regions"][1],
            {"id": "tail-wrapper", "numeric_id": 2},
            {**tail_contract["regions"][2], "numeric_id": 3},
        ]
        tail_caller = json.loads(json.dumps(caller))
        tail_caller["outcome"]["target"] = 2
        tail_wrapper = {
            "registers": {
                register: {"op": "input_reg", "reg": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            },
            "writes": [], "x87": {}, "flags": {},
            "outcome": {"op": "jump", "target": 3},
        }
        tail_behaviors = [
            {"original_ir": tail_caller, "candidate_ir": tail_caller},
            {"original_ir": {}, "candidate_ir": {}},
            {"original_ir": tail_wrapper, "candidate_ir": tail_wrapper},
            {"original_ir": thunk, "candidate_ir": thunk},
        ]
        tail_jump_edge = {
            "source_region_index": 2,
            "target_region_index": 3,
            "direct_call_push_claim": None,
            "kind": "jump",
            "environment_barrier": False,
            "original_guard": {"op": "bool_constant", "value": True},
            "candidate_guard": {"op": "bool_constant", "value": True},
            "relation_preservation_proposed": True,
        }
        tail_register_relations = {
            "edges": [
                {
                    "source_region_index": 0,
                    "target_region_index": 2,
                    "direct_call_push_claim": {
                        "profile": "mapped_direct_call_push_v1",
                    },
                },
                tail_jump_edge,
            ],
            "regions": [{}, {}, {}, {"output_claims": output_claims}],
        }
        tail_analysis = _direct_import_thunk_call_candidates(
            tail_contract, tail_behaviors, tail_register_relations,
            first_site_id=20,
        )
        self.assertEqual(tail_analysis["gaps"], [])
        self.assertEqual(len(tail_analysis["candidates"]), 1)
        tail_site = tail_analysis["candidates"][0]
        self.assertEqual(tail_site["source_region_index"], 3)
        self.assertEqual(tail_site["call_target_region_index"], 2)
        self.assertEqual(tail_site["tail_jump_region_indices"], [2])
        self.assertEqual(tail_site["tail_jump_edge_indices"], [1])

        ambiguous_tail_relations = json.loads(json.dumps(tail_register_relations))
        ambiguous_tail_relations["edges"].append(
            json.loads(json.dumps(tail_jump_edge))
        )
        ambiguous_tail = _direct_import_thunk_call_candidates(
            tail_contract, tail_behaviors, ambiguous_tail_relations,
            first_site_id=20,
        )
        self.assertEqual(ambiguous_tail["candidates"], [])
        self.assertIn(
            "lacks one unambiguous local edge",
            ambiguous_tail["gaps"][0]["reason"],
        )

        missing_contract = json.loads(json.dumps(contract))
        missing_contract["machine_import_call_contracts"] = []
        incomplete = _direct_import_thunk_call_candidates(
            missing_contract, behaviors, register_relations, first_site_id=10
        )
        self.assertEqual(incomplete["candidates"], [])
        self.assertIn("no unique machine import call contract", incomplete["gaps"][0]["reason"])

        mismatched = json.loads(json.dumps(behaviors))
        mismatched[2]["candidate_ir"]["outcome"]["import"]["name"]["bytes"] = list(
            b"SetLastError"
        )
        identity_gap = _direct_import_thunk_call_candidates(
            contract, mismatched, register_relations, first_site_id=10
        )
        self.assertEqual(identity_gap["candidates"], [])
        self.assertIn("identities do not match", identity_gap["gaps"][0]["reason"])

        differing_arguments = json.loads(json.dumps(behaviors))
        differing_arguments[2]["candidate_ir"]["outcome"]["arguments"][0][
            "address"
        ]["right"]["value"] = 8
        argument_gap = _direct_import_thunk_call_candidates(
            contract, differing_arguments, register_relations, first_site_id=10
        )
        self.assertEqual(argument_gap["candidates"], [])
        self.assertIn("arguments differ", argument_gap["gaps"][0]["reason"])

        unmapped_continuation = json.loads(json.dumps(behaviors))
        for side in ("original_ir", "candidate_ir"):
            unmapped_continuation[0][side]["outcome"]["continuation"] = 99
        continuation_gap = _direct_import_thunk_call_candidates(
            contract, unmapped_continuation, register_relations, first_site_id=10
        )
        self.assertEqual(continuation_gap["candidates"], [])
        self.assertIn(
            "continuation is not mapped", continuation_gap["gaps"][0]["reason"]
        )

        ambiguous_abi = json.loads(json.dumps(contract))
        ambiguous_abi["machine_import_call_contracts"].append(
            json.loads(json.dumps(ambiguous_abi["machine_import_call_contracts"][0]))
        )
        ambiguous_abi["machine_import_call_contracts"][1]["id"] = 8
        abi_gap = _direct_import_thunk_call_candidates(
            ambiguous_abi, behaviors, register_relations, first_site_id=10
        )
        self.assertEqual(abi_gap["candidates"], [])
        self.assertIn("no unique machine import call contract", abi_gap["gaps"][0]["reason"])

    def test_register_import_call_is_externalized_only_with_checked_target(self):
        stack = {"op": "input_reg", "reg": "esp"}
        pushed_stack = {
            "op": "add", "left": stack,
            "right": {"op": "constant", "value": 2**32 - 4},
        }
        behavior = {
            "registers": {
                "esp": pushed_stack,
                "ebp": {"op": "input_reg", "reg": "ebp"},
                "ebx": {"op": "input_reg", "reg": "ebx"},
                "edi": {"op": "input_reg", "reg": "edi"},
                "esi": {"op": "input_reg", "reg": "esi"},
            },
            "writes": [
                {"address": stack, "value": {"op": "constant", "value": 7}},
                {"address": pushed_stack,
                 "value": {"op": "constant", "value": 0x401234}},
            ],
            "outcome": {
                "op": "indirect_call",
                "target": {"op": "input_reg", "reg": "ebp"},
                "continuation": 1,
            },
            "x87": {},
        }
        contract = {
            "machine_import_call_contracts": [{
                "id": 4,
                "import": {"dll": "kernel32.dll", "symbol": "TlsGetValue"},
                "stack_argument_offsets": [0],
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            }],
            "regions": [
                {
                    "id": "call", "numeric_id": 0,
                    "input_relations": [
                        {"original": register, "candidate": register,
                         "relation": "related_word"}
                        for register in ("ebx", "edi", "esi")
                    ],
                    "input_import_relations": [{
                        "original": "ebp", "candidate": "ebp",
                        "import": {
                            "dll": "kernel32.dll", "symbol": "TlsGetValue",
                        },
                    }],
                    "output_relations": [], "output_import_relations": [],
                    "output_dynamic_range_relations": [], "flag_outputs": [],
                },
                {"id": "continuation", "numeric_id": 1},
            ],
        }
        relations = {
            "regions": [{"output_claims": [
                {
                    "kind": "identity",
                    "input": {"original": register, "candidate": register,
                              "relation": "related_word"},
                    "output": {"original": register, "candidate": register,
                               "relation": "related_word"},
                }
                for register in ("ebx", "edi", "esi")
            ]}, {}],
            "edges": [{
                "source_region_index": 0,
                "target_region_index": 1,
                "environment_barrier": True,
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
            }],
        }
        call = {
            "profile": "inductive_iat_register_call_v1",
            "source_region_index": 0,
            "continuation_region_index": 1,
            "original_register": "ebp",
            "candidate_register": "ebp",
            "import": {"dll": "kernel32.dll", "symbol": "TlsGetValue"},
        }
        analysis = _external_call_site_candidates(
            contract,
            [{"original_ir": behavior, "candidate_ir": behavior}],
            relations,
            [call],
        )
        self.assertEqual(analysis["counts"], {"candidates": 1, "gaps": 0})
        self.assertEqual(
            analysis["candidates"][0]["dispatch_profile"],
            "checked_import_register",
        )
        self.assertEqual(
            analysis["candidates"][0]["dispatch_registers"],
            {"original": "ebp", "candidate": "ebp"},
        )
        self.assertEqual(analysis["candidates"][0]["argument_values"], [7])

        multi_contract = json.loads(json.dumps(contract))
        multi_contract["machine_import_call_contracts"][0][
            "stack_argument_offsets"
        ] = [0, 4]
        multi_contract["regions"][0]["stack_windows"] = [{
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 4,
            "bytes_above": 8,
        }]
        multi = _external_call_site_candidates(
            multi_contract,
            [{"original_ir": behavior, "candidate_ir": behavior}],
            relations,
            [call],
        )
        self.assertEqual(multi["counts"], {"candidates": 1, "gaps": 0})
        self.assertEqual(
            [
                claim["kind"]
                for claim in multi["candidates"][0]["argument_relation_claims"]
            ],
            ["self", "stack_word_read"],
        )
        self.assertEqual(
            multi["candidates"][0]["argument_values"], [7, None]
        )

        overlapping_behavior = json.loads(json.dumps(behavior))
        overlapping_behavior["writes"].insert(1, {
            "address": {
                "op": "add",
                "left": stack,
                "right": {"op": "constant", "value": 5},
            },
            "value": {"op": "constant", "value": 9},
        })
        overlapping = _external_call_site_candidates(
            multi_contract,
            [{
                "original_ir": overlapping_behavior,
                "candidate_ir": overlapping_behavior,
            }],
            relations,
            [call],
        )
        self.assertEqual(overlapping["counts"], {"candidates": 0, "gaps": 1})
        self.assertIn("stack-argument shape", overlapping["gaps"][0]["reason"])

        missing_window_contract = json.loads(json.dumps(multi_contract))
        missing_window_contract["regions"][0].pop("stack_windows")
        missing_window = _external_call_site_candidates(
            missing_window_contract,
            [{"original_ir": behavior, "candidate_ir": behavior}],
            relations,
            [call],
        )
        self.assertEqual(missing_window["counts"], {"candidates": 0, "gaps": 1})
        self.assertIn(
            "source dynamic-range relation",
            missing_window["gaps"][0]["reason"],
        )

        missing_target = _external_call_site_candidates(
            contract,
            [{"original_ir": behavior, "candidate_ir": behavior}],
            relations,
            [],
        )
        self.assertEqual(missing_target["counts"], {"candidates": 0, "gaps": 1})
        self.assertIn("unambiguous checked import-register target",
                      missing_target["gaps"][0]["reason"])

    def test_register_import_call_seeds_full_abi_argument_stack_span(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        stack = {"op": "input_reg", "reg": "esp"}
        pushed_stack = {
            "op": "add", "left": stack,
            "right": {"op": "constant", "value": 2**32 - 4},
        }
        imported = {"dll": "kernel32.dll", "symbol": "VirtualProtect"}
        behavior = {
            "registers": {
                "esp": pushed_stack,
                "ebx": {"op": "input_reg", "reg": "ebx"},
            },
            "writes": [{
                "address": pushed_stack,
                "value": {"op": "constant", "value": 0x401234},
            }],
            "outcome": {
                "op": "indirect_call",
                "target": {"op": "input_reg", "reg": "ebx"},
                "continuation": 1,
            },
        }
        contract = {
            "machine_import_call_contracts": [{
                "import": imported,
                "stack_argument_offsets": [0, 4, 8, 12],
            }],
            "regions": [
                {
                    "id": "call",
                    "address_separations": [],
                    "input_import_relations": [{
                        "original": "ebx", "candidate": "ebx",
                        "import": imported,
                    }],
                },
                {
                    "id": "unrelated-trailing-region",
                    "address_separations": [],
                    "input_import_relations": [],
                },
            ],
        }
        refined, analysis = _attach_stack_window_invariants(
            contract,
            [{"original_ir": behavior, "candidate_ir": behavior}],
            {"edges": []},
            binary,
            binary,
        )
        self.assertEqual(analysis["windows"], 1)
        self.assertEqual(
            refined["regions"][0]["stack_windows"][0],
            {
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 4,
                "bytes_above": 16,
                "source": (
                    "paired_memory_write_seed+register_import_argument_seed"
                ),
            },
        )

    def test_iat_read_classification_fails_closed(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            imports=[SimpleNamespace(
                thunk_rva=0x2000,
                dll="kernel32.dll",
                symbol="TlsGetValue",
                ordinal=None,
            )],
        )

        exact = _iat_read_classification(binary, {
            "constant_address": 0x402000, "width": 4,
        })
        self.assertEqual(exact, {
            "status": "exact_iat_cell",
            "proof_role": "requires_import_address_pair_witness",
            "iat_rva": 0x2000,
            "import": {"dll": "kernel32.dll", "symbol": "TlsGetValue"},
        })
        self.assertEqual(
            _iat_read_classification(binary, {
                "constant_address": 0x401000, "width": 4,
            })["status"],
            "statically_outside_iat",
        )
        self.assertEqual(
            _iat_read_classification(binary, {
                "constant_address": 0x402001, "width": 1,
            })["status"],
            "partial_iat_overlap_unsupported",
        )
        self.assertEqual(
            _iat_read_classification(binary, {
                "constant_address": None, "width": 4,
            })["status"],
            "dynamic_address_requires_non_iat_proof",
        )

        def byte(offset, shift):
            read = {
                "op": "read8",
                "address": {"op": "constant", "value": 0x402000 + offset},
            }
            return read if shift == 0 else {
                "op": "shift_left", "value": read, "amount": shift,
            }

        assembled = {
            "op": "bit_or",
            "left": {
                "op": "bit_or", "left": byte(0, 0), "right": byte(1, 8),
            },
            "right": {
                "op": "bit_or", "left": byte(2, 16), "right": byte(3, 24),
            },
        }
        self.assertEqual(
            _assembled_iat_read_candidates(binary, {
                "registers": {"ecx": assembled},
            })[0]["status"],
            "exact_iat_cell",
        )

    def test_assembled_iat_write_separation_is_a_first_class_obligation(self):
        candidate = {
            "register": "ecx",
            "iat_rva": 0x2000,
            "import": {"dll": "msvcrt.dll", "symbol": "_errno"},
            "intervening_register_writes": 1,
            "status": "requires_intervening_write_separation",
            "next_action": "prove separation",
        }
        attached = _attach_import_register_analysis(
            {"obligations": [], "families": [], "status": "incomplete"},
            [],
            {
                "counts": {"seeds": 0, "relations": 0, "indirect_import_calls": 0},
                "relations": [],
                "indirect_import_calls": [],
            },
            [],
            {"regions": [{
                "index": 7,
                "id": "assembled-iat",
                "assembled_iat_read_candidates": {
                    "original": [candidate], "candidate": [candidate],
                },
            }]},
        )

        obligation = next(
            item for item in attached["obligations"]
            if item["kind"] == "assembled_iat_register_seed"
        )
        self.assertEqual(obligation["region_index"], 7)
        self.assertEqual(obligation["register"], "ecx")
        self.assertEqual(obligation["status"], "incomplete")

    def test_import_register_inference_requires_inductive_abi_preservation(self):
        imported = {"dll": "kernel32.dll", "symbol": "TlsGetValue"}

        def identity_registers():
            return {
                register: {"op": "input_reg", "reg": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            }

        contract = {"regions": [
            {"numeric_id": 0}, {"numeric_id": 1}, {"numeric_id": 2},
        ]}
        behaviors = [
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "ebp"},
                        "continuation": 2,
                    },
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "edi"},
                        "continuation": 2,
                    },
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
            },
        ]
        seeds = [{
            "region_index": 0,
            "original_register": "ebp",
            "candidate_register": "edi",
            "import": imported,
        }]
        analysis = _infer_import_register_invariants(contract, behaviors, seeds)
        self.assertEqual(analysis["counts"]["indirect_import_calls"], 1, analysis)
        self.assertEqual(
            {row["region_index"] for row in analysis["relations"]}, {1, 2}
        )

        volatile_seeds = [{
            "region_index": 0,
            "original_register": "eax",
            "candidate_register": "eax",
            "import": imported,
        }]
        volatile_behaviors = json.loads(json.dumps(behaviors))
        for side in ("original_ir", "candidate_ir"):
            volatile_behaviors[1][side]["outcome"]["target"]["reg"] = "eax"
        volatile = _infer_import_register_invariants(
            contract, volatile_behaviors, volatile_seeds
        )
        self.assertEqual(volatile["relations"], [], volatile)
        self.assertEqual(volatile["indirect_import_calls"], [], volatile)

    def test_import_register_inference_tracks_paired_register_renames(self):
        imported = {
            "dll": "kernel32.dll",
            "symbol": "WideCharToMultiByte",
        }

        def identity_registers():
            return {
                register: {"op": "input_reg", "reg": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            }

        contract = {
            "regions": [
                {"numeric_id": region_index}
                for region_index in range(4)
            ],
        }
        renamed_original = identity_registers()
        renamed_candidate = identity_registers()
        renamed_original["ebx"] = {"op": "input_reg", "reg": "ebp"}
        renamed_candidate["esi"] = {"op": "input_reg", "reg": "edi"}
        renamed_original["ebp"] = {"op": "constant", "value": 0}
        renamed_candidate["edi"] = {"op": "constant", "value": 0}
        behaviors = [
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
            },
            {
                "original_ir": {
                    "registers": renamed_original,
                    "outcome": {"op": "jump", "target": 2},
                },
                "candidate_ir": {
                    "registers": renamed_candidate,
                    "outcome": {"op": "jump", "target": 2},
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "ebx"},
                        "continuation": 3,
                    },
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "esi"},
                        "continuation": 3,
                    },
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "returned"},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "returned"},
                },
            },
        ]
        analysis = _infer_import_register_invariants(
            contract,
            behaviors,
            [{
                "region_index": 0,
                "original_register": "ebp",
                "candidate_register": "edi",
                "import": imported,
            }],
        )

        relation_keys = {
            (
                row["region_index"],
                row["original_register"],
                row["candidate_register"],
            )
            for row in analysis["relations"]
        }
        self.assertIn((1, "ebp", "edi"), relation_keys)
        self.assertIn((2, "ebx", "esi"), relation_keys)
        self.assertIn((3, "ebx", "esi"), relation_keys)
        self.assertEqual(
            analysis["indirect_import_calls"],
            [{
                "profile": "inductive_iat_register_call_v1",
                "source_region_index": 2,
                "continuation_region_index": 3,
                "original_register": "ebx",
                "candidate_register": "esi",
                "import": imported,
            }],
        )

    def test_import_register_inference_composes_checked_internal_returns(self):
        imported = {"dll": "kernel32.dll", "symbol": "GetTickCount"}

        def identity_registers():
            return {
                register: {"op": "input_reg", "reg": register}
                for register in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            }

        contract = {"regions": [
            {"numeric_id": 0}, {"numeric_id": 1},
            {"numeric_id": 2}, {"numeric_id": 3},
        ]}
        behaviors = [
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "returned"},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "returned"},
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "esi"},
                        "continuation": 3,
                    },
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "esi"},
                        "continuation": 3,
                    },
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "returned"},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "returned"},
                },
            },
        ]
        seeds = [{
            "region_index": 0,
            "original_register": "esi",
            "candidate_register": "esi",
            "import": imported,
        }]

        without_return = _infer_import_register_invariants(
            contract, behaviors, seeds
        )
        self.assertNotIn(
            2, {row["region_index"] for row in without_return["relations"]}
        )

        analysis = _infer_import_register_invariants(
            contract,
            behaviors,
            seeds,
            internal_return_predecessors=[{
                "source_region_index": 1,
                "target_region_index": 2,
            }],
        )
        self.assertEqual(
            {row["region_index"] for row in analysis["relations"]}, {1, 2, 3}
        )
        self.assertEqual(analysis["counts"]["internal_return_predecessors"], 1)
        self.assertEqual(analysis["counts"]["indirect_import_calls"], 1)

    def test_import_register_transfer_claims_are_unique_and_fail_closed(self):
        imported = {"dll": "kernel32.dll", "symbol": "TlsGetValue"}
        relation = {
            "original": "ebp", "candidate": "edi", "import": imported,
        }
        contract = {"regions": [
            {"input_import_relations": []},
            {"input_import_relations": [relation]},
        ]}
        behaviors = [{
            "original_ir": {"registers": {"ebp": {"op": "input_reg", "reg": "ebp"}}},
            "candidate_ir": {"registers": {"edi": {"op": "input_reg", "reg": "edi"}}},
        }, {"original_ir": {}, "candidate_ir": {}}]
        seed = {
            "profile": "iat_register_seed_v1",
            "region_index": 0,
            "original_register": "ebp",
            "candidate_register": "edi",
            "original_iat_rva": 0x2200,
            "candidate_iat_rva": 0x2300,
            "import": imported,
        }
        claims = _import_register_transfer_claims(contract, behaviors, 0, 1, [seed])
        self.assertEqual([claim["kind"] for claim in claims or []], ["seed"])
        self.assertIsNone(
            _import_register_transfer_claims(contract, behaviors, 0, 1, [seed, seed])
        )

        contract["regions"][0]["input_import_relations"] = [relation]
        claims = _import_register_transfer_claims(contract, behaviors, 0, 1, [])
        self.assertEqual([claim["kind"] for claim in claims or []], ["preserve"])
        self.assertIsNone(
            _import_register_transfer_claims(contract, behaviors, 0, 1, [seed])
        )
        behaviors[0]["candidate_ir"]["registers"]["edi"] = {
            "op": "input_reg", "reg": "eax",
        }
        self.assertIsNone(
            _import_register_transfer_claims(contract, behaviors, 0, 1, [])
        )

    def test_related_word_zero_guard_claim_supports_negation_but_not_other_shapes(self):
        source = {"input_relations": [{
            "original": "esi", "candidate": "edi", "relation": "related_word",
        }]}
        zero = {
            "op": "equal",
            "left": {
                "op": "bit_and",
                "left": {"op": "input_reg", "reg": "esi"},
                "right": {"op": "input_reg", "reg": "esi"},
            },
            "right": {"op": "constant", "value": 0},
        }
        candidate_zero = json.loads(json.dumps(zero))
        candidate_zero["left"]["left"]["reg"] = "edi"
        candidate_zero["left"]["right"]["reg"] = "edi"
        claim = _related_word_zero_guard_claim(
            source, {"op": "not", "value": zero},
            {"op": "not", "value": candidate_zero},
        )
        self.assertEqual(claim, {
            "profile": "related_word_zero_guard_v1",
            "original_register": "esi",
            "candidate_register": "edi",
            "value_relation": "related_word",
            "not_count": 1,
        })
        mismatched = json.loads(json.dumps(candidate_zero))
        mismatched["right"]["value"] = 1
        self.assertIsNone(_related_word_zero_guard_claim(source, zero, mismatched))

    def test_paired_stack_guard_claim_requires_unique_covered_reads(self):
        window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "ebp",
            "bytes_below": 0,
            "bytes_above": 128,
        }
        source = {"stack_windows": [window]}

        def read(register, offset):
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": offset},
                },
            }

        def zero_guard(register, offset, not_count=0):
            value = read(register, offset)
            expression = {
                "op": "equal",
                "left": {"op": "bit_and", "left": value, "right": value},
                "right": {"op": "constant", "value": 0},
            }
            for _ in range(not_count):
                expression = {"op": "not", "value": expression}
            return expression

        original = zero_guard("esp", 76, not_count=1)
        candidate = zero_guard("ebp", 76, not_count=1)
        claim = _paired_stack_guard_claim(source, original, candidate)
        self.assertEqual(claim["profile"], "paired_stack_read_guard_v1")
        self.assertEqual(claim["window"], window)
        self.assertEqual(claim["offset"], 76)
        self.assertEqual(claim["not_count"], 1)

        mismatched = zero_guard("ebp", 80, not_count=1)
        self.assertIsNone(_paired_stack_guard_claim(source, original, mismatched))
        self.assertIsNone(_paired_stack_guard_claim(
            {"stack_windows": [window, dict(window)]}, original, candidate,
        ))
        self.assertIsNone(_paired_stack_guard_claim(
            {"stack_windows": [{**window, "bytes_above": 79}]}, original, candidate,
        ))

        arithmetic_original = {
            "op": "equal",
            "left": {
                "op": "sub",
                "left": read("esp", 76),
                "right": read("esp", 12),
            },
            "right": {"op": "constant", "value": 0},
        }
        arithmetic_candidate = {
            "op": "equal",
            "left": {
                "op": "sub",
                "left": read("ebp", 76),
                "right": read("ebp", 12),
            },
            "right": {"op": "constant", "value": 0},
        }
        self.assertIsNone(
            _paired_stack_guard_claim(source, arithmetic_original, arithmetic_candidate)
        )

    def test_relative_stack_guard_supports_checked_below_frame_reads(self):
        window = {
            "range_id": 0,
            "original_register": "ebp",
            "candidate_register": "edi",
            "bytes_below": 16,
            "bytes_above": 4,
        }
        source = {"stack_windows": [window]}

        def guard(register, amount, not_count=0):
            address = {
                "op": "add",
                "left": {"op": "input_reg", "reg": register},
                "right": {"op": "constant", "value": 2**32 - amount},
            }
            value = {"op": "read32", "address": address}
            expression = {
                "op": "equal",
                "left": {"op": "bit_and", "left": value, "right": value},
                "right": {"op": "constant", "value": 0},
            }
            for _ in range(not_count):
                expression = {"op": "not", "value": expression}
            return expression

        original = guard("ebp", 12, not_count=1)
        candidate = guard("edi", 12, not_count=1)
        claim = _paired_stack_relative_guard_claim(source, original, candidate)
        self.assertEqual(claim["profile"], "paired_stack_read_relative_guard_v1")
        self.assertEqual(claim["adjustment"], {"kind": "subtract", "amount": 12})
        self.assertEqual(claim["window"], window)
        self.assertTrue(claim["masked"])
        self.assertEqual(claim["not_count"], 1)

        self.assertIsNone(
            _paired_stack_relative_guard_claim(
                source, original, guard("edi", 8, not_count=1),
            )
        )
        self.assertIsNone(
            _paired_stack_relative_guard_claim(
                {"stack_windows": [{**window, "bytes_below": 8}]},
                original, candidate,
            )
        )
        self.assertIsNone(
            _paired_stack_relative_guard_claim(
                {"stack_windows": [window, dict(window)]}, original, candidate,
            )
        )

    def test_stack_read32_sub_output_claim_requires_checked_window(self):
        window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "ebp",
            "bytes_below": 0,
            "bytes_above": 84,
        }
        output = {"original": "eax", "candidate": "ecx", "relation": "related_word"}

        def expression(register, offset=76, subtract=0):
            return {
                "op": "sub",
                "left": {
                    "op": "read32",
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": register},
                        "right": {"op": "constant", "value": offset},
                    },
                },
                "right": {"op": "constant", "value": subtract},
            }

        claim = _stack_read32_sub_output_claim(
            {"stack_windows": [window]}, output,
            expression("esp"), expression("ebp"),
        )
        self.assertEqual(claim["kind"], "stack_read32_sub")
        self.assertEqual(claim["offset"], 76)
        self.assertEqual(claim["subtract"], 0)
        self.assertFalse(claim["original_direct_read"])
        self.assertFalse(claim["candidate_direct_read"])
        self.assertFalse(claim["original_direct_address"])
        self.assertFalse(claim["candidate_direct_address"])
        direct_claim = _stack_read32_sub_output_claim(
            {"stack_windows": [window]}, output,
            expression("esp")["left"], expression("ebp")["left"],
        )
        self.assertEqual(direct_claim["offset"], 76)
        self.assertEqual(direct_claim["subtract"], 0)
        self.assertTrue(direct_claim["original_direct_read"])
        self.assertTrue(direct_claim["candidate_direct_read"])
        self.assertFalse(direct_claim["original_direct_address"])
        self.assertFalse(direct_claim["candidate_direct_address"])
        zero_offset_claim = _stack_read32_sub_output_claim(
            {"stack_windows": [window]}, output,
            {"op": "read32", "address": {"op": "input_reg", "reg": "esp"}},
            {"op": "read32", "address": {"op": "input_reg", "reg": "ebp"}},
        )
        self.assertEqual(zero_offset_claim["offset"], 0)
        self.assertTrue(zero_offset_claim["original_direct_read"])
        self.assertTrue(zero_offset_claim["candidate_direct_read"])
        self.assertTrue(zero_offset_claim["original_direct_address"])
        self.assertTrue(zero_offset_claim["candidate_direct_address"])
        mixed_shape_claim = _stack_read32_sub_output_claim(
            {"stack_windows": [window]}, output,
            expression("esp", offset=0)["left"],
            {"op": "read32", "address": {"op": "input_reg", "reg": "ebp"}},
        )
        self.assertFalse(mixed_shape_claim["original_direct_address"])
        self.assertTrue(mixed_shape_claim["candidate_direct_address"])
        self.assertIsNone(_stack_read32_sub_output_claim(
            {"stack_windows": [{**window, "bytes_above": 79}]}, output,
            expression("esp"), expression("ebp"),
        ))
        self.assertIsNone(_stack_read32_sub_output_claim(
            {"stack_windows": [window]}, output,
            expression("esp"), expression("ebp", subtract=1),
        ))

    def test_direct_call_push_requires_unique_mapped_final_stack_write(self):
        stack = {
            "op": "sub",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 4},
        }
        region = {"code_targets": [
            {
                "id": 7, "region_index": 7,
                "original_rva": 0x700, "candidate_rva": 0x900,
            },
            {
                "id": 8, "region_index": 8,
                "original_rva": 0x800, "candidate_rva": 0xA00,
            },
        ]}
        behavior = {
            "original_ir": {
                "registers": {"esp": stack},
                "writes": [{
                    "address": stack,
                    "value": {"op": "constant", "value": 0x400800},
                }],
                "outcome": {"op": "call", "target": 7, "continuation": 8},
            },
            "candidate_ir": {
                "registers": {"esp": stack},
                "writes": [{
                    "address": stack,
                    "value": {"op": "constant", "value": 0x500A00},
                }],
                "outcome": {"op": "call", "target": 7, "continuation": 8},
            },
        }
        claim = _direct_call_push_claim(
            region, behavior,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        )
        self.assertEqual(claim, {
            "profile": "mapped_direct_call_push_v1",
            "callee_target_id": 7,
            "continuation_target_id": 8,
            "continuation_region_index": 8,
            "original_return_address": 0x400800,
            "candidate_return_address": 0x500A00,
            "original_stack_address": stack,
            "candidate_stack_address": stack,
        })
        self.assertEqual(_direct_call_stack_amount(claim), 4)

        framed = json.loads(json.dumps(claim))
        framed_stack = {
            "op": "sub",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 16},
        }
        framed["original_stack_address"] = framed_stack
        framed["candidate_stack_address"] = framed_stack
        self.assertEqual(_direct_call_stack_amount(framed), 16)

        mismatched = json.loads(json.dumps(framed))
        mismatched["candidate_stack_address"]["right"]["value"] = 20
        self.assertIsNone(_direct_call_stack_amount(mismatched))

        wrong_return = json.loads(json.dumps(behavior))
        wrong_return["candidate_ir"]["writes"][-1]["value"]["value"] += 4
        self.assertIsNone(_direct_call_push_claim(
            region, wrong_return,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        ))

        overwritten = json.loads(json.dumps(behavior))
        overwritten["original_ir"]["writes"].append({
            "address": stack, "value": {"op": "constant", "value": 0},
        })
        self.assertIsNone(_direct_call_push_claim(
            region, overwritten,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        ))

        ambiguous = json.loads(json.dumps(region))
        ambiguous["code_targets"].append(dict(ambiguous["code_targets"][1]))
        self.assertIsNone(_direct_call_push_claim(
            ambiguous, behavior,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        ))

    def test_return_pop_requires_matching_esp_relative_slot_and_delta(self):
        def offset(value):
            return {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": value},
            }

        behavior = {
            "original_ir": {
                "registers": {"esp": offset(20)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
            "candidate_ir": {
                "registers": {"esp": offset(20)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
        }
        self.assertEqual(_return_pop_claim(behavior), {
            "profile": "esp_relative_return_pop_v1",
            "original_stack_address": offset(8),
            "candidate_stack_address": offset(8),
            "original_stack_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 8,
            },
            "candidate_stack_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 8,
            },
            "original_stack_offset": 8,
            "candidate_stack_offset": 8,
            "original_output_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 20,
            },
            "candidate_output_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 20,
            },
            "original_output_offset": 20,
            "candidate_output_offset": 20,
            "pop_bytes": 8,
        })

        mismatched = json.loads(json.dumps(behavior))
        mismatched["candidate_ir"]["registers"]["esp"]["right"]["value"] = 24
        self.assertIsNone(_return_pop_claim(mismatched))

        transformed = json.loads(json.dumps(behavior))
        transformed["original_ir"]["outcome"]["target"] = {
            "op": "bit_or", "left": {"op": "constant", "value": 0},
            "right": {"op": "read32", "address": offset(8)},
        }
        self.assertIsNone(_return_pop_claim(transformed))

    def test_return_after_static_write_requires_complete_image_separations(self):
        stack = {"op": "input_reg", "reg": "esp"}
        output = {
            "op": "add", "left": stack,
            "right": {"op": "constant", "value": 4},
        }
        original_write = {
            "address": {"op": "constant", "value": 0x401000},
            "value": {"op": "read32", "address": output},
        }
        candidate_write = {
            "address": {"op": "constant", "value": 0x501000},
            "value": {"op": "read32", "address": output},
        }
        behavior = {
            "original_ir": {
                "registers": {"esp": output},
                "writes": [original_write],
                "outcome": {
                    "op": "returned",
                    "target": _semantic_read32_after_writes(
                        stack, [original_write]
                    ),
                },
            },
            "candidate_ir": {
                "registers": {"esp": output},
                "writes": [candidate_write],
                "outcome": {
                    "op": "returned",
                    "target": _semantic_read32_after_writes(
                        stack, [candidate_write]
                    ),
                },
            },
        }
        binary = lambda base: SimpleNamespace(
            image_base=base,
            pe=SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x3000)),
        )
        contract = {"regions": [{"address_separations": []}]}
        refined = _attach_return_write_address_separations(
            contract, [behavior], binary(0x400000), binary(0x500000)
        )
        region = refined["regions"][0]

        self.assertEqual(len(region["address_separations"]), 16)
        claim = _return_pop_claim(behavior, region=region)
        self.assertIsNotNone(claim)
        self.assertEqual(
            claim["profile"], "esp_relative_return_after_static_writes_v1"
        )
        self.assertEqual(claim["pop_bytes"], 0)

        missing = json.loads(json.dumps(region))
        missing["address_separations"].pop()
        self.assertIsNone(_return_pop_claim(behavior, region=missing))

        dynamic = json.loads(json.dumps(behavior))
        dynamic["original_ir"]["writes"][0]["address"] = stack
        dynamic["original_ir"]["outcome"]["target"] = (
            _semantic_read32_after_writes(
                stack, dynamic["original_ir"]["writes"]
            )
        )
        dynamic_contract = _attach_return_write_address_separations(
            contract, [dynamic], binary(0x400000), binary(0x500000)
        )
        self.assertIsNone(_return_pop_claim(
            dynamic, region=dynamic_contract["regions"][0]
        ))

        outside = json.loads(json.dumps(behavior))
        outside["candidate_ir"]["writes"][0]["address"]["value"] = 0x600000
        outside["candidate_ir"]["outcome"]["target"] = (
            _semantic_read32_after_writes(
                stack, outside["candidate_ir"]["writes"]
            )
        )
        outside_contract = _attach_return_write_address_separations(
            contract, [outside], binary(0x400000), binary(0x500000)
        )
        self.assertIsNone(_return_pop_claim(
            outside, region=outside_contract["regions"][0]
        ))

        malformed = json.loads(json.dumps(behavior))
        malformed["original_ir"]["outcome"]["target"]["right"]["right"][
            "amount"
        ] = 23
        self.assertIsNone(_return_pop_claim(malformed, region=region))

    def test_return_slot_contracts_seed_transfer_and_align_a_return(self):
        def offset(value):
            operation = "add" if value >= 0 else "sub"
            return {
                "op": operation,
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": abs(value)},
            }

        identity_registers = {"esp": offset(0)}
        return_behavior = {
            "original_ir": {
                "registers": {"esp": offset(12)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
            "candidate_ir": {
                "registers": {"esp": offset(12)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
        }
        behaviors = [
            {"original_ir": {"registers": identity_registers},
             "candidate_ir": {"registers": identity_registers}},
            {"original_ir": {"registers": {"esp": offset(-8)}},
             "candidate_ir": {"registers": {"esp": offset(-8)}}},
            return_behavior,
        ]
        rows = [
            {"region_index": 0, "is_return": False, "return_pop_claim": None,
             "outputs": [{"original": "esp", "candidate": "esp"}]},
            {"region_index": 1, "is_return": False, "return_pop_claim": None,
             "outputs": [{"original": "esp", "candidate": "esp"}]},
            {"region_index": 2, "is_return": True,
             "return_pop_claim": _return_pop_claim(return_behavior),
             "outputs": [{"original": "esp", "candidate": "esp"}]},
        ]
        edges = [
            {
                "source_region_index": 0, "target_region_index": 1,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": {
                    "checked": True, "continuation_region_index": 2,
                },
            },
            {
                "source_region_index": 1, "target_region_index": 2,
                "kind": "jump", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": None,
            },
        ]

        analysis = _attach_return_slot_contracts(behaviors, rows, edges)

        self.assertTrue(analysis["converged"])
        self.assertEqual(analysis["seed_edges"], 1)
        self.assertEqual(rows[1]["return_slot_offsets"], [
            {
                "original_register": "esp", "original": 0,
                "candidate_register": "esp", "candidate": 0,
            },
        ])
        self.assertEqual(rows[2]["return_slot_offsets"], [
            {
                "original_register": "esp", "original": 8,
                "candidate_register": "esp", "candidate": 8,
            },
        ])
        self.assertEqual(rows[2]["return_slot_status"], "satisfied")
        self.assertEqual(len(edges[1]["return_slot_transfer_claims"]), 1)
        self.assertEqual(len(rows[2]["return_pop_frame_claims"]), 1)

    def test_return_slot_contracts_preserve_outer_frame_without_public_esp(self):
        def offset(value):
            operation = "add" if value >= 0 else "sub"
            return {
                "op": operation,
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": abs(value)},
            }

        behaviors = [
            {
                "original_ir": {"registers": {"esp": offset(-4)}},
                "candidate_ir": {"registers": {"esp": offset(-4)}},
            },
            {
                "original_ir": {"registers": {"esp": offset(-4)}},
                "candidate_ir": {"registers": {"esp": offset(-4)}},
            },
            {
                "original_ir": {"registers": {"esp": offset(0)}},
                "candidate_ir": {"registers": {"esp": offset(0)}},
            },
        ]
        rows = [
            {"region_index": index, "is_return": False,
             "return_pop_claim": None, "outputs": []}
            for index in range(3)
        ]
        edges = [
            {
                "source_region_index": 0, "target_region_index": 1,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": {
                    "continuation_region_index": 0,
                },
            },
            {
                "source_region_index": 1, "target_region_index": 2,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": {
                    "continuation_region_index": 1,
                },
            },
        ]

        analysis = _attach_return_slot_contracts(behaviors, rows, edges)

        self.assertTrue(analysis["converged"])
        self.assertEqual(rows[1]["return_slot_offsets"], [
            {
                "original_register": "esp", "original": 0,
                "candidate_register": "esp", "candidate": 0,
            },
        ])
        self.assertEqual(rows[2]["return_slot_offsets"], [
            {
                "original_register": "esp", "original": 0,
                "candidate_register": "esp", "candidate": 0,
            },
            {
                "original_register": "esp", "original": 4,
                "candidate_register": "esp", "candidate": 4,
            },
        ])
        self.assertEqual(edges[1]["return_slot_transfer_claims"], [{
            "profile": "return_slot_affine_transfer_v2",
            "source": {
                "original_register": "esp", "original": 0,
                "candidate_register": "esp", "candidate": 0,
            },
            "target": {
                "original_register": "esp", "original": 4,
                "candidate_register": "esp", "candidate": 4,
            },
            "original_output_witness": {
                "kind": "sub_right", "prior": {"kind": "input"}, "value": 4,
            },
            "candidate_output_witness": {
                "kind": "sub_right", "prior": {"kind": "input"}, "value": 4,
            },
        }])

    def test_private_runtime_frame_transfer_rejects_non_affine_esp(self):
        def offset(value):
            operation = "add" if value >= 0 else "sub"
            return {
                "op": operation,
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": abs(value)},
            }

        behaviors = [
            {
                "original_ir": {"registers": {"esp": offset(-4)}},
                "candidate_ir": {"registers": {"esp": offset(-4)}},
            },
            {
                "original_ir": {"registers": {
                    "esp": {"op": "constant", "value": 0x1000},
                }},
                "candidate_ir": {"registers": {
                    "esp": {"op": "constant", "value": 0x2000},
                }},
            },
        ]
        rows = [
            {"region_index": index, "is_return": False,
             "return_pop_claim": None, "outputs": []}
            for index in range(2)
        ]
        edges = [
            {
                "source_region_index": 0, "target_region_index": 1,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": {"continuation_region_index": 0},
            },
            {
                "source_region_index": 1, "target_region_index": 1,
                "kind": "jump", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": None,
            },
        ]

        analysis = _attach_return_slot_contracts(behaviors, rows, edges)

        self.assertTrue(analysis["converged"])
        self.assertEqual(edges[1]["return_slot_transfer_rules"], [])
        self.assertEqual(edges[1]["return_slot_transfer_claims"], [])

    def test_return_slot_summary_replays_a_checked_indirect_nested_call(self):
        def offset(value):
            operation = "add" if value >= 0 else "sub"
            return {
                "op": operation,
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": abs(value)},
            }

        return_behavior = {
            "original_ir": {
                "registers": {"esp": offset(4)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(0)},
                },
            },
            "candidate_ir": {
                "registers": {"esp": offset(4)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(0)},
                },
            },
        }
        behaviors = [
            {"original_ir": {"registers": {"esp": offset(-4)}},
             "candidate_ir": {"registers": {"esp": offset(-4)}}},
            {"original_ir": {"registers": {"esp": offset(-4)}},
             "candidate_ir": {"registers": {"esp": offset(-4)}}},
            return_behavior,
            {"original_ir": {"registers": {"esp": offset(0)}},
             "candidate_ir": {"registers": {"esp": offset(0)}}},
        ]
        rows = [{
            "region_index": index,
            "is_return": index == 2,
            "return_pop_claim": (
                _return_pop_claim(return_behavior) if index == 2 else None
            ),
            "outputs": [{"original": "esp", "candidate": "esp"}],
        } for index in range(4)]
        edges = [
            {
                "source_region_index": 0, "target_region_index": 1,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": {"continuation_region_index": 3},
            },
            {
                "source_region_index": 1, "target_region_index": 2,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": None,
                "indirect_target_profile":
                    "immutable_relocated_function_pointer_call_v1",
                "indirect_target_claim": {"target_id": 2},
                "indirect_call_push_claim": {
                    "continuation_region_index": 3,
                    "continuation_target_id": 3,
                },
            },
        ]

        analysis = _attach_return_slot_contracts(behaviors, rows, edges)

        self.assertTrue(analysis["converged"])
        self.assertEqual(rows[3]["return_slot_offsets"], [{
            "original_register": "esp", "original": 0,
            "candidate_register": "esp", "candidate": 0,
        }])
        self.assertEqual(len(edges[1]["return_slot_call_summary_claims"]), 1)
        self.assertEqual(
            edges[1]["return_slot_call_summary_claims"][0]["profile"],
            "return_slot_call_summary_v1",
        )
        indirect_summary = next(
            summary
            for summary in analysis["call_summary_analysis"]["summaries"]
            if summary["callsite_region_index"] == 1
        )
        self.assertEqual(
            indirect_summary["return_slot_status"],
            "candidate_requires_lean_replay",
        )

    def test_return_slot_contracts_follow_frame_pointer_round_trip(self):
        def input_register(register):
            return {"op": "input_reg", "reg": register}

        behaviors = [
            {
                "original_ir": {"registers": {"esp": input_register("esp")}},
                "candidate_ir": {"registers": {"esp": input_register("esp")}},
            },
            {
                "original_ir": {"registers": {
                    "esp": input_register("esp"), "ebp": input_register("esp"),
                }},
                "candidate_ir": {"registers": {
                    "esp": input_register("esp"), "ebp": input_register("esp"),
                }},
            },
            {
                "original_ir": {"registers": {
                    "esp": input_register("ebp"), "ebp": input_register("ebp"),
                }},
                "candidate_ir": {"registers": {
                    "esp": input_register("ebp"), "ebp": input_register("ebp"),
                }},
            },
            {
                "original_ir": {"registers": {
                    "esp": input_register("esp"), "ebp": input_register("ebp"),
                }},
                "candidate_ir": {"registers": {
                    "esp": input_register("esp"), "ebp": input_register("ebp"),
                }},
            },
        ]
        rows = [{
            "region_index": index,
            "is_return": False,
            "return_pop_claim": None,
            "outputs": [
                {"original": "esp", "candidate": "esp"},
                {"original": "ebp", "candidate": "ebp"},
            ],
        } for index in range(4)]
        edges = [
            {
                "source_region_index": 0, "target_region_index": 1,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": {"continuation_region_index": 0},
            },
            {
                "source_region_index": 1, "target_region_index": 2,
                "kind": "jump", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": None,
            },
            {
                "source_region_index": 2, "target_region_index": 3,
                "kind": "jump", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": None,
            },
        ]

        analysis = _attach_return_slot_contracts(behaviors, rows, edges)

        self.assertTrue(analysis["converged"])
        self.assertIn({
            "original_register": "ebp", "original": 0,
            "candidate_register": "ebp", "candidate": 0,
        }, rows[3]["return_slot_offsets"])
        self.assertIn({
            "original_register": "esp", "original": 0,
            "candidate_register": "esp", "candidate": 0,
        }, rows[3]["return_slot_offsets"])
        frame_pointer_claims = [
            claim for claim in edges[2]["return_slot_transfer_claims"]
            if claim["source"]["original_register"] == "ebp"
            and claim["target"]["original_register"] == "esp"
        ]
        self.assertEqual(len(frame_pointer_claims), 1)

    def test_exact_memory_register_claim_requires_empty_global_value_map(self):
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        registers["eax"] = {
            "op": "read32",
            "address": {"op": "input_reg", "reg": "ebx"},
        }
        behavior = {
            "format": "stage-a-normalized-behavior-v1",
            "registers": registers,
            "x87": {},
            "writes": [],
            "flags": {},
            "outcome": {"op": "returned", "target": {"op": "input_reg", "reg": "eax"}},
        }
        pairs = [
            {"original": register, "candidate": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        ]
        contract = {
            "code_targets": [],
            "value_targets": [],
            "regions": [{
                "id": "entry",
                "numeric_id": 0,
                "root": True,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
            }],
        }
        behaviors = [{"original_ir": behavior, "candidate_ir": behavior}]

        _, identity_memory = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        self.assertEqual(identity_memory["counts"]["register_output_claims"], 8)
        self.assertIn(
            "exact_memory",
            {claim["kind"] for claim in identity_memory["regions"][0]["output_claims"]},
        )

        contract["value_targets"] = [{
            "id": 0,
            "original_value": 0x402000,
            "candidate_value": 0x403000,
            "mapped_size": 16,
        }]
        _, mapped_memory = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        self.assertEqual(mapped_memory["counts"]["register_output_claims"], 7)
        self.assertEqual(
            mapped_memory["regions"][0]["outputs"][0]["relation"],
            "related_word",
        )
        self.assertNotIn(
            "exact_memory",
            {claim["kind"] for claim in mapped_memory["regions"][0]["output_claims"]},
        )

    def test_external_call_register_policy_preserves_win32_nonvolatile_relations(self):
        register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }
        source = {
            "registers": registers,
            "outcome": {
                "op": "external_call",
                "import": {"dll": [], "name": {"op": "ordinal", "value": 1}},
                "arguments": [],
                "continuation": 1,
            },
        }
        target = {
            "registers": registers,
            "outcome": {
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            },
        }
        pairs = [
            {"original": register, "candidate": register}
            for register in register_names
        ]
        contract = {
            "code_targets": [],
            "value_targets": [],
            "machine_import_call_contracts": [{
                "id": 3,
                "import": {"dll": "", "ordinal": 1},
                "stack_result_delta": 4,
                "preserved_registers": ["ebx", "esi", "edi", "ebp"],
            }],
            "regions": [
                {
                    "id": "call",
                    "numeric_id": 0,
                    "root": True,
                    "inputs": pairs,
                    "outputs": pairs,
                    "values": [],
                },
                {
                    "id": "continuation",
                    "numeric_id": 1,
                    "root": False,
                    "inputs": pairs,
                    "outputs": pairs,
                    "values": [],
                },
            ],
        }
        _, relations = _synthesize_register_relations(
            contract,
            [
                {"original_ir": source, "candidate_ir": source},
                {"original_ir": target, "candidate_ir": target},
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        continuation = {
            relation["original"]: relation["relation"]
            for relation in relations["regions"][1]["inputs"]
        }
        self.assertEqual(
            {register for register, relation in continuation.items() if relation == "exact"},
            {"ebx", "esi", "edi", "ebp", "esp"},
        )
        self.assertEqual(
            {register for register, relation in continuation.items() if relation == "related_word"},
            {"eax", "ecx", "edx"},
        )
        self.assertEqual(
            relations["edges"][0]["environment_register_policy"]["id"],
            "win32-cdecl-stdcall-registers-v1",
        )
        external_rules = relations["edges"][0][
            "return_slot_external_transfer_rules"
        ]
        esp_rule = next(
            rule for rule in external_rules
            if rule["original_source_register"] == "esp"
            and rule["original_target_register"] == "esp"
        )
        self.assertEqual(esp_rule["machine_contract_id"], 3)
        self.assertEqual(esp_rule["original_internal_delta"], 0)
        self.assertEqual(esp_rule["original_environment_delta"], 4)
        self.assertEqual(esp_rule["original_delta"], 4)
        ebp_rule = next(
            rule for rule in external_rules
            if rule["original_source_register"] == "ebp"
            and rule["original_target_register"] == "ebp"
        )
        self.assertEqual(ebp_rule["original_environment_delta"], 0)
        self.assertEqual(ebp_rule["original_delta"], 0)
        self.assertGreater(
            relations["return_slot_analysis"]["external_transfer_rules"], 0
        )
        self.assertEqual(relations["counts"]["environment_register_policy_edges"], 1)

    def test_indirect_import_is_not_replayed_as_a_direct_external_call(self):
        contract = {"regions": [{}, {}]}
        direct = {
            "environment_barrier": True,
            "machine_contract_id": 3,
            "source_region_index": 0,
            "target_region_index": 1,
        }
        indirect = {
            **direct,
            "indirect_target_profile": "inductive_iat_register_call_v1",
        }

        self.assertTrue(_external_register_policy_replay_candidate(contract, direct))
        self.assertFalse(_external_register_policy_replay_candidate(contract, indirect))

        contract["regions"][1]["input_import_relations"] = [{
            "original": "ebp", "candidate": "edi",
        }]
        self.assertFalse(_external_register_policy_replay_candidate(contract, direct))

    def test_import_register_atoms_replace_redundant_related_word_atoms(self):
        register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        pairs = [
            {"original": register, "candidate": register}
            for register in register_names
        ]
        source_registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }
        source_registers["ebp"] = {
            "op": "read32", "address": {"op": "constant", "value": 0x402200},
        }
        target_registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }
        imported = {"dll": "kernel32.dll", "symbol": "TlsGetValue"}
        contract = {
            "code_targets": [],
            "value_targets": [],
            "regions": [
                {
                    "id": "seed", "numeric_id": 0, "root": True,
                    "inputs": pairs, "outputs": pairs, "values": [],
                    "input_import_relations": [],
                },
                {
                    "id": "use", "numeric_id": 1, "root": False,
                    "inputs": pairs, "outputs": pairs, "values": [],
                    "input_import_relations": [{
                        "original": "ebp", "candidate": "ebp", "import": imported,
                    }],
                },
            ],
        }
        _, relations = _synthesize_register_relations(
            contract,
            [
                {
                    "original_ir": {
                        "registers": source_registers,
                        "outcome": {"op": "jump", "target": 1},
                    },
                    "candidate_ir": {
                        "registers": source_registers,
                        "outcome": {"op": "jump", "target": 1},
                    },
                },
                {
                    "original_ir": {
                        "registers": target_registers,
                        "outcome": {"op": "returned", "target": {"op": "input_reg", "reg": "eax"}},
                    },
                    "candidate_ir": {
                        "registers": target_registers,
                        "outcome": {"op": "returned", "target": {"op": "input_reg", "reg": "eax"}},
                    },
                },
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        self.assertNotIn(
            "ebp", {relation["original"] for relation in relations["regions"][0]["outputs"]}
        )
        self.assertNotIn(
            "ebp", {relation["original"] for relation in relations["regions"][1]["inputs"]}
        )
        self.assertTrue(relations["regions"][0]["fully_supported_output_transfer"])
        self.assertTrue(relations["edges"][0]["relation_preservation_proposed"])

    def test_function_metadata_does_not_authorize_call_return_edges(self):
        register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }

        def behavior(outcome):
            return {"registers": registers, "outcome": outcome}

        pairs = [
            {"original": register, "candidate": register}
            for register in register_names
        ]
        regions = [
            {
                "id": "caller",
                "numeric_id": 0,
                "root": True,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
            },
            {
                "id": "callee-entry",
                "numeric_id": 1,
                "root": False,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
                "function_id": "callee",
                "function_entry": True,
            },
            {
                "id": "callee-return",
                "numeric_id": 2,
                "root": False,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
                "function_id": "callee",
                "function_entry": False,
            },
            {
                "id": "continuation",
                "numeric_id": 3,
                "root": False,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
            },
        ]
        behaviors = [
            behavior({"op": "call", "target": 1, "continuation": 3}),
            behavior({"op": "jump", "target": 2}),
            behavior({"op": "returned", "target": {"op": "input_reg", "reg": "eax"}}),
            behavior({"op": "returned", "target": {"op": "input_reg", "reg": "eax"}}),
        ]
        _, relations = _synthesize_register_relations(
            {"code_targets": [], "value_targets": [], "regions": regions},
            [
                {"original_ir": item, "candidate_ir": item}
                for item in behaviors
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        self.assertNotIn(
            "call_return", [edge["kind"] for edge in relations["edges"]]
        )
        self.assertEqual(relations["counts"]["call_return_edges"], 0)
        self.assertTrue(all(
            relation["relation"] == "related_word"
            for relation in relations["regions"][3]["inputs"]
        ))
        proof_ir = _attach_register_relation_analysis(
            {"obligations": []}, relations
        )
        self.assertFalse(any(
            obligation["kind"] == "call_return_stack_composition"
            for obligation in proof_ir["obligations"]
        ))

    def test_memory_pullback_support_recurses_through_local_write_reads(self):
        register = lambda name: {"op": "input_reg", "reg": name}
        prior = {"op": "read8", "address": register("ebx")}
        nested = {
            "op": "read8_after_write",
            "address": register("ebx"),
            "write_address": register("esp"),
            "write_value": register("eax"),
            "prior": prior,
        }
        self.assertEqual(
            _semantic_memory_pullback_support(nested),
            ("lean_pullback_supported", None),
        )
        nested["prior"] = {
            "op": "read8",
            "address": {"op": "input_flag_value", "bit": 5},
        }
        status, blocker = _semantic_memory_pullback_support(nested)
        self.assertEqual(status, "unsupported_nested_post_write_read")
        self.assertIn("flag-dependent", blocker)

    def test_x87_load_pullback_accepts_predecessor_control_replacement(self):
        register = lambda name: {"op": "input_reg", "reg": name}
        observation = {
            "op": "load",
            "format": "float64",
            "address": {"op": "add", "left": register("esp"),
                        "right": {"op": "constant", "value": 8}},
            "control": {"op": "input_x87_control"},
        }
        source = {
            "x87": {
                "control": {"op": "read32", "address": register("eax")},
                "status": {"op": "input_x87_status"},
            }
        }
        self.assertTrue(_semantic_x87_load_pullback_supported(observation, source))
        observation["control"] = {"op": "input_x87_status"}
        self.assertFalse(_semantic_x87_load_pullback_supported(observation, source))

    def test_weakest_precondition_synthesizes_compare_branch_bound_invariant(self):
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        truth_flags = {
            "zero": None,
            "carry": None,
            "sign": None,
            "overflow": None,
            "parity": None,
        }
        compare_flags = {
            **truth_flags,
            "zero": {
                "op": "equal",
                "left": {"op": "input_reg", "reg": "ecx"},
                "right": {"op": "constant", "value": 90},
            },
            "carry": {
                "op": "unsigned_less",
                "left": {"op": "input_reg", "reg": "ecx"},
                "right": {"op": "constant", "value": 90},
            },
        }
        branch = {
            "op": "and",
            "left": {"op": "not", "value": {"op": "input_flag", "index": 0}},
            "right": {"op": "not", "value": {"op": "input_flag", "index": 6}},
        }

        def behavior(outcome, flags=truth_flags):
            return {
                "format": "stage-a-normalized-behavior-v1",
                "registers": registers,
                "x87": {},
                "writes": [],
                "flags": flags,
                "outcome": outcome,
            }

        regions = [
            {"id": "compare", "numeric_id": 0, "root": True, "bounds": [], "address_separations": []},
            {"id": "branch", "numeric_id": 1, "root": False, "bounds": [], "address_separations": []},
            {
                "id": "table",
                "numeric_id": 2,
                "root": False,
                "bounds": [{"original": "ecx", "candidate": "ecx", "unsigned_lt": 91}],
                "address_separations": [],
            },
        ]
        compare = behavior({"op": "jump", "target": 1}, compare_flags)
        choose = behavior({
            "op": "branch", "condition": branch, "taken": 99, "fallthrough": 2,
        })
        table = behavior({"op": "jump", "target": 99})
        synthesis = _synthesize_relational_invariants(
            {"regions": regions},
            [
                {"original_ir": compare, "candidate_ir": compare},
                {"original_ir": choose, "candidate_ir": choose},
                {"original_ir": table, "candidate_ir": table},
            ],
        )

        self.assertEqual(synthesis["counts"]["seeds"], 2)
        self.assertEqual(synthesis["counts"]["region_invariants"], 4)
        self.assertEqual(synthesis["counts"]["edge_obligations"], 4)
        self.assertEqual(synthesis["counts"]["candidate_tautology_edges"], 2)
        self.assertEqual(synthesis["counts"]["barriers"], 0)
        self.assertEqual(
            synthesis["obligations"][0]["status"],
            "candidate_requires_lean_replay",
        )
        proved_edges = [
            edge for edge in synthesis["edge_obligations"]
            if edge["analysis_status"] == "candidate_tautology"
        ]
        self.assertEqual({edge["source_id"] for edge in proved_edges}, {"compare"})
        self.assertTrue(all(edge["lean_status"] == "pending" for edge in proved_edges))

        duplicate_regions = [dict(region) for region in regions]
        duplicate_regions[2]["bounds"] = [
            *regions[2]["bounds"],
            dict(regions[2]["bounds"][0]),
        ]
        duplicate = _synthesize_relational_invariants(
            {"regions": duplicate_regions},
            [
                {"original_ir": compare, "candidate_ir": compare},
                {"original_ir": choose, "candidate_ir": choose},
                {"original_ir": table, "candidate_ir": table},
            ],
        )
        self.assertEqual(duplicate["counts"]["seeds"], 4)
        self.assertEqual(len(duplicate["obligations"]), 2)
        expected_aliases = {
            "invariant:table:0",
            "invariant:table:1",
        }
        self.assertTrue(all(
            set(edge["obligation_ids"]) == expected_aliases
            for edge in duplicate["edge_obligations"]
        ))
        self.assertEqual(
            duplicate["obligations"][0]["candidate_tautology_edges"],
            duplicate["obligations"][1]["candidate_tautology_edges"],
        )

        missing_compare = behavior({"op": "jump", "target": 1})
        incomplete = _synthesize_relational_invariants(
            {"regions": regions},
            [
                {"original_ir": missing_compare, "candidate_ir": missing_compare},
                {"original_ir": choose, "candidate_ir": choose},
                {"original_ir": table, "candidate_ir": table},
            ],
        )
        self.assertIn(
            "loader_entry_assumption_required",
            {barrier["kind"] for barrier in incomplete["barriers"]},
        )
        self.assertTrue(all(
            obligation["status"] == "incomplete"
            for obligation in incomplete["obligations"]
        ))

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for invariant replay")
    def test_compare_branch_bound_invariant_is_replayed_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("83f95aeb007702ebfeebfe")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            spans = [(0x1000, 5), (0x1005, 2), (0x1007, 2), (0x1009, 2)]
            payload = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, (rva, _) in enumerate(spans)
                ],
                "regions": [
                    {
                        "id": f"region-{index}",
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                        **({
                            "bounds": [{
                                "original": "ecx", "candidate": "ecx", "unsigned_lt": 91,
                            }],
                        } if index == 2 else {}),
                    }
                    for index, (rva, size) in enumerate(spans)
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(payload), encoding="utf-8")

            with patch.dict(os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=root / "report",
                )

            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            synthesis = json.loads(
                (root / "report" / "relational-invariants.json").read_text(encoding="utf-8")
            )
            self.assertEqual(synthesis["counts"]["barriers"], 0)
            self.assertEqual(
                synthesis["obligations"][0]["status"],
                "candidate_requires_lean_replay",
            )
            invariant_module = root / "report" / "lean" / "StageA" / "RelationalInvariantFamily0.lean"
            self.assertTrue(invariant_module.is_file())
            source = invariant_module.read_text(encoding="utf-8")
            self.assertIn("NormalizedInvariantPredicateEdgeClosed", source)
            self.assertIn("invariantPredicateEdgeClosed_of_wp", source)
            self.assertIn("successorRangePredicate", source)
            self.assertNotIn("evalNormalizedX87", source)
            self.assertIn("invariantFamily0Checked", source)
            inventory_modules = sorted(
                (root / "report" / "lean" / "StageA").glob(
                    "RelationalInvariantFamily0Inventory*.lean"
                )
            )
            self.assertEqual(len(inventory_modules), 2)
            self.assertTrue(all(
                "invariantEdgeInventoryClosed" in path.read_text(encoding="utf-8")
                for path in inventory_modules
            ))
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            self.assertIn("GeneratedInvariantCertificate", bundle)
            self.assertIn("invariantFamily0Checked", bundle)
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            bound = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "cfg_bound_invariant"
            )
            self.assertEqual(bound["status"], "proved")
            self.assertEqual(
                bound["evidence"]["kind"],
                "lean_checked_inductive_invariant_family",
            )

            inventory_with_edge = next(
                path for path in inventory_modules
                if "ClaimedEdges : List InvariantEdgeSpec := [{"
                in path.read_text(encoding="utf-8")
            )
            inventory_lines = inventory_with_edge.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(inventory_lines):
                if "ClaimedEdges : List InvariantEdgeSpec := [{" in line:
                    inventory_lines[index] = line.split(":=", 1)[0] + ":= []"
                    break
            inventory_with_edge.write_text(
                "\n".join(inventory_lines) + "\n", encoding="utf-8"
            )
            inventory_with_edge.with_suffix(".olean").unlink(missing_ok=True)
            rejected = _run_lean_relational(
                root / "report" / "lean", bundle=inventory_with_edge.stem,
            )
            self.assertEqual(rejected["status"], "failed")
            self.assertIn("proved that the proposition", rejected["stdout"])

    def test_mapped_relocation_offsets_reject_duplicate_loader_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocation_pointer_table(0x2000))
            candidate.write_bytes(
                _pe32_image_with_relocation_pointer_table(0x3000, duplicate_data_entry=True)
            )
            issues = []

            offsets = _mapped_relocation_offsets(
                _parse_stage_a_pe(original),
                _parse_stage_a_pe(candidate),
                {
                    "id": 7,
                    "original_value": 0x402000,
                    "candidate_value": 0x403000,
                    "mapped_size": 8,
                },
                issues,
            )

            self.assertEqual(offsets, [])
            self.assertEqual(issues[0]["category"], "mapped_object_relocation_duplicate")
            self.assertEqual(issues[0]["duplicates"]["candidate"], [0])

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

    def test_identical_state_only_writes_use_compositional_checked_proof(self):
        write = (
            "[(StageA.Formal.Expr.add (StageA.Formal.Expr.inputReg "
            "(StageA.Formal.Reg.esp)) (StageA.Formal.Expr.constant 4), "
            "StageA.Formal.Expr.constant 7)]"
        )
        behavior = "{ registers := shared, writes := " + write + ", comparison := none }"
        behaviors = {"original": behavior, "candidate": behavior}
        region = {
            "inputs": [
                {"original": "eax", "candidate": "eax"},
                {"original": "esp", "candidate": "esp"},
            ],
        }

        self.assertEqual(
            _lean_identical_state_only_write_registers(region, behaviors),
            ["esp"],
        )
        source = _lean_identical_state_only_writes_component(7, region, behaviors)
        self.assertIsNotNone(source)
        assert source is not None
        self.assertIn("espGetRelated", source)
        self.assertIn("apply writesRelated_self", source)
        self.assertNotIn("memoryRelated", source)
        self.assertNotIn("addressSeparationsRelated", source)

        memory_behavior = behavior.replace(
            "StageA.Formal.Expr.constant 7",
            "StageA.Formal.Expr.read32 (StageA.Formal.Expr.constant 7)",
        )
        self.assertIsNone(_lean_identical_state_only_write_registers(
            region,
            {"original": memory_behavior, "candidate": memory_behavior},
        ))
        self.assertIsNone(_lean_identical_state_only_write_registers(
            region,
            {"original": behavior, "candidate": behavior.replace("constant 7", "constant 8")},
        ))
        self.assertIsNone(_lean_identical_state_only_write_registers(
            {"inputs": [{"original": "esp", "candidate": "ebp"}]},
            behaviors,
        ))
