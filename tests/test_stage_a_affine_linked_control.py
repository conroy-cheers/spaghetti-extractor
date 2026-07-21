import copy
import unittest

from spaghetti_extractor.relational.analyses.affine_linked_control import (
    affine_linked_control_payload,
)
from spaghetti_extractor.relational.analyses.control import (
    _affine_linked_composition_progress,
)
from spaghetti_extractor.stage_binary import StageAInputError


class StageAAffineLinkedControlTests(unittest.TestCase):
    @staticmethod
    def _family(
        state_id, node_id, original_base, candidate_base, *, stride=4
    ):
        return {
            "id": state_id,
            "node_id": node_id,
            "seed_rooted": True,
            "family": {
                "original_register": "esp",
                "original_base": original_base,
                "candidate_register": "esp",
                "candidate_base": candidate_base,
                "translation_stride": stride,
            },
        }

    @staticmethod
    def _inventory(original, candidate, *, payload=True):
        result = {
            "locations": [{
                "original_register": "esp",
                "original": original,
                "candidate_register": "esp",
                "candidate": candidate,
            }],
        }
        if payload:
            result.update({
                "exact_words": [{"original": 4, "candidate": 8}],
                "preserved_imports": [{
                    "original": "esi",
                    "candidate": "esi",
                    "import": {"dll": "test.dll", "symbol": "fixture_word"},
                }],
                "preserved_relations": [{
                    "original": "ebx", "candidate": "ebx", "relation": "exact",
                }],
            })
        return result

    @classmethod
    def _inputs(cls):
        affine = {
            "format": "stage-a-runtime-frame-affine-viability-v1",
            "certificate": {
                "viable_families": [
                    cls._family(0, 0, 0, 8),
                    cls._family(1, 1, 0, 8),
                    cls._family(2, 2, 4, 12),
                ],
                "seed_rooted_state_ids": [0, 1, 2],
                "viable_transitions": [],
                "seed_rooted_transition_ids": [],
                "viable_seeds": [{
                    "id": 0,
                    "edge_index": 0,
                    "target_state_id": 0,
                    "direct_call_push_claim": {
                        "continuation_target_id": 2,
                    },
                }],
            },
        }
        source = cls._inventory(4, 12)
        inner = cls._inventory(8, 16)
        linked = {
            "states": [
                {"id": 0, "node_id": 0, "continuation_target_id": 2,
                 "active_frame": source, "minimum_depth": 1},
                {"id": 1, "node_id": 1, "continuation_target_id": 3,
                 "active_frame": inner, "minimum_depth": 2},
                {"id": 2, "node_id": 2, "continuation_target_id": 2,
                 "active_frame": source, "minimum_depth": 1},
            ],
            "links": [{
                "source_state_id": 0,
                "target_state_id": 1,
                "resume_state_id": 2,
                "call_source_target_id": 0,
                "resume_node_id": 2,
                "resume_target_id": 2,
                "resume_continuation": 2,
                "inner_inventory": inner,
                "suspended_inventory": cls._inventory(12, 20),
                "resume_inventory": source,
                "original_gap": 8,
                "candidate_gap": 8,
            }],
        }
        graph = {
            "nodes": [
                {"id": node_id, "target_id": node_id}
                for node_id in range(3)
            ],
            "edges": [{
                "id": 0,
                "kind": "call",
                "infeasible": False,
                "source_node_id": 0,
                "target_node_id": 1,
                "source_target_id": 0,
                "target_target_id": 1,
            }],
        }
        return affine, linked, graph

    def test_projects_unique_affine_shapes_and_preserves_payload(self):
        affine, linked, graph = self._inputs()

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
        )

        self.assertEqual(result["status"], "complete_proposal")
        self.assertFalse(result["acceptance_authority"])
        self.assertEqual(result["gaps"], [])
        self.assertEqual(result["counts"], {
            "states": 3,
            "links": 1,
            "gaps": 0,
            "affine_shapes": 6,
            "exact_fallbacks": 0,
            "synthesized_resume_states": 0,
            "rooted_affine_states": 3,
            "profile_affine_states": 3,
            "represented_rooted_affine_states": 3,
            "unrepresented_rooted_affine_states": 0,
            "rooted_affine_transitions": 0,
            "profile_affine_transitions": 0,
            "bound_rooted_affine_transitions": 0,
            "unbound_rooted_affine_transitions": 0,
            "minimal_active_states": 1,
            "active_affine_states": 1,
            "dormant_only_affine_states": 2,
            "minimal_transition_bindings": 0,
            "minimal_memory_transition_bindings": 0,
            "minimal_transition_binding_gaps": 0,
            "minimal_call_link_shapes": 0,
            "minimal_call_transition_bindings": 0,
            "call_transition_binding_gaps": 0,
            "active_call_transition_variants": 0,
            "dormant_call_transition_variants": 0,
            "active_call_contexts": 0,
            "bound_active_call_contexts": 0,
            "unbound_active_call_contexts": 0,
            "bound_call_transitions": 0,
            "unbound_call_transitions": 0,
        })
        shape = result["links"][0]["inner_shape"]
        self.assertEqual(shape["locations"], {
            "kind": "affine_family",
            "artifact_state_id": 1,
            "profile_state_index": 1,
        })
        self.assertEqual(
            shape["preserved_relations"],
            linked["links"][0]["inner_inventory"]["preserved_relations"],
        )
        self.assertEqual(result["links"][0]["suspended_inventory_node_id"], 1)
        self.assertEqual(result["control_closure_status"], "complete")
        self.assertEqual(result["minimal_control_closure_status"], "complete")
        self.assertEqual(
            result["minimal_active_states"][0]["continuation_target_id"], 2
        )

    def test_unrepresented_rooted_authority_is_an_explicit_coverage_gap(self):
        affine, linked, graph = self._inputs()
        affine["certificate"]["viable_families"].append(
            self._family(3, 7, 0, 8)
        )
        affine["certificate"]["seed_rooted_state_ids"].append(3)

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
        )

        self.assertEqual(result["shape_projection_status"], "complete")
        self.assertEqual(result["control_closure_status"], "incomplete")
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["coverage_gaps"]["unrepresented_rooted_affine_state_ids"],
            [3],
        )

    def test_binds_unique_no_write_affine_control_transition(self):
        affine, linked, graph = self._inputs()
        affine["certificate"]["viable_transitions"] = [{
            "id": 0,
            "source_state_id": 0,
            "target_state_id": 2,
            "edge_index": 1,
            "source_node": 0,
            "target_node": 2,
        }]
        affine["certificate"]["seed_rooted_transition_ids"] = [0]
        graph["edges"].append({
            "id": 1,
            "kind": "direct",
            "infeasible": False,
            "source_node_id": 0,
            "target_node_id": 2,
            "source_target_id": 0,
            "target_target_id": 2,
        })
        graph["nodes"] = [
            {"id": node_id, "target_id": node_id} for node_id in range(3)
        ]
        behaviors = [{
            "original_ir": {"writes": []},
            "candidate_ir": {"writes": []},
        } for _ in range(3)]

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            behaviors=behaviors,
        )

        self.assertEqual(result["counts"]["bound_rooted_affine_transitions"], 1)
        self.assertEqual(result["counts"]["unbound_rooted_affine_transitions"], 0)
        self.assertEqual(result["transition_binding_gaps"], [])
        self.assertEqual(result["transition_bindings"][0]["transition_id"], 0)
        self.assertEqual(result["counts"]["minimal_active_states"], 2)
        self.assertEqual(result["counts"]["minimal_transition_bindings"], 1)

    def test_physical_state_only_transition_remains_explicitly_unbound(self):
        affine, linked, graph = self._inputs()
        affine["certificate"]["viable_transitions"] = [{
            "id": 0,
            "source_state_id": 0,
            "target_state_id": 2,
            "edge_index": 1,
            "source_node": 0,
            "target_node": 2,
        }]
        affine["certificate"]["seed_rooted_transition_ids"] = [0]
        graph["edges"].append({
            "id": 1,
            "kind": "direct",
            "infeasible": False,
            "source_node_id": 0,
            "target_node_id": 2,
            "source_target_id": 0,
            "target_target_id": 2,
        })
        behaviors = [{
            "original_ir": {"writes": []},
            "candidate_ir": {"writes": []},
        } for _ in range(3)]

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            behaviors=behaviors,
            physical_state_only_region_indices={0},
        )

        self.assertEqual(result["transition_bindings"], [])
        self.assertEqual(
            result["transition_binding_gaps"][0]["reason"],
            "physical_state_only_transition",
        )
        self.assertEqual(result["minimal_transition_bindings"], [])
        self.assertEqual(
            result["minimal_transition_binding_gaps"][0]["reason"],
            "physical_state_only_transition",
        )

    def test_binds_exact_paired_writes_separately_from_no_write_control(self):
        affine, linked, graph = self._inputs()
        affine["certificate"]["viable_transitions"] = [{
            "id": 0,
            "source_state_id": 0,
            "target_state_id": 2,
            "edge_index": 1,
            "source_node": 0,
            "target_node": 2,
        }]
        affine["certificate"]["seed_rooted_transition_ids"] = [0]
        graph["edges"].append({
            "id": 1,
            "kind": "direct",
            "infeasible": False,
            "source_node_id": 0,
            "target_node_id": 2,
            "source_target_id": 0,
            "target_target_id": 2,
        })
        graph["nodes"] = [
            {"id": node_id, "target_id": node_id} for node_id in range(3)
        ]
        original_write = {
            "address": {"op": "input_reg", "reg": "esp"},
            "value": {"op": "input_reg", "reg": "eax"},
        }
        candidate_write = {
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": 4},
            },
            "value": {"op": "input_reg", "reg": "ebx"},
        }
        behaviors = [{
            "original_ir": {"writes": [original_write]},
            "candidate_ir": {"writes": [candidate_write]},
        } for _ in range(3)]

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            behaviors=behaviors,
        )

        self.assertEqual(result["transition_bindings"], [])
        self.assertEqual(len(result["memory_transition_bindings"]), 1)
        self.assertEqual(result["minimal_transition_bindings"], [])
        self.assertEqual(len(result["minimal_memory_transition_bindings"]), 1)
        self.assertEqual(
            result["minimal_memory_transition_bindings"][0]["writes"],
            [{
                "original_address": original_write["address"],
                "original_value": original_write["value"],
                "candidate_address": candidate_write["address"],
                "candidate_value": candidate_write["value"],
            }],
        )
        self.assertEqual(result["minimal_transition_binding_gaps"], [])

    @classmethod
    def _call_inputs(cls):
        singleton = 2**32
        affine = {
            "format": "stage-a-runtime-frame-affine-viability-v1",
            "certificate": {
                "viable_families": [
                    cls._family(0, 0, 4, 12, stride=singleton),
                    cls._family(1, 1, 0, 0, stride=singleton),
                    cls._family(2, 2, 4, 12, stride=singleton),
                    cls._family(3, 1, 16, 24, stride=singleton),
                ],
                "seed_rooted_state_ids": [0, 1, 2, 3],
                "viable_transitions": [{
                    "id": 0,
                    "source_state_id": 0,
                    "target_state_id": 3,
                    "edge_index": 0,
                    "source_node": 0,
                    "target_node": 1,
                }],
                "seed_rooted_transition_ids": [0],
                "viable_seeds": [
                    {
                        "id": 0,
                        "edge_index": 0,
                        "target_state_id": 1,
                        "direct_call_push_claim": {
                            "continuation_target_id": 2,
                            "original_stack_address": {
                                "op": "sub",
                                "left": {"op": "input_reg", "reg": "esp"},
                                "right": {"op": "constant", "value": 12},
                            },
                            "candidate_stack_address": {
                                "op": "sub",
                                "left": {"op": "input_reg", "reg": "esp"},
                                "right": {"op": "constant", "value": 12},
                            },
                        },
                    },
                    {
                        "id": 1,
                        "edge_index": 1,
                        "target_state_id": 0,
                        "direct_call_push_claim": {
                            "continuation_target_id": 99,
                        },
                    },
                ],
            },
        }
        source = cls._inventory(4, 12, payload=False)
        inner = cls._inventory(0, 0, payload=False)
        suspended = cls._inventory(16, 24, payload=False)
        linked = {
            "states": [
                {
                    "id": 0,
                    "node_id": 0,
                    "continuation_target_id": 99,
                    "active_frame": source,
                    "minimum_depth": 1,
                },
                {
                    "id": 1,
                    "node_id": 1,
                    "continuation_target_id": 2,
                    "active_frame": inner,
                    "minimum_depth": 2,
                },
                {
                    "id": 2,
                    "node_id": 2,
                    "continuation_target_id": 99,
                    "active_frame": source,
                    "minimum_depth": 1,
                },
            ],
            "links": [{
                "source_state_id": 0,
                "target_state_id": 1,
                "resume_state_id": 2,
                "call_source_target_id": 0,
                "resume_node_id": 2,
                "resume_target_id": 2,
                "resume_continuation": 99,
                "inner_inventory": inner,
                "suspended_inventory": suspended,
                "resume_inventory": source,
                "original_gap": 16,
                "candidate_gap": 24,
            }],
        }
        graph = {
            "nodes": [
                {"id": node_id, "target_id": node_id}
                for node_id in range(3)
            ],
            "edges": [
                {
                    "id": 0,
                    "kind": "call",
                    "infeasible": False,
                    "source_node_id": 0,
                    "target_node_id": 1,
                    "source_target_id": 0,
                    "target_target_id": 1,
                },
                {
                    "id": 1,
                    "kind": "direct",
                    "infeasible": False,
                    "source_node_id": 2,
                    "target_node_id": 0,
                    "source_target_id": 2,
                    "target_target_id": 0,
                },
            ],
        }
        regions = [
            {
                "numeric_id": 0,
                "stack_windows": [{
                    "range_id": 0,
                    "original_register": "esp",
                    "candidate_register": "esp",
                    "bytes_below": 12,
                    "bytes_above": 32,
                }],
            },
            {"numeric_id": 1, "stack_windows": []},
            {"numeric_id": 2, "stack_windows": []},
        ]
        register_relations = {"edges": [
            {
                "source_region_index": 0,
                "target_region_index": 1,
                "return_slot_call_summary_claims": [{
                    "profile": "return_slot_call_summary_v1",
                    "source": {
                        "original_register": "esp",
                        "original": 4,
                        "candidate_register": "esp",
                        "candidate": 12,
                    },
                    "target": {
                        "original_register": "esp",
                        "original": 4,
                        "candidate_register": "esp",
                        "candidate": 12,
                    },
                    "return_region_index": 2,
                    "original_call_witness": {"kind": "input"},
                    "candidate_call_witness": {"kind": "input"},
                    "original_return_slot_witness": {"kind": "input"},
                    "candidate_return_slot_witness": {"kind": "input"},
                    "original_return_output_witness": {"kind": "input"},
                    "candidate_return_output_witness": {"kind": "input"},
                    "pop_bytes": 0,
                }],
            },
            {
                "source_region_index": 2,
                "target_region_index": 0,
                "return_slot_call_summary_claims": [],
            },
        ]}
        return affine, linked, graph, regions, register_relations

    def test_binds_singleton_affine_call_and_resumes_outer_continuation(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(result["minimal_control_closure_status"], "complete")
        self.assertEqual(result["counts"]["bound_call_transitions"], 1)
        self.assertEqual(result["counts"]["unbound_call_transitions"], 0)
        self.assertEqual(result["counts"]["active_call_contexts"], 1)
        self.assertEqual(result["counts"]["bound_active_call_contexts"], 1)
        self.assertEqual(result["counts"]["unbound_active_call_contexts"], 0)
        self.assertEqual(result["call_transition_binding_gaps"], [])
        binding = result["minimal_call_transition_bindings"][0]
        self.assertEqual(binding["outer_continuation_target_id"], 99)
        self.assertEqual(binding["call_continuation_target_id"], 2)
        self.assertEqual(
            binding["stack_amount"], {"original": 12, "candidate": 12}
        )
        self.assertEqual(binding["return_region_indices"], [2])
        link = result["minimal_call_link_shapes"][binding["link_shape_id"]]
        self.assertEqual(
            (link["original_gap"], link["candidate_gap"]), (16, 24)
        )
        resume = result["minimal_active_states"][
            binding["resume_control_state_id"]
        ]
        self.assertEqual(resume["continuation_target_id"], 99)

    def test_binds_returning_import_summary_without_internal_return_site(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        relation_edge = register_relations["edges"][0]
        internal_claim = relation_edge["return_slot_call_summary_claims"][0]
        relation_edge["return_slot_call_summary_claims"] = []
        relation_edge["return_slot_external_call_summary_claims"] = [{
            "profile": "external_return_slot_call_summary_v1",
            "machine_contract_id": 4,
            "thunk_region_index": 1,
            "continuation_region_index": 2,
            "source": copy.deepcopy(internal_claim["source"]),
            "suspended": copy.deepcopy(internal_claim["source"]),
            "target": copy.deepcopy(internal_claim["target"]),
            "original_call_witness": {"kind": "input"},
            "candidate_call_witness": {"kind": "input"},
            "thunk_transfer": {
                "source": copy.deepcopy(internal_claim["source"]),
                "internal_target": copy.deepcopy(internal_claim["target"]),
                "boundary_target": copy.deepcopy(internal_claim["target"]),
                "internal_rule": {
                    "original_source_register": "esp",
                    "candidate_source_register": "esp",
                    "original_target_register": "esp",
                    "candidate_target_register": "esp",
                    "original_output_witness": {"kind": "input"},
                    "candidate_output_witness": {"kind": "input"},
                    "original_delta": 0,
                    "candidate_delta": 0,
                },
                "result_rule": {
                    "source": copy.deepcopy(internal_claim["target"]),
                    "target": copy.deepcopy(internal_claim["target"]),
                    "original_delta": 0,
                    "candidate_delta": 0,
                },
                "memory_claim": {
                    "offsets": copy.deepcopy(internal_claim["source"]),
                    "original_write_witnesses": [],
                    "candidate_write_witnesses": [],
                },
            },
        }]

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(result["minimal_control_closure_status"], "complete")
        self.assertEqual(result["counts"]["bound_active_call_contexts"], 1)
        binding = result["minimal_call_transition_bindings"][0]
        self.assertEqual(
            binding["profile"],
            "returning_import_direct_call_singleton_affine_control_v1",
        )
        self.assertEqual(binding["return_summaries"], [])
        self.assertEqual(binding["external_summary"]["machine_contract_id"], 4)

    def test_multi_write_call_requires_linked_memory_binding(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        call_write = {
            "address": {"op": "input_reg", "reg": "esp"},
            "value": {"op": "input_reg", "reg": "eax"},
        }
        return_slot_write = {
            "address": affine["certificate"]["viable_seeds"][0][
                "direct_call_push_claim"
            ]["original_stack_address"],
            "value": {"op": "constant", "value": 4096},
        }
        behaviors = [{
            "original_ir": {
                "writes": [call_write, return_slot_write],
            },
            "candidate_ir": {
                "writes": [call_write, return_slot_write],
            },
        } for _ in regions]

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            behaviors=behaviors,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(result["minimal_call_transition_bindings"], [])
        self.assertEqual(
            result["call_transition_binding_gaps"][0],
            {
                "transition_id": 0,
                "edge_id": 0,
                "source_node_id": 0,
                "target_node_id": 1,
                "reason": "call_linked_memory_binding_required",
                "original_write_count": 2,
                "candidate_write_count": 2,
            },
        )
        self.assertEqual(
            result["coverage_gaps"]["unbound_call_transition_ids"], [0]
        )
        self.assertEqual(result["counts"]["active_call_contexts"], 1)
        self.assertEqual(result["counts"]["unbound_active_call_contexts"], 1)
        self.assertTrue(any(
            state["node_id"] == 2
            and state["continuation_target_id"] == 99
            for state in result["minimal_active_states"]
        ))

    def test_non_singleton_call_family_remains_explicitly_unbound(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        affine["certificate"]["viable_families"][0]["family"][
            "translation_stride"
        ] = 4

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(result["minimal_call_transition_bindings"], [])
        self.assertEqual(
            result["call_transition_binding_gaps"][0]["reason"],
            "call_source_family_not_singleton",
        )
        self.assertEqual(
            result["coverage_gaps"]["unbound_call_transition_ids"], [0]
        )

    def test_call_binding_allows_different_paired_stack_reservations(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        candidate_stack = affine["certificate"]["viable_seeds"][0][
            "direct_call_push_claim"
        ]["candidate_stack_address"]
        candidate_stack["right"]["value"] = 16
        affine["certificate"]["viable_families"][3]["family"][
            "candidate_base"
        ] = 28
        linked["links"][0]["suspended_inventory"]["locations"][0][
            "candidate"
        ] = 28
        linked["links"][0]["candidate_gap"] = 28
        regions[0]["stack_windows"][0]["bytes_below"] = 16

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        binding = result["minimal_call_transition_bindings"][0]
        self.assertEqual(
            binding["stack_amount"], {"original": 12, "candidate": 16}
        )
        self.assertEqual(
            result["minimal_call_link_shapes"][0]["candidate_gap"], 28
        )

    def test_missing_call_stack_window_remains_explicitly_unbound(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        regions[0]["stack_windows"] = []

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(result["minimal_call_transition_bindings"], [])
        self.assertEqual(
            result["call_transition_binding_gaps"][0]["reason"],
            "call_source_stack_window_missing",
        )

    def test_missing_call_return_summary_is_not_reported_as_ambiguous(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        register_relations["edges"][0]["return_slot_call_summary_claims"] = []

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(
            result["call_transition_binding_gaps"][0]["reason"],
            "call_return_summary_missing",
        )

    def test_missing_resume_affine_state_is_not_reported_as_ambiguous(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        affine["certificate"]["viable_families"][2]["family"][
            "original_base"
        ] = 8

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(
            result["call_transition_binding_gaps"][0]["reason"],
            "call_resume_affine_state_missing",
        )

    def test_missing_call_seed_is_not_reported_as_ambiguous(self):
        affine, linked, graph, regions, register_relations = self._call_inputs()
        source_seed = affine["certificate"]["viable_seeds"][1]
        source_seed["id"] = 0
        affine["certificate"]["viable_seeds"] = [source_seed]

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        self.assertEqual(
            result["call_transition_binding_gaps"][0]["reason"],
            "call_seed_missing",
        )

    def test_ambiguous_family_falls_back_to_exact_without_claiming_authority(self):
        affine, linked, graph = self._inputs()
        duplicate = copy.deepcopy(affine["certificate"]["viable_families"][1])
        duplicate["id"] = 3
        affine["certificate"]["viable_families"].append(duplicate)
        affine["certificate"]["seed_rooted_state_ids"].append(3)

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
        )

        self.assertFalse(result["acceptance_authority"])
        self.assertTrue(result["exact_fallbacks"])
        self.assertEqual(
            result["states"][1]["active_shape"]["locations"]["kind"], "exact"
        )

    def test_ambiguous_call_edge_is_an_explicit_gap(self):
        affine, linked, graph = self._inputs()
        duplicate = copy.deepcopy(graph["edges"][0])
        duplicate["id"] = 1
        graph["edges"].append(duplicate)

        result = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["links"], [])
        self.assertEqual(result["gaps"][0]["reason"], "call_edge_not_unique")

    def test_noncanonical_state_ids_fail_closed(self):
        affine, linked, graph = self._inputs()
        linked["states"][1]["id"] = 7

        with self.assertRaisesRegex(StageAInputError, "canonical"):
            affine_linked_control_payload(
                runtime_frame_affine=affine,
                linked_control=linked,
                product_graph=graph,
            )

    def test_composition_progress_separates_certified_ordinary_control_from_calls(self):
        graph = {
            "nodes": [
                {"id": 0, "outgoing_edge_ids": [0, 1]},
                {"id": 1, "outgoing_edge_ids": []},
            ],
            "edges": [
                {
                    "id": 0,
                    "source_node_id": 0,
                    "target_node_id": 1,
                    "kind": "jump",
                    "infeasible": False,
                },
                {
                    "id": 1,
                    "source_node_id": 0,
                    "target_node_id": 1,
                    "kind": "call",
                    "infeasible": False,
                },
            ],
            "evidence": {
                "locally_refined_edge_ids": [0],
                "declared_reachable_node_ids": [0, 1],
                "reachable_feasible_edge_ids": [0, 1],
            },
        }
        acceptance = {"affine_linked_control": {
            "acceptance_authority": False,
            "minimal_active_states": [
                {"id": 0, "node_id": 0},
                {"id": 1, "node_id": 0},
            ],
            "minimal_transition_bindings": [
                {
                    "source_control_state_id": 0,
                    "edge_id": 0,
                },
                {
                    "source_control_state_id": 1,
                    "edge_id": 0,
                },
            ],
            "minimal_memory_transition_bindings": [],
            "minimal_transition_binding_gaps": [],
            "links": [],
            "coverage_gaps": {
                "unbound_call_transition_ids": [7],
                "unbound_call_transitions": [{
                    "transition_id": 7,
                    "edge_id": 1,
                    "source_node_id": 0,
                    "target_node_id": 1,
                }],
                "unbound_active_call_contexts": [{
                    "id": 0,
                    "transition_id": 7,
                    "edge_id": 1,
                    "source_control_state_id": 0,
                    "outer_continuation_target_id": 9,
                    "reason": "call_return_summary_missing",
                }],
            },
        }}

        progress = _affine_linked_composition_progress(graph, acceptance)

        self.assertIsNotNone(progress)
        self.assertEqual(progress["ordinary_dispatch_node_edges"], 1)
        self.assertEqual(progress["ordinary_control_complete_node_ids"], [0])
        self.assertEqual(progress["ordinary_composition_ready_node_ids"], [0])
        self.assertEqual(progress["ordinary_segment_frontier_edge_ids"], [])
        self.assertEqual(progress["rooted_ordinary_dispatch_node_edges"], 1)
        self.assertEqual(progress["rooted_unbound_call_transition_ids"], [7])
        self.assertEqual(progress["unbound_call_transition_ids"], [7])
        self.assertEqual(progress["unbound_active_call_contexts"], 1)
        self.assertEqual(progress["rooted_unbound_active_call_contexts"], 1)
        self.assertEqual(
            progress["rooted_unbound_active_call_context_reason_counts"],
            {"call_return_summary_missing": 1},
        )
        self.assertEqual(progress["status"], "proofs_not_connected_to_acceptance")

        acceptance["affine_linked_control"]["minimal_transition_bindings"].pop()
        incomplete = _affine_linked_composition_progress(graph, acceptance)
        self.assertEqual(incomplete["ordinary_dispatch_node_edges"], 0)
        self.assertEqual(incomplete["ordinary_control_complete_node_ids"], [])
        self.assertEqual(incomplete["ordinary_composition_ready_node_ids"], [])


if __name__ == "__main__":
    unittest.main()
