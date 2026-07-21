import unittest
from copy import deepcopy

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.affine_frames import (
    relational_affine_frame_profile_source,
)
from spaghetti_extractor.relational.runtime_frame_artifact import (
    runtime_frame_affine_viability_payload,
)


class StageARuntimeFrameAffineArtifactTests(unittest.TestCase):
    @staticmethod
    def _behavior():
        return {
            "original_ir": {"writes": []},
            "candidate_ir": {"writes": []},
        }

    @staticmethod
    def _witness(delta):
        if delta == 0:
            return {"kind": "input"}
        return {
            "kind": "add_right" if delta > 0 else "sub_right",
            "prior": {"kind": "input"},
            "value": abs(delta),
        }

    @classmethod
    def _rule(cls, delta=-4):
        return {
            "profile": "return_slot_affine_transfer_rule_v1",
            "original_source_register": "esp",
            "candidate_source_register": "esp",
            "original_target_register": "esp",
            "candidate_target_register": "esp",
            "original_delta": delta,
            "candidate_delta": delta,
            "original_output_witness": cls._witness(delta),
            "candidate_output_witness": cls._witness(delta),
        }

    @classmethod
    def _call_edge(cls, node, seed_offset, *, rules=None):
        return {
            "source_region_index": node,
            "target_region_index": node,
            "kind": "call",
            "environment_barrier": False,
            "direct_call_push_claim": {
                "profile": "mapped_direct_call_push_v1",
                "callee_target_id": node,
                "continuation_target_id": node,
                "original_return_address": node,
                "candidate_return_address": node,
                "original_stack_address": {
                    "op": "input_reg",
                    "reg": "esp",
                },
                "candidate_stack_address": {
                    "op": "input_reg",
                    "reg": "esp",
                },
            },
            "return_slot_seed": {
                "profile": "direct_call_runtime_frame_seed_v1",
                "target_region_index": node,
                "offsets": {
                    "original_register": "esp",
                    "original": seed_offset,
                    "candidate_register": "esp",
                    "candidate": seed_offset,
                },
            },
            "return_slot_transfer_rules": rules or [cls._rule()],
        }

    def _artifact(self, edges, *, graph_kinds=None):
        behaviors = [self._behavior() for _ in range(1 + max(
            edge["source_region_index"] for edge in edges
        ))]
        product_graph = None
        if graph_kinds is not None:
            product_graph = {
                "nodes": [
                    {"id": node_id} for node_id in range(len(behaviors))
                ],
                "edges": [
                    {
                        "id": edge_id,
                        "source_node_id": edge["source_region_index"],
                        "target_node_id": edge["target_region_index"],
                        "kind": graph_kinds[edge_id],
                        "infeasible": False,
                    }
                    for edge_id, edge in enumerate(edges)
                ],
            }
        return runtime_frame_affine_viability_payload(
            original_sha256="0" * 64,
            candidate_sha256="1" * 64,
            relation_contract_sha256="2" * 64,
            decoded_behaviors_sha256="3" * 64,
            register_relations={
                "edges": edges,
                "regions": [{} for _ in behaviors],
            },
            register_relations_sha256="4" * 64,
            behaviors=behaviors,
            product_graph=product_graph,
        )

    def test_canonical_ids_seed_coefficients_and_rooted_closure_are_stable(self):
        edges = [
            self._call_edge(1, 8),
            self._call_edge(0, 12),
        ]

        artifact = self._artifact(edges, graph_kinds=["call", "call"])

        self.assertEqual(
            artifact,
            self._artifact(edges, graph_kinds=["call", "call"]),
        )
        self.assertTrue(artifact["complete"])
        self.assertFalse(artifact["acceptance_authority"])
        certificate = artifact["certificate"]
        self.assertEqual(
            [(row["id"], row["node_id"], row["seed_rooted"])
             for row in certificate["viable_families"]],
            [(0, 0, True), (1, 1, True)],
        )
        self.assertEqual(
            [(row["id"], row["source_state_id"], row["edge_index"],
              row["target_state_id"])
             for row in certificate["viable_transitions"]],
            [(0, 0, 1, 0), (1, 1, 0, 1)],
        )
        self.assertEqual(
            [(row["id"], row["edge_index"], row["target_state_id"],
              row["coefficient"])
             for row in certificate["viable_seeds"]],
            [(0, 0, 1, 2), (1, 1, 0, 3)],
        )
        self.assertEqual(
            certificate["required_transition_bindings"],
            [
                {
                    "source_state_id": 0,
                    "edge_index": 1,
                    "candidate_transition_ids": [0],
                    "status": "selected",
                    "selected_transition_id": 0,
                },
                {
                    "source_state_id": 1,
                    "edge_index": 0,
                    "candidate_transition_ids": [1],
                    "status": "selected",
                    "selected_transition_id": 1,
                },
            ],
        )
        self.assertEqual(certificate["seed_rooted_state_ids"], [0, 1])
        self.assertEqual(certificate["seed_rooted_transition_ids"], [0, 1])
        self.assertEqual(certificate["orphan_state_ids"], [])
        self.assertEqual(certificate["orphan_transition_ids"], [])

    def test_ambiguous_required_transition_is_blocked_without_selection(self):
        edge = self._call_edge(
            0,
            8,
            rules=[self._rule(0), self._rule(-4)],
        )

        artifact = self._artifact([edge], graph_kinds=["call"])

        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["acceptance_authority"])
        certificate = artifact["certificate"]
        self.assertEqual(
            certificate["required_transition_bindings"],
            [{
                "source_state_id": 0,
                "edge_index": 0,
                "candidate_transition_ids": [0, 1],
                "status": "blocked_ambiguity",
            }],
        )
        self.assertIn(
            "runtime_frame_affine_transition_binding_ambiguous",
            {row["code"] for row in artifact["blockers"]},
        )
        self.assertEqual(certificate["seed_rooted_state_ids"], [0])
        self.assertEqual(certificate["seed_rooted_transition_ids"], [0, 1])
        self.assertEqual(certificate["orphan_transition_ids"], [])

    def test_missing_call_edge_binding_does_not_root_viable_family(self):
        artifact = self._artifact(
            [self._call_edge(0, 8)],
            graph_kinds=["jump"],
        )

        self.assertFalse(artifact["complete"])
        self.assertFalse(artifact["acceptance_authority"])
        self.assertIn(
            {
                "code": "runtime_frame_affine_seed_binding_missing",
                "edge_index": 0,
                "reason": "call_edge",
            },
            artifact["blockers"],
        )
        certificate = artifact["certificate"]
        self.assertEqual(certificate["viable_seeds"], [])
        self.assertEqual(certificate["seed_rooted_state_ids"], [])
        self.assertEqual(certificate["seed_rooted_transition_ids"], [])
        self.assertEqual(certificate["orphan_state_ids"], [0])
        self.assertEqual(certificate["orphan_transition_ids"], [0])
        self.assertFalse(certificate["viable_families"][0]["seed_rooted"])
        self.assertFalse(certificate["viable_transitions"][0]["seed_rooted"])

    def test_checked_call_summary_target_is_a_nonrooting_resume_anchor(self):
        edge = self._call_edge(0, 0)
        edge["direct_call_push_claim"]["continuation_region_index"] = 1
        edge["return_slot_call_summary_claims"] = [{
            "profile": "return_slot_call_summary_v1",
            "source": {
                "original_register": "esp",
                "original": 8,
                "candidate_register": "esp",
                "candidate": 8,
            },
            "target": {
                "original_register": "esp",
                "original": 12,
                "candidate_register": "esp",
                "candidate": 12,
            },
            "return_region_index": 0,
        }]
        behaviors = [self._behavior(), self._behavior()]
        artifact = runtime_frame_affine_viability_payload(
            original_sha256="0" * 64,
            candidate_sha256="1" * 64,
            relation_contract_sha256="2" * 64,
            decoded_behaviors_sha256="3" * 64,
            register_relations_sha256="4" * 64,
            behaviors=behaviors,
            register_relations={"edges": [edge], "regions": [{}, {}]},
            product_graph={
                "nodes": [{"id": 0}, {"id": 1}],
                "edges": [{
                    "id": 0,
                    "source_node_id": 0,
                    "target_node_id": 0,
                    "kind": "call",
                    "infeasible": False,
                }],
            },
        )

        self.assertTrue(artifact["complete"])
        self.assertEqual(
            artifact["facts"]["resume_anchors"],
            [{
                "edge_index": 0,
                "claim_index": 0,
                "source_node_id": 0,
                "callee_node_id": 0,
                "node_id": 1,
                "return_region_index": 0,
                "source": {
                    "original_register": "esp",
                    "original": 8,
                    "candidate_register": "esp",
                    "candidate": 8,
                },
                "location": {
                    "original_register": "esp",
                    "original": 12,
                    "candidate_register": "esp",
                    "candidate": 12,
                },
                "profile": "checked_call_return_summary_resume_anchor_v1",
            }],
        )
        certificate = artifact["certificate"]
        self.assertEqual(certificate["resume_anchor_state_ids"], [1])
        self.assertEqual(certificate["seed_rooted_state_ids"], [0])
        self.assertEqual(certificate["orphan_state_ids"], [1])
        self.assertFalse(certificate["viable_families"][1]["seed_rooted"])
        relational_affine_frame_profile_source(artifact)

        malformed = deepcopy(artifact)
        malformed["facts"]["resume_anchors"][0]["source_node_id"] = 99
        with self.assertRaisesRegex(StageAInputError, "source-gated anchor set"):
            relational_affine_frame_profile_source(malformed)

    def test_checked_external_call_summary_target_is_a_nonrooting_resume_anchor(self):
        edge = self._call_edge(0, 0)
        edge["direct_call_push_claim"]["continuation_region_index"] = 1
        edge["returning_external_thunk_contract_id"] = 7
        edge["return_slot_external_call_summary_claims"] = [{
            "profile": "external_return_slot_call_summary_v1",
            "machine_contract_id": 7,
            "thunk_region_index": 0,
            "continuation_region_index": 1,
            "source": {
                "original_register": "esp", "original": 8,
                "candidate_register": "esp", "candidate": 8,
            },
            "target": {
                "original_register": "esp", "original": 12,
                "candidate_register": "esp", "candidate": 12,
            },
        }]
        behaviors = [self._behavior(), self._behavior()]
        artifact = runtime_frame_affine_viability_payload(
            original_sha256="0" * 64,
            candidate_sha256="1" * 64,
            relation_contract_sha256="2" * 64,
            decoded_behaviors_sha256="3" * 64,
            register_relations_sha256="4" * 64,
            behaviors=behaviors,
            register_relations={"edges": [edge], "regions": [{}, {}]},
            product_graph={
                "nodes": [{"id": 0}, {"id": 1}],
                "edges": [{
                    "id": 0,
                    "source_node_id": 0,
                    "target_node_id": 0,
                    "kind": "call",
                    "infeasible": False,
                }],
            },
        )

        self.assertTrue(artifact["complete"])
        self.assertEqual(
            artifact["facts"]["resume_anchors"][0]["profile"],
            "checked_external_call_summary_resume_anchor_v1",
        )
        self.assertEqual(
            artifact["facts"]["resume_anchors"][0]["machine_contract_id"], 7
        )
        self.assertEqual(artifact["certificate"]["resume_anchor_state_ids"], [1])
        self.assertEqual(artifact["certificate"]["seed_rooted_state_ids"], [0])

    def test_external_call_summary_contract_mismatch_fails_closed(self):
        edge = self._call_edge(0, 0)
        edge["direct_call_push_claim"]["continuation_region_index"] = 1
        edge["returning_external_thunk_contract_id"] = 7
        edge["return_slot_external_call_summary_claims"] = [{
            "profile": "external_return_slot_call_summary_v1",
            "machine_contract_id": 8,
            "thunk_region_index": 0,
            "continuation_region_index": 1,
            "source": {
                "original_register": "esp", "original": 8,
                "candidate_register": "esp", "candidate": 8,
            },
            "target": {
                "original_register": "esp", "original": 12,
                "candidate_register": "esp", "candidate": 12,
            },
        }]
        behaviors = [self._behavior(), self._behavior()]
        artifact = runtime_frame_affine_viability_payload(
            original_sha256="0" * 64,
            candidate_sha256="1" * 64,
            relation_contract_sha256="2" * 64,
            decoded_behaviors_sha256="3" * 64,
            register_relations_sha256="4" * 64,
            behaviors=behaviors,
            register_relations={"edges": [edge], "regions": [{}, {}]},
        )

        self.assertFalse(artifact["complete"])
        self.assertIn(
            "runtime_frame_affine_external_resume_anchor_invalid",
            {row["code"] for row in artifact["blockers"]},
        )


if __name__ == "__main__":
    unittest.main()
