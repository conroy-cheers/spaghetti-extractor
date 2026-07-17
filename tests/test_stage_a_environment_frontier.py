import unittest

from spaghetti_extractor.relational.analyses.control import _composition_progress


class StageAEnvironmentFrontierTests(unittest.TestCase):
    def test_incomplete_acceptance_excludes_candidate_backed_external_edges(self):
        product_graph = {
            "counts": {
                "roots": 1,
                "declared_reachable_nodes": 1,
                "potential_reachable_nodes": 1,
                "potential_reachable_feasible_edges": 2,
                "potential_unrepresented_control_edges": 0,
                "reachable_locally_refined_edges": 1,
                "reachable_product_local_complete": False,
                "reachability_truncated_by_control_frontier": False,
            },
            "evidence": {
                "canonical_node_inventory": [{
                    "node_id": 0,
                    "target_id": 0,
                    "region_id": "root",
                    "region_numeric_id": 0,
                    "original_rva_start": 0x1000,
                    "original_rva_end": 0x1001,
                    "candidate_rva_start": 0x1000,
                    "candidate_rva_end": 0x1001,
                    "original_entry_aliases": [],
                    "candidate_entry_aliases": [],
                }],
                "declared_reachable_node_ids": [0],
                "declared_reachable_bits": [True],
                "reachable_feasible_edge_ids": [0, 1],
                "potential_control_cuts": [],
                "potential_reachable_feasible_edge_ids": [0, 1],
                "runtime_call_continuations": [],
                "reachable_local_refinement_frontier_edge_ids": [1],
                "decoded_control_complete_node_ids": [0],
                "reachable_decoded_control_frontier_node_ids": [],
                "potential_reachable_node_ids": [0],
            },
            "edges": [
                {
                    "id": 0, "source_node_id": 0, "target_node_id": 0,
                    "kind": "externalCall", "infeasible": False,
                },
                {
                    "id": 1, "source_node_id": 0, "target_node_id": 0,
                    "kind": "externalCall", "infeasible": False,
                },
            ],
            "nodes": [{
                "id": 0, "target_id": 0, "root": True,
                "outgoing_edge_ids": [0, 1],
            }],
            "root_node_ids": [0],
        }
        external_call_sites = {
            "candidates": [{
                "edge_index": 0,
                "source_region_index": 0,
                "target_region_index": 0,
            }],
            "gaps": [{
                "edge_index": 1,
                "source_region_index": 0,
                "target_region_index": 0,
                "reason": "missing paired environment refinement",
            }],
        }
        acceptance = {
            "status": "incomplete",
            "profile": None,
            "theorem": None,
            "node_steps": [],
            "blockers": [{
                "code": "environment_pending",
                "next_action": "close the remaining environment refinement",
            }],
        }

        progress = _composition_progress(
            product_graph,
            {"status": "supported", "issues": []},
            external_call_sites,
            acceptance,
        )

        self.assertEqual(progress["status"], "incomplete")
        self.assertEqual(progress["acceptance"]["status"], "incomplete")
        self.assertFalse(progress["trust"]["acceptance_authority"])
        self.assertEqual(progress["counts"]["rooted_external_edges"], 2)
        self.assertEqual(
            progress["counts"]["rooted_external_refinement_candidates"], 1
        )
        self.assertEqual(
            progress["counts"]["rooted_environment_frontier_edges"], 1
        )
        self.assertEqual(progress["frontiers"]["external_edge_ids"], [1])


if __name__ == "__main__":
    unittest.main()
