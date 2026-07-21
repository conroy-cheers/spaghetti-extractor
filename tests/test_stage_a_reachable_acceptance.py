from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.relational.lean.acceptance import (
    _whole_program_acceptance_plan,
)


class StageAReachableAcceptanceTests(unittest.TestCase):
    @staticmethod
    def _inputs() -> tuple[dict, list[dict], dict, dict]:
        contract = {
            "machine_import_call_contracts": [],
            "regions": [
                {
                    "id": "root",
                    "numeric_id": 0,
                    "input_import_relations": [],
                    "input_stack_windows": [],
                    "output_stack_windows": [],
                    "input_invariant": {},
                    "original": {"rva_start": 0x1000, "rva_end": 0x1002},
                    "candidate": {"rva_start": 0x1000, "rva_end": 0x1002},
                },
                {
                    "id": "unreachable",
                    "numeric_id": 1,
                    "input_import_relations": [],
                    "input_stack_windows": [],
                    "output_stack_windows": [],
                    "input_invariant": {},
                    "original": {"rva_start": 0x1002, "rva_end": 0x1003},
                    "candidate": {"rva_start": 0x1002, "rva_end": 0x1003},
                },
            ],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {"op": "jump", "target": 0}},
                "candidate_ir": {"outcome": {"op": "jump", "target": 0}},
            },
            {
                "original_ir": {"outcome": {"op": "unsupported_dead"}},
                "candidate_ir": {"outcome": {"op": "unsupported_dead"}},
            },
        ]
        product_graph = {
            "nodes": [
                {"id": 0, "target_id": 0, "outgoing_edge_ids": [0]},
                {"id": 1, "target_id": 1, "outgoing_edge_ids": []},
            ],
            "edges": [{
                "id": 0,
                "source_region_index": 0,
                "target_region_index": 0,
                "source_node_id": 0,
                "target_node_id": 0,
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "kind": "jump",
            }],
            "root_node_ids": [0],
            "evidence": {
                "reachable_product_local_complete": False,
                "declared_reachable_node_ids": [0],
            },
        }
        register_relations = {
            "regions": [
                {"is_return": False, "return_pop_claim": None},
                {"is_return": False, "return_pop_claim": None},
            ],
            "edges": [],
        }
        return contract, behaviors, product_graph, register_relations

    def test_behavioral_acceptance_ignores_checked_unreachable_nodes(self) -> None:
        contract, behaviors, product_graph, register_relations = self._inputs()

        plan = _whole_program_acceptance_plan(
            contract, behaviors, product_graph, register_relations, [], []
        )

        blocker_codes = {blocker["code"] for blocker in plan["blockers"]}
        blocker_examples = {
            example
            for blocker in plan["blockers"]
            for example in blocker.get("examples", [])
        }
        self.assertNotIn("unreachable_region_composition_pending", blocker_codes)
        self.assertFalse(any("product node 1" in item for item in blocker_examples))

    def test_pre_entry_tls_directory_blocks_console_launch_profile(self) -> None:
        contract, behaviors, product_graph, register_relations = self._inputs()

        plan = _whole_program_acceptance_plan(
            contract,
            behaviors,
            product_graph,
            register_relations,
            [],
            [],
            launch_profile={
                "original_tls_directory": {"rva": 0xF594, "size": 24},
                "candidate_tls_directory": {"rva": 0xF59C, "size": 24},
                "original_tls_callback_rvas": [],
                "candidate_tls_callback_rvas": [],
            },
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertIn(
            "pre_entry_tls_profile_unmet",
            {blocker["code"] for blocker in plan["blockers"]},
        )

    def test_pre_entry_tls_inventory_must_be_explicit(self) -> None:
        contract, behaviors, product_graph, register_relations = self._inputs()

        plan = _whole_program_acceptance_plan(
            contract,
            behaviors,
            product_graph,
            register_relations,
            [],
            [],
            launch_profile={
                "original_tls_directory": {"rva": 0xF594, "size": 24},
                "candidate_tls_directory": {"rva": 0xF59C, "size": 24},
            },
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertIn(
            "pre_entry_tls_inventory_missing",
            {blocker["code"] for blocker in plan["blockers"]},
        )

    def test_reachable_inventory_must_be_canonical_and_include_roots(self) -> None:
        contract, behaviors, product_graph, register_relations = self._inputs()
        malformed = copy.deepcopy(product_graph)
        malformed["evidence"]["declared_reachable_node_ids"] = [1, 1]

        plan = _whole_program_acceptance_plan(
            contract, behaviors, malformed, register_relations, [], []
        )

        self.assertIn(
            "declared_reachability_inventory_invalid",
            {blocker["code"] for blocker in plan["blockers"]},
        )


if __name__ == "__main__":
    unittest.main()
