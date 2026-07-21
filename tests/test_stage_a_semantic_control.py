from __future__ import annotations

import unittest
from typing import Any

from spaghetti_extractor.relational.analyses.control import (
    _relational_product_graph,
)


class StageASemanticControlTests(unittest.TestCase):
    @staticmethod
    def _fixture(
        *,
        continuation: int = 11,
        graph_guard: dict[str, Any] | None = None,
    ) -> tuple[
        dict[str, Any],
        list[dict[str, Any]],
        dict[str, Any],
        dict[str, Any],
    ]:
        valid = {
            "op": "equal",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 1},
        }
        contract = {
            "regions": [
                {
                    "id": "checked",
                    "numeric_id": 10,
                    "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                },
                {
                    "id": "continuation",
                    "numeric_id": 11,
                    "root": False,
                    "original": {"rva_start": 0x1010},
                    "candidate": {"rva_start": 0x1020},
                },
                {
                    "id": "unrelated",
                    "numeric_id": 12,
                    "root": False,
                    "original": {"rva_start": 0x1030},
                    "candidate": {"rva_start": 0x1040},
                },
            ],
            "code_targets": [
                {
                    "id": 0,
                    "region_index": 0,
                    "original_rva": 0x1000,
                    "candidate_rva": 0x1000,
                },
                {
                    "id": 1,
                    "region_index": 1,
                    "original_rva": 0x1010,
                    "candidate_rva": 0x1020,
                },
                {
                    "id": 2,
                    "region_index": 2,
                    "original_rva": 0x1030,
                    "candidate_rva": 0x1040,
                },
            ],
        }
        checked_continue = {
            "op": "checked_continue",
            "continuation": continuation,
            "valid": valid,
        }
        returned = {"op": "returned"}
        behaviors = [
            {
                "original_ir": {"outcome": checked_continue},
                "candidate_ir": {"outcome": checked_continue},
            },
            {
                "original_ir": {"outcome": returned},
                "candidate_ir": {"outcome": returned},
            },
            {
                "original_ir": {"outcome": returned},
                "candidate_ir": {"outcome": returned},
            },
        ]
        relation_guard = graph_guard if graph_guard is not None else valid
        register_relations = {
            "edges": [{
                "source_region_index": 0,
                "target_region_index": 1,
                "kind": "checked_continue",
                "original_guard": relation_guard,
                "candidate_guard": relation_guard,
            }],
        }
        return contract, behaviors, register_relations, valid

    @staticmethod
    def _graph(
        contract: dict[str, Any],
        behaviors: list[dict[str, Any]],
        register_relations: dict[str, Any],
    ) -> dict[str, Any]:
        return _relational_product_graph(
            contract,
            behaviors,
            register_relations,
            [],
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        )

    def test_checked_continue_uses_guarded_semantic_continuation(self) -> None:
        contract, behaviors, register_relations, valid = self._fixture()

        graph = self._graph(contract, behaviors, register_relations)

        self.assertEqual(graph["edges"][0]["kind"], "checkedContinue")
        self.assertEqual(graph["edges"][0]["target_node_id"], 1)
        self.assertEqual(graph["edges"][0]["original_guard"], valid)
        self.assertEqual(graph["edges"][0]["candidate_guard"], valid)
        self.assertIn(
            0, graph["evidence"]["decoded_control_complete_node_ids"]
        )
        self.assertEqual(graph["evidence"]["potential_control_cuts"], [])

    def test_checked_continue_with_wrong_guard_fails_closed(self) -> None:
        truth = {"op": "bool_constant", "value": True}
        contract, behaviors, register_relations, _valid = self._fixture(
            graph_guard=truth
        )

        graph = self._graph(contract, behaviors, register_relations)

        self.assertNotIn(
            0, graph["evidence"]["decoded_control_complete_node_ids"]
        )
        self.assertEqual(
            graph["evidence"]["potential_control_cuts"],
            [{
                "node_id": 0,
                "operations": ["checked_continue"],
                "reason": "decoded_direct_control_not_represented",
                "provenance": [],
                "potential_target_count": 1,
                "potential_target_node_ids": [1],
                "target_scope": "decoded_target_union",
            }],
        )

    def test_checked_continue_with_noncanonical_continuation_fails_closed(
        self,
    ) -> None:
        contract, behaviors, register_relations, _valid = self._fixture(
            continuation=99
        )

        graph = self._graph(contract, behaviors, register_relations)

        self.assertNotIn(
            0, graph["evidence"]["decoded_control_complete_node_ids"]
        )
        self.assertEqual(
            graph["evidence"]["potential_control_cuts"],
            [{
                "node_id": 0,
                "operations": ["checked_continue"],
                "reason": "decoded_direct_control_not_represented",
                "provenance": [],
                "potential_target_count": 0,
                "potential_target_node_ids": [],
                "target_scope": "decoded_target_union",
            }],
        )

    def test_x87_singleton_control_uses_physical_decoder_profile(self) -> None:
        contract, behaviors, register_relations, _valid = self._fixture()
        behaviors[0] = {
            "original_ir": {"outcome": {"op": "jump", "target": 11}},
            "candidate_ir": {"outcome": {"op": "jump", "target": 11}},
        }
        register_relations["edges"][0].update({
            "kind": "jump",
            "original_guard": {"op": "bool_constant", "value": True},
            "candidate_guard": {"op": "bool_constant", "value": True},
        })
        segment_candidates = [{
            "edge_index": 0,
            "source_region_index": 0,
            "target_region_index": 1,
            "certificate_profile": "composable_x87_state_only_singleton_v1",
        }]

        graph = _relational_product_graph(
            contract,
            behaviors,
            register_relations,
            segment_candidates,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        )

        candidate = graph["evidence"]["decoded_control_candidates"][0]
        self.assertEqual(candidate["profile"], "x87_singleton_decoded_control_v1")


if __name__ == "__main__":
    unittest.main()
