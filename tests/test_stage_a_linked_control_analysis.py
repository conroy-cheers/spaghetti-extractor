import unittest

from spaghetti_extractor.relational.analyses.linked_control import (
    linked_control_expansion_key,
    linked_control_state_key,
    project_linked_control_profile,
)
from spaghetti_extractor.relational.lean.acceptance import (
    _witnessed_linked_call_target_control_state,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _inventory(offset: int, *, exact_words: bool = False) -> dict:
    return {
        "locations": [{
            "original_register": "esp",
            "original": offset,
            "candidate_register": "esp",
            "candidate": offset,
        }],
        "exact_words": (
            [{"original": 4, "candidate": 4}] if exact_words else []
        ),
    }


class StageALinkedControlAnalysisTests(unittest.TestCase):
    def test_call_successor_uses_expansion_witness_not_dormant_tail(self):
        source = {
            "node_id": 7,
            "calls": [11, 23],
            "frame_offsets": [_inventory(16), _inventory(32)],
        }
        seeded = _inventory(0, exact_words=True)
        witness = {
            "node_id": 8,
            "calls": [99, 11, 777],
            "frame_offsets": [seeded, _inventory(16), _inventory(4096)],
        }

        target = _witnessed_linked_call_target_control_state(
            target_node_id=8,
            continuation=99,
            source_control_state=source,
            seeded_frame_inventory=seeded,
            transformed_outer_frame_inventories=source["frame_offsets"],
            expansion_witness_keys={linked_control_expansion_key(witness)},
        )

        self.assertEqual(target, {
            "node_id": 8,
            "calls": [99, 11, 23],
            "frame_offsets": [seeded, _inventory(16), _inventory(32)],
        })

    def test_call_successor_rejects_missing_immediate_expansion(self):
        source = {
            "node_id": 7,
            "calls": [11],
            "frame_offsets": [_inventory(16)],
        }
        seeded = _inventory(0)
        wrong_witness = {
            "node_id": 8,
            "calls": [99, 12],
            "frame_offsets": [seeded, _inventory(16)],
        }

        self.assertIsNone(_witnessed_linked_call_target_control_state(
            target_node_id=8,
            continuation=99,
            source_control_state=source,
            seeded_frame_inventory=seeded,
            transformed_outer_frame_inventories=source["frame_offsets"],
            expansion_witness_keys={
                linked_control_expansion_key(wrong_witness)
            },
        ))

    def test_fixed_point_key_ignores_only_the_checked_dormant_tail(self):
        one_frame = {
            "node_id": 7,
            "calls": [11],
            "frame_offsets": [_inventory(0, exact_words=True)],
        }
        recursive_tail = {
            "node_id": 7,
            "calls": [11, 23, 23],
            "frame_offsets": [
                _inventory(0, exact_words=True),
                _inventory(16),
                _inventory(32),
            ],
        }

        self.assertEqual(
            linked_control_state_key(one_frame),
            linked_control_state_key(recursive_tail),
        )
        changed_head = {**recursive_tail, "calls": [12, 23, 23]}
        changed_active = {
            **recursive_tail,
            "frame_offsets": [_inventory(4), *recursive_tail["frame_offsets"][1:]],
        }
        self.assertNotEqual(
            linked_control_state_key(one_frame),
            linked_control_state_key(changed_head),
        )
        self.assertNotEqual(
            linked_control_state_key(one_frame),
            linked_control_state_key(changed_active),
        )

    def test_expansion_key_keeps_one_caller_and_ignores_deeper_frames(self):
        depth_two = {
            "node_id": 7,
            "calls": [11, 23],
            "frame_offsets": [_inventory(0), _inventory(16)],
        }
        depth_three = {
            "node_id": 7,
            "calls": [11, 23, 31],
            "frame_offsets": [_inventory(0), _inventory(16), _inventory(32)],
        }
        different_caller = {
            **depth_three,
            "calls": [11, 24, 31],
        }

        self.assertEqual(
            linked_control_expansion_key(depth_two),
            linked_control_expansion_key(depth_three),
        )
        self.assertNotEqual(
            linked_control_expansion_key(depth_two),
            linked_control_expansion_key(different_caller),
        )

    def test_concrete_recursive_depths_collapse_to_one_linked_state(self):
        states = [
            {
                "node_id": 7,
                "calls": [11],
                "frame_offsets": [_inventory(0, exact_words=True)],
            },
            {
                "node_id": 7,
                "calls": [11, 23],
                "frame_offsets": [
                    _inventory(0, exact_words=True),
                    _inventory(16),
                ],
            },
            {
                "node_id": 7,
                "calls": [11, 23, 23],
                "frame_offsets": [
                    _inventory(0, exact_words=True),
                    _inventory(16),
                    _inventory(32),
                ],
            },
        ]

        result = project_linked_control_profile(states)

        self.assertEqual(result["status"], "profile_ready")
        self.assertEqual(result["counts"]["concrete_states"], 3)
        self.assertEqual(result["counts"]["linked_states"], 1)
        self.assertEqual(result["counts"]["collapsed_states"], 2)
        self.assertEqual(result["counts"]["multi_depth_states"], 1)
        self.assertEqual(result["states"][0]["representative_depths"], [1, 2, 3])
        self.assertEqual(
            result["states"][0]["active_frame"]["exact_words"],
            [{"original": 4, "candidate": 4}],
        )

    def test_malformed_concrete_stack_fails_closed(self):
        with self.assertRaisesRegex(StageAInputError, "equal lengths"):
            project_linked_control_profile([{
                "node_id": 7,
                "calls": [11],
                "frame_offsets": [],
            }])

    def test_nested_call_proposes_one_suspended_frame_link(self):
        source = _inventory(0, exact_words=True)
        inner = _inventory(0)
        suspended = _inventory(16, exact_words=True)
        resumed = _inventory(4, exact_words=True)
        states = [
            {"node_id": 0, "calls": [99], "frame_offsets": [source]},
            {
                "node_id": 1,
                "calls": [2, 99],
                "frame_offsets": [inner, suspended],
            },
            {"node_id": 2, "calls": [99], "frame_offsets": [resumed]},
        ]
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "call", "target": 1, "continuation": 2,
                }},
                "candidate_ir": {"outcome": {
                    "op": "call", "target": 1, "continuation": 2,
                }},
            },
            {"original_ir": {"outcome": {"op": "returned"}},
             "candidate_ir": {"outcome": {"op": "returned"}}},
            {"original_ir": {"outcome": {"op": "returned"}},
             "candidate_ir": {"outcome": {"op": "returned"}}},
        ]
        nodes = [{"target_id": index} for index in range(3)]

        result = project_linked_control_profile(
            states, behaviors=behaviors, nodes=nodes
        )

        self.assertEqual(result["counts"]["link_candidates"], 1)
        self.assertEqual(result["counts"]["link_gaps"], 0)
        link = result["links"][0]
        self.assertEqual(link["original_gap"], 16)
        self.assertEqual(link["candidate_gap"], 16)
        self.assertEqual(link["resume_target_id"], 2)
        self.assertEqual(link["inner_inventory"], inner)
        self.assertEqual(link["suspended_inventory"], suspended)
        self.assertEqual(link["resume_inventory"], resumed)
        self.assertTrue(link["requires_no_wrap_witness"])


if __name__ == "__main__":
    unittest.main()
