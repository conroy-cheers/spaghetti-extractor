from __future__ import annotations

import unittest

from spaghetti_extractor.relational.analyses.x87 import (
    attach_x87_exact_stack_read_invariants,
)


def _window() -> dict[str, object]:
    return {
        "range_id": 0,
        "original_register": "esp",
        "candidate_register": "esp",
        "bytes_below": 4,
        "bytes_above": 96,
        "source": "test",
    }


def _load(offset: int, target: int, *, candidate_format: str = "float64") -> dict[str, object]:
    def behavior(format_name: str) -> dict[str, object]:
        address = {
            "op": "add",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": offset},
        }
        return {
            "writes": [],
            "x87": {
                "stack": [{"op": "load", "format": format_name, "address": address}],
            },
            "outcome": {"op": "jump", "target": target},
        }

    return {
        "original_ir": behavior("float64"),
        "candidate_ir": behavior(candidate_format),
    }


class StageAX87AnalysisTests(unittest.TestCase):
    def test_attaches_one_deterministic_exact_read_inventory_to_load_chain(self):
        contract = {
            "regions": [
                {"numeric_id": index, "stack_windows": [_window()]}
                for index in range(4)
            ],
        }
        contract["regions"][3]["stack_windows"][0]["bytes_above"] = 72
        behaviors = [_load(72, 1), _load(80, 2), _load(88, 3), {}]

        updated, report = attach_x87_exact_stack_read_invariants(contract, behaviors)

        self.assertEqual(report["component_count"], 1)
        self.assertEqual(report["attached_predicate_count"], 3)
        self.assertEqual(len(report["claims"]), 3)
        predicates = [
            region["state_predicates"][0] for region in updated["regions"][:3]
        ]
        self.assertTrue(all(predicate == predicates[0] for predicate in predicates))
        self.assertNotIn("state_predicates", updated["regions"][3])
        self.assertEqual(
            [
                read["original_address"]["right"]["value"]
                for read in predicates[0]["exact_memory_reads"]
            ],
            [72, 80, 88],
        )

    def test_rejects_mismatched_operand_widths(self):
        contract = {
            "regions": [
                {"numeric_id": index, "stack_windows": [_window()]}
                for index in range(2)
            ],
        }

        updated, report = attach_x87_exact_stack_read_invariants(
            contract,
            [_load(72, 1, candidate_format="float32"), {}],
        )

        self.assertEqual(report["claims"], [])
        self.assertNotIn("state_predicates", updated["regions"][0])


if __name__ == "__main__":
    unittest.main()
