import copy
import unittest
from types import SimpleNamespace

from spaghetti_extractor.relational.analyses.stack import (
    _attach_stack_window_invariants,
    _discover_direct_call_stack_return_summaries,
    _return_pop_claim,
)


def _esp_offset(value: int) -> dict[str, object]:
    stack = {"op": "input_reg", "reg": "esp"}
    if value == 0:
        return stack
    return {
        "op": "add" if value > 0 else "sub",
        "left": stack,
        "right": {"op": "constant", "value": abs(value)},
    }


def _behavior(
    esp_delta: int,
    outcome: dict[str, object],
    *,
    writes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    ir = {
        "registers": {"esp": _esp_offset(esp_delta)},
        "writes": writes or [],
        "outcome": outcome,
    }
    return {"original_ir": copy.deepcopy(ir), "candidate_ir": copy.deepcopy(ir)}


def _return_behavior(output_offset: int = 12) -> dict[str, object]:
    return _behavior(
        output_offset,
        {
            "op": "returned",
            "target": {"op": "read32", "address": _esp_offset(8)},
        },
    )


def _plain_return_behavior() -> dict[str, object]:
    return _behavior(
        4,
        {
            "op": "returned",
            "target": {"op": "read32", "address": _esp_offset(0)},
        },
    )


def _fixture() -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    call_write = {
        "address": _esp_offset(-4),
        "value": {"op": "constant", "value": 5},
    }
    saved_register_writes = [
        {
            "address": _esp_offset(-4),
            "value": {"op": "input_reg", "reg": "esi"},
        },
        {
            "address": _esp_offset(-8),
            "value": {"op": "input_reg", "reg": "ebx"},
        },
    ]
    behaviors = [
        _behavior(
            -4,
            {"op": "call", "target": 1, "continuation": 5},
            writes=[call_write],
        ),
        _behavior(-8, {"op": "jump", "target": 2}, writes=saved_register_writes),
        _behavior(
            0,
            {
                "op": "branch",
                "condition": {"op": "input_flag", "index": 6},
                "taken": 3,
                "fallthrough": 4,
            },
        ),
        _return_behavior(),
        _return_behavior(),
        _behavior(
            0,
            {"op": "jump", "target": 5},
            writes=[{
                "address": _esp_offset(16),
                "value": {"op": "constant", "value": 1},
            }],
        ),
    ]
    rows = [
        {
            "region_index": index,
            "is_return": index in {3, 4},
            "return_pop_claim": (
                _return_pop_claim(behaviors[index]) if index in {3, 4} else None
            ),
        }
        for index in range(len(behaviors))
    ]
    edges = [
        {
            "source_region_index": 0,
            "target_region_index": 1,
            "kind": "call",
            "environment_barrier": False,
            "requires_call_stack_proof": False,
            "relation_preservation_proposed": True,
            "direct_call_push_claim": {
                "profile": "mapped_direct_call_push_v1",
                "continuation_region_index": 5,
            },
        },
        {
            "source_region_index": 1,
            "target_region_index": 2,
            "kind": "jump",
            "environment_barrier": False,
            "requires_call_stack_proof": False,
            "relation_preservation_proposed": True,
        },
        {
            "source_region_index": 2,
            "target_region_index": 3,
            "kind": "branch_taken",
            "environment_barrier": False,
            "requires_call_stack_proof": False,
            "relation_preservation_proposed": True,
        },
        {
            "source_region_index": 2,
            "target_region_index": 4,
            "kind": "branch_fallthrough",
            "environment_barrier": False,
            "requires_call_stack_proof": False,
            "relation_preservation_proposed": True,
        },
    ]
    contract = {
        "regions": [
            {
                "id": f"region-{index}",
                "numeric_id": index,
                "address_separations": [],
            }
            for index in range(len(behaviors))
        ],
    }
    return contract, behaviors, rows, edges


class StageACallReturnSummaryTests(unittest.TestCase):
    def test_affine_multi_return_summary_propagates_the_full_stack_window(self):
        contract, behaviors, rows, edges = _fixture()

        analysis = _discover_direct_call_stack_return_summaries(
            contract["regions"], behaviors, rows, edges
        )

        summary = analysis["summaries"][0]
        self.assertEqual(summary["status"], "candidate_requires_local_lean_replay")
        self.assertEqual(summary["return_delta"], 4)
        self.assertEqual(summary["return_region_indices"], [3, 4])
        self.assertEqual(
            (summary["bytes_below"], summary["bytes_above"]),
            (8, 4),
        )

        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        refined, stack_analysis = _attach_stack_window_invariants(
            contract,
            behaviors,
            {
                "regions": rows,
                "edges": edges,
                "return_slot_analysis": {
                    "call_summary_analysis": {"summaries": []},
                },
            },
            binary,
            binary,
        )

        callee_window = refined["regions"][1]["stack_windows"][0]
        self.assertEqual(
            (callee_window["bytes_below"], callee_window["bytes_above"]),
            (8, 24),
        )
        self.assertNotIn(
            "direct_call_window_requires_return_summary",
            {row["reason"] for row in stack_analysis["frontier"]},
        )

    def test_completed_summary_is_reused_by_a_nested_direct_call(self):
        contract, behaviors, rows, edges = _fixture()
        for index in range(6, 10):
            contract["regions"].append({
                "id": f"region-{index}",
                "numeric_id": index,
                "address_separations": [],
            })
        behaviors.extend([
            _behavior(
                -4,
                {"op": "call", "target": 1, "continuation": 7},
                writes=[{
                    "address": _esp_offset(-4),
                    "value": {"op": "constant", "value": 7},
                }],
            ),
            _plain_return_behavior(),
            _behavior(
                -4,
                {"op": "call", "target": 6, "continuation": 9},
                writes=[{
                    "address": _esp_offset(-4),
                    "value": {"op": "constant", "value": 9},
                }],
            ),
            _behavior(0, {"op": "jump", "target": 9}),
        ])
        rows.extend([
            {"region_index": 6, "is_return": False, "return_pop_claim": None},
            {
                "region_index": 7,
                "is_return": True,
                "return_pop_claim": _return_pop_claim(behaviors[7]),
            },
            {"region_index": 8, "is_return": False, "return_pop_claim": None},
            {"region_index": 9, "is_return": False, "return_pop_claim": None},
        ])
        edges.extend([
            {
                "source_region_index": 6,
                "target_region_index": 1,
                "kind": "call",
                "environment_barrier": False,
                "requires_call_stack_proof": False,
                "relation_preservation_proposed": True,
                "direct_call_push_claim": {
                    "profile": "mapped_direct_call_push_v1",
                    "continuation_region_index": 7,
                },
            },
            {
                "source_region_index": 8,
                "target_region_index": 6,
                "kind": "call",
                "environment_barrier": False,
                "requires_call_stack_proof": False,
                "relation_preservation_proposed": True,
                "direct_call_push_claim": {
                    "profile": "mapped_direct_call_push_v1",
                    "continuation_region_index": 9,
                },
            },
        ])

        analysis = _discover_direct_call_stack_return_summaries(
            contract["regions"], behaviors, rows, edges
        )

        outer = next(
            summary for summary in analysis["summaries"]
            if summary["callsite_region_index"] == 8
        )
        self.assertEqual(outer["status"], "candidate_requires_local_lean_replay")
        self.assertEqual(outer["return_delta"], 4)
        self.assertEqual((outer["bytes_below"], outer["bytes_above"]), (12, 4))

    def test_return_summary_rejects_ambiguous_or_missing_paths(self):
        for mutation, expected_blocker in (
            ("divergent_return", "ambiguous_return_esp_restoration"),
            ("missing_return", "reachable_non_return_terminal"),
            ("unpaired_write", "paired_memory_preservation_unproved"),
            ("non_affine_esp", "non_affine_or_unpaired_esp_transfer"),
        ):
            with self.subTest(mutation=mutation):
                contract, behaviors, rows, edges = _fixture()
                if mutation == "divergent_return":
                    behaviors[4] = _return_behavior(16)
                    rows[4]["return_pop_claim"] = _return_pop_claim(behaviors[4])
                elif mutation == "missing_return":
                    behaviors[2]["original_ir"]["outcome"]["fallthrough"] = 5
                    behaviors[2]["candidate_ir"]["outcome"]["fallthrough"] = 5
                    edges[3]["target_region_index"] = 5
                elif mutation == "unpaired_write":
                    behaviors[1]["candidate_ir"]["writes"].pop()
                else:
                    non_affine = {"op": "constant", "value": 0x1000}
                    behaviors[1]["original_ir"]["registers"]["esp"] = non_affine
                    behaviors[1]["candidate_ir"]["registers"]["esp"] = non_affine

                analysis = _discover_direct_call_stack_return_summaries(
                    contract["regions"], behaviors, rows, edges
                )

                summary = analysis["summaries"][0]
                self.assertEqual(summary["status"], "incomplete")
                self.assertEqual(summary["blocker"], expected_blocker)


if __name__ == "__main__":
    unittest.main()
