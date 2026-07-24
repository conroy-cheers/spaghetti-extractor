import copy
import json
import unittest
from unittest.mock import patch

from spaghetti_extractor.relational.analyses import registers


def _legacy_translate_callsite_behavior(
    behavior: dict[str, object],
    region_by_target_id: dict[int, int],
) -> tuple[dict[str, object], list[str]]:
    translated = json.loads(json.dumps(behavior))
    outcome = translated.get("outcome")
    if not isinstance(outcome, dict):
        return translated, ["normalized_outcome_missing"]
    operation = outcome.get("op")
    if operation == "jump":
        target_fields = ("target",)
    elif operation == "branch":
        target_fields = ("taken", "fallthrough")
    elif operation == "call":
        target_fields = ("target", "continuation")
    elif operation == "call_unmapped_return":
        target_fields = ("target",)
    elif operation in {"external_call", "indirect_call"}:
        target_fields = ("continuation",)
    else:
        target_fields = ()
    issues = []
    for field in target_fields:
        target_id = outcome.get(field)
        if (
            not isinstance(target_id, int)
            or isinstance(target_id, bool)
            or int(target_id) not in region_by_target_id
        ):
            issues.append(f"{field}_target_unmapped")
            continue
        outcome[field] = region_by_target_id[int(target_id)]
    return translated, sorted(set(issues))


def _behavior(outcome: object) -> dict[str, object]:
    expression = {
        "op": "add",
        "left": {"op": "input_reg", "reg": "eax"},
        "right": {"op": "constant", "value": 4},
    }
    return {
        "format": "stage-a-normalized-behavior-v1",
        "registers": {
            register: copy.deepcopy(expression)
            for register in ("eax", "ebx", "ecx", "edx")
        },
        "x87": {},
        "writes": [{"address": copy.deepcopy(expression), "value": 1}],
        "flags": {},
        "outcome": outcome,
    }


class StageARegisterAnalysisPerformanceTests(unittest.TestCase):
    def test_translation_matches_json_roundtrip_without_mutating_source(self) -> None:
        outcomes = [
            {"op": "jump", "target": 100},
            {"op": "branch", "taken": 100, "fallthrough": 101},
            {"op": "call", "target": 100, "continuation": 101},
            {"op": "call_unmapped_return", "target": 100},
            {"op": "external_call", "continuation": 101},
            {"op": "indirect_call", "continuation": 101},
            {"op": "returned", "target": {"op": "input_reg", "reg": "eax"}},
        ]
        target_regions = {100: 7, 101: 8}

        for outcome in outcomes:
            with self.subTest(operation=outcome["op"]):
                behavior = _behavior(outcome)
                before = copy.deepcopy(behavior)
                expected = _legacy_translate_callsite_behavior(
                    behavior, target_regions,
                )

                actual = registers._translate_callsite_behavior(
                    behavior, target_regions,
                )

                self.assertEqual(actual, expected)
                self.assertEqual(behavior, before)
                self.assertIsNot(actual[0], behavior)
                self.assertIsNot(actual[0]["outcome"], behavior["outcome"])

    def test_translation_shares_unmodified_behavior_subtrees(self) -> None:
        behavior = _behavior({"op": "jump", "target": 100})

        with (
            patch.object(
                registers.json,
                "loads",
                side_effect=AssertionError("translation must not deserialize"),
            ),
            patch.object(
                registers.json,
                "dumps",
                side_effect=AssertionError("translation must not serialize"),
            ),
        ):
            translated, issues = registers._translate_callsite_behavior(
                behavior, {100: 7},
            )

        self.assertEqual(issues, [])
        self.assertEqual(translated["outcome"]["target"], 7)
        self.assertEqual(behavior["outcome"]["target"], 100)
        self.assertIs(translated["registers"], behavior["registers"])
        self.assertIs(translated["writes"], behavior["writes"])

    def test_translation_remains_fail_closed_for_invalid_targets(self) -> None:
        behavior = _behavior({
            "op": "branch",
            "taken": True,
            "fallthrough": 999,
        })
        before = copy.deepcopy(behavior)

        translated, issues = registers._translate_callsite_behavior(
            behavior, {1: 7},
        )

        self.assertEqual(behavior, before)
        self.assertEqual(translated, behavior)
        self.assertEqual(issues, [
            "fallthrough_target_unmapped",
            "taken_target_unmapped",
        ])

    def test_translation_rejects_missing_normalized_outcome(self) -> None:
        behavior = _behavior(["not", "an", "outcome"])

        translated, issues = registers._translate_callsite_behavior(
            behavior, {},
        )

        self.assertEqual(translated, behavior)
        self.assertIsNot(translated, behavior)
        self.assertEqual(issues, ["normalized_outcome_missing"])


if __name__ == "__main__":
    unittest.main()
