from __future__ import annotations

import unittest

from spaghetti_extractor.extraction.definedness import analyze_definedness_rows


def _undefined() -> dict[str, object]:
    return {
        "op": "undefined_flag",
        "id": "fixture:sar:of",
        "reason": "shift_overflow_undefined",
    }


def _row(*, escapes: bool) -> dict[str, object]:
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "expression_model": "stage-a-semantic-ir-v1",
        "id": "semantic-transfer:fixture-sar-and",
        "status": "reimplementable",
        "reachable": False,
        "blocker": None,
        "original": {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
        "register_writes": [],
        "flag_writes": [
            {"flag": "of", "value": _undefined() if escapes else {"op": "false"}}
        ],
        "memory_events": [],
        "external_events": [],
        "ordered_events": [],
        "faults": [],
        "edge_conditions": [{"target_rva": 0x1005, "condition": {"op": "true"}}],
        "outcome": {"kind": "fallthrough", "target_rva": 0x1005},
        "fpu_state": None,
        "instruction_effect_schedule": {
            "format": "stage-a-instruction-ordered-effect-schedule-v1",
            "status": "complete",
            "blockers": [],
            "records": [
                {
                    "rva_start": 0x1000,
                    "rva_end": 0x1003,
                    "effects": {
                        "undefined_flag_writes": [
                            {"flag": "of", "value": _undefined()}
                        ]
                    },
                },
                {
                    "rva_start": 0x1003,
                    "rva_end": 0x1005,
                    "effects": {
                        "defined_flag_writes": [
                            {"flag": "of", "value": {"op": "false"}}
                        ]
                    },
                },
            ],
        },
    }


class DefinednessTests(unittest.TestCase):
    def test_schedule_local_dead_value_does_not_require_rooted_reachability(self) -> None:
        evidence = analyze_definedness_rows([_row(escapes=False)])

        slot = evidence["slots"][0]
        self.assertEqual(slot["classification"], "unconstrained_noninterfering")
        self.assertEqual(slot["witness_policy"], "zero")
        self.assertEqual(slot["proof"]["kind"], "instruction-schedule-dead-value-v1")
        self.assertEqual(slot["proof_obligations"], [])
        self.assertEqual(slot["blocking_paths"], [])

    def test_schedule_value_escaping_to_boundary_remains_unknown(self) -> None:
        evidence = analyze_definedness_rows([_row(escapes=True)])

        slot = evidence["slots"][0]
        self.assertEqual(slot["classification"], "unknown")
        self.assertIn(
            "incomplete_source_reachability",
            {item["reason_code"] for item in slot["blocking_paths"]},
        )


if __name__ == "__main__":
    unittest.main()
