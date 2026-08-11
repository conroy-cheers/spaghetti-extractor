from __future__ import annotations

import unittest

from spaghetti_extractor.control_analysis_v2 import exact_control_inventory_v2


def _unit(
    identifier: str,
    start_rva: int,
    *,
    direct_targets: list[int] | None = None,
    events: list[dict] | None = None,
) -> dict:
    return {
        "id": identifier,
        "source": {
            "original": {"rva_start": start_rva, "rva_end": start_rva + 1},
        },
        "control": {
            "direct_targets": list(direct_targets or []),
            "has_indirect_target": False,
            "kind": "fallthrough",
        },
        "semantics": {
            "outcome": {"kind": "fallthrough"},
            "edge_conditions": [
                {"target_rva": target, "condition": {"op": "true"}}
                for target in direct_targets or []
            ],
            "external_events": list(events or []),
        },
    }


class ControlAnalysisV2Tests(unittest.TestCase):
    def test_internal_call_target_is_separate_from_ordinary_control(self) -> None:
        units = [
            _unit(
                "unit:caller",
                0x1000,
                direct_targets=[0x1001],
                events=[{
                    "kind": "internal_call",
                    "target_rva": 0x2000,
                    "return_rva": 0x1001,
                }],
            ),
            _unit("unit:continuation", 0x1001),
            _unit("unit:callee", 0x2000),
        ]

        inventory = exact_control_inventory_v2(units)

        self.assertEqual(inventory["issues"], [])
        self.assertEqual(
            inventory["direct_edges"],
            [{
                "source_unit_id": "unit:caller",
                "target_unit_id": "unit:continuation",
                "guard": {"op": "true"},
            }],
        )
        self.assertEqual(
            inventory["internal_call_edges"],
            [{
                "source_unit_id": "unit:caller",
                "source_event_index": 0,
                "target_unit_id": "unit:callee",
            }],
        )


if __name__ == "__main__":
    unittest.main()
