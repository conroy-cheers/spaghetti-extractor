from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.transition_inventory_v2 import (
    TransitionSummaryInventoryV2,
    TransitionSummaryInventoryV2Error,
    build_transition_summary_inventory_v2,
    check_transition_summary_inventory_v2,
)
from tests.test_transition_summary_v2 import _binary, _unit


class TransitionSummaryInventoryV2Tests(unittest.TestCase):
    def test_inventory_round_trip_covers_every_exact_unit(self) -> None:
        first = _unit()
        second = copy.deepcopy(first)
        second["id"] = "unit:second"
        second["source"]["original"] = {
            "rva_start": 0x1010,
            "rva_end": 0x1018,
        }
        second["source"]["instruction_bytes_sha256"] = "c" * 64
        for family in (
            "memory_events",
            "external_events",
            "faults",
            "ordered_events",
        ):
            for event in second["semantics"][family]:
                if "instruction_rva" in event:
                    event["instruction_rva"] += 0x10
        units = [first, second]
        binary = _binary(units)

        inventory = build_transition_summary_inventory_v2(
            units=units,
            binary=binary,
        )
        parsed = TransitionSummaryInventoryV2.parse(inventory.to_payload())

        self.assertEqual(
            check_transition_summary_inventory_v2(
                parsed,
                units=units,
                binary=binary,
            ),
            inventory,
        )
        self.assertEqual(
            [row.unit.unit_id for row in inventory.summaries],
            ["unit:entry", "unit:second"],
        )

    def test_missing_unit_and_stale_counts_fail_closed(self) -> None:
        unit = _unit()
        binary = _binary([unit])
        payload = build_transition_summary_inventory_v2(
            units=[unit],
            binary=binary,
        ).to_payload()

        stale = copy.deepcopy(payload)
        stale["counts"]["units"] = 2
        with self.assertRaisesRegex(
            TransitionSummaryInventoryV2Error,
            "counts are stale",
        ):
            TransitionSummaryInventoryV2.parse(stale)

        parsed = TransitionSummaryInventoryV2.parse(payload)
        with self.assertRaisesRegex(
            TransitionSummaryInventoryV2Error,
            "does not cover every exact unit",
        ):
            check_transition_summary_inventory_v2(
                parsed,
                units=[],
                binary=binary,
            )


if __name__ == "__main__":
    unittest.main()
