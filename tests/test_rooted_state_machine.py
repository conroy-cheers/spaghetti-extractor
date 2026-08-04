from __future__ import annotations

import unittest

from spaghetti_extractor.rooted_state_machine import (
    _rooted_unmaterialized_control_targets,
    _rooted_unresolved_direct_targets,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _manifest() -> dict:
    return {
        "source_map": [
            {"unit_id": "root", "rva_start": 0x1000},
            {"unit_id": "known", "rva_start": 0x1100},
            {"unit_id": "unreachable", "rva_start": 0x2000},
        ],
        "control": {
            "reachability": {"reachable_units": ["root", "known"]},
            "direct_targets": [
                {
                    "source_unit_id": "root",
                    "target_rva": 0x1200,
                    "status": "incomplete",
                },
                {
                    "source_unit_id": "unreachable",
                    "target_rva": 0x2100,
                    "status": "incomplete",
                },
            ],
            "recovered_indirect_targets": [
                {
                    "source_unit_id": "known",
                    "status": "recovered",
                    "target_rvas": [0x1100, 0x1300],
                    "target_unit_ids": ["known"],
                },
                {
                    "source_unit_id": "unreachable",
                    "status": "recovered",
                    "target_rvas": [0x2200],
                    "target_unit_ids": [],
                },
                {
                    "source_unit_id": "root",
                    "status": "incomplete",
                    "target_rvas": [0x1400],
                    "target_unit_ids": [],
                },
            ],
        },
    }


class RootedControlTargetTests(unittest.TestCase):
    def test_collects_only_rooted_unmaterialized_control_targets(self) -> None:
        targets = _rooted_unmaterialized_control_targets(_manifest())

        self.assertEqual(targets["all"], [0x1200, 0x1300])
        self.assertEqual(targets["direct"], [0x1200])
        self.assertEqual(targets["indirect"], [0x1300])
        self.assertEqual(
            _rooted_unresolved_direct_targets(_manifest()),
            [0x1200],
        )

    def test_materializing_target_removes_only_that_seed(self) -> None:
        manifest = _manifest()
        manifest["source_map"].append(
            {"unit_id": "new-indirect", "rva_start": 0x1300}
        )

        targets = _rooted_unmaterialized_control_targets(manifest)

        self.assertEqual(targets["all"], [0x1200])
        self.assertEqual(targets["indirect"], [])

    def test_malformed_recovered_inventory_fails_closed(self) -> None:
        manifest = _manifest()
        manifest["control"]["recovered_indirect_targets"][0][
            "target_rvas"
        ] = "0x1300"

        with self.assertRaisesRegex(
            StageAInputError,
            "recovered indirect target inventory is malformed",
        ):
            _rooted_unmaterialized_control_targets(manifest)


if __name__ == "__main__":
    unittest.main()
