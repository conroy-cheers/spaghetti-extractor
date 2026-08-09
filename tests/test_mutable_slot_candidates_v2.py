from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import cast

from spaghetti_extractor.mutable_slot_candidates_v2 import (
    derive_recovery_slot_requirements_v2,
)
from spaghetti_extractor.stage_binary import StageABinary


def _binary() -> StageABinary:
    return cast(StageABinary, SimpleNamespace(
        image_base=0x400000,
        sections=(
            SimpleNamespace(
                writable=False, rva_start=0x1000, rva_end=0x2000
            ),
            SimpleNamespace(
                writable=True, rva_start=0x3000, rva_end=0x4000
            ),
        ),
    ))


class MutableSlotCandidatesV2Tests(unittest.TestCase):
    def test_cold_recoveries_define_the_exact_requirement_inventory(self) -> None:
        requirements = derive_recovery_slot_requirements_v2(
            _binary(),
            [{
                "id": "exit:b",
                "status": "incomplete",
                "mutable_slot_dependencies": [{
                    "slot_rva": 0x3020,
                    "width_bytes": 4,
                    "read_sites": [{"unit_id": "read:b", "event_index": 2}],
                    "origin_witnessed": False,
                }],
            }, {
                "id": "exit:a",
                "status": "incomplete",
                "mutable_slot_dependencies": [{
                    "slot_rva": 0x3020,
                    "width_bytes": 4,
                    "read_sites": [{"unit_id": "read:a", "event_index": 1}],
                    "origin_witnessed": False,
                }, {
                    "slot_rva": 0x3030,
                    "width_bytes": 4,
                    "read_sites": [],
                    "origin_witnessed": True,
                }],
            }],
        )

        self.assertEqual(
            [requirement.slot_rva for requirement in requirements],
            [0x3020, 0x3030],
        )
        self.assertEqual(
            [use.exit_id for use in requirements[0].uses],
            ["exit:a", "exit:b"],
        )
        self.assertEqual(
            requirements[1].dependency_rows(),
            ({
                "slot_rva": 0x3030,
                "exit_id": "exit:a",
                "witness_only": True,
                "proof_authority": False,
            },),
        )

    def test_duplicate_exit_use_is_merged_deterministically(self) -> None:
        requirements = derive_recovery_slot_requirements_v2(
            _binary(),
            [{
                "id": "exit:a",
                "mutable_slot_dependencies": [{
                    "slot_rva": 0x3020,
                    "width_bytes": 4,
                    "read_sites": [{"unit_id": "read:b", "event_index": 2}],
                }, {
                    "slot_rva": 0x3020,
                    "width_bytes": 4,
                    "read_sites": [{"unit_id": "read:a", "event_index": 1}],
                    "origin_witnessed": True,
                }],
            }],
        )

        self.assertEqual(len(requirements), 1)
        self.assertEqual(
            requirements[0].uses[0].read_sites,
            (("read:a", 1), ("read:b", 2)),
        )
        self.assertTrue(requirements[0].uses[0].origin_witnessed)

    def test_nonwritable_and_malformed_requirements_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "not writable image data"):
            derive_recovery_slot_requirements_v2(
                _binary(),
                [{
                    "id": "exit:a",
                    "mutable_slot_dependencies": [{
                        "slot_rva": 0x1010,
                        "width_bytes": 4,
                        "read_sites": [],
                    }],
                }],
            )
        with self.assertRaisesRegex(ValueError, "invalid exact span"):
            derive_recovery_slot_requirements_v2(
                _binary(),
                [{
                    "id": "exit:a",
                    "mutable_slot_dependencies": [{
                        "slot_rva": 0x3020,
                        "width_bytes": 8,
                    }],
                }],
            )


if __name__ == "__main__":
    unittest.main()
