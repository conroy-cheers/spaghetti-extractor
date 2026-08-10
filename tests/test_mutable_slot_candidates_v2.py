from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import cast

from spaghetti_extractor.mutable_slot_candidates_v2 import (
    derive_dependency_scoped_slot_inventory_v2,
    derive_proposal_slot_dependencies,
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

    def test_proposal_slots_seed_only_incomplete_cold_exits(self) -> None:
        proposal = [{
            "slot_rva": 0x3020,
            "exit_id": "exit:a",
            "witness_only": True,
            "proof_authority": False,
        }]

        slot_rvas, dependencies = derive_dependency_scoped_slot_inventory_v2(
            _binary(),
            [{"id": "exit:a", "status": "incomplete"}],
            proposal_dependencies=proposal,
        )
        self.assertEqual(slot_rvas, (0x3020,))
        self.assertEqual(dependencies, tuple(proposal))

        slot_rvas, dependencies = derive_dependency_scoped_slot_inventory_v2(
            _binary(),
            [{
                "id": "exit:a",
                "status": "recovered",
                "mutable_slot_dependencies": [{
                    "slot_rva": 0x3030,
                    "width_bytes": 4,
                    "read_sites": [],
                    "origin_witnessed": True,
                }],
            }],
            proposal_dependencies=proposal,
        )
        self.assertEqual(slot_rvas, (0x3030,))
        self.assertEqual(
            dependencies,
            ({
                "slot_rva": 0x3030,
                "exit_id": "exit:a",
                "witness_only": True,
                "proof_authority": False,
            },),
        )

    def test_proposal_slot_inventory_is_strictly_non_authorizing(self) -> None:
        with self.assertRaisesRegex(ValueError, "malformed"):
            derive_dependency_scoped_slot_inventory_v2(
                _binary(),
                [{"id": "exit:a", "status": "incomplete"}],
                proposal_dependencies=[{
                    "slot_rva": 0x3020,
                    "exit_id": "exit:a",
                    "witness_only": True,
                    "proof_authority": True,
                }],
            )

        with self.assertRaisesRegex(ValueError, "malformed"):
            derive_dependency_scoped_slot_inventory_v2(
                _binary(),
                [{"id": "exit:a", "status": "incomplete"}],
                proposal_dependencies=[{
                    "slot_rva": 0x3020,
                    "exit_id": "exit:a",
                    "witness_only": True,
                    "proof_authority": False,
                    "unchecked_note": "must not survive v2 parsing",
                }],
            )

    def test_contextual_proposal_names_exact_dynamic_read_site(self) -> None:
        dependencies = derive_proposal_slot_dependencies(
            _binary(),
            [{
                "id": "exit:a",
                "status": "recovered",
                "proposal_static_read_addresses": [0x403020, 0x403024],
                "proposal_read_sites": [{
                    "unit_id": "read:cursor",
                    "event_index": 0,
                    "slot_addresses": [0x403020, 0x403024],
                }],
            }],
        )

        self.assertEqual(dependencies, [{
            "slot_rva": 0x3020,
            "exit_id": "exit:a",
            "unit_id": "read:cursor",
            "event_index": 0,
            "proof_authority": False,
        }, {
            "slot_rva": 0x3024,
            "exit_id": "exit:a",
            "unit_id": "read:cursor",
            "event_index": 0,
            "proof_authority": False,
        }])

        slot_rvas, replay_dependencies = (
            derive_dependency_scoped_slot_inventory_v2(
                _binary(),
                [{"id": "exit:a", "status": "incomplete"}],
                proposal_dependencies=dependencies,
            )
        )
        self.assertEqual(slot_rvas, (0x3020, 0x3024))
        self.assertEqual(replay_dependencies, tuple(dependencies))


if __name__ == "__main__":
    unittest.main()
