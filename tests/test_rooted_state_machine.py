from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.rooted_state_machine import (
    _manifest_seed_roots,
    _merge_roots,
    _rooted_direct_reachability,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _row(
    identity: str,
    rva: int,
    outcome: dict,
    *,
    events: list[dict] | None = None,
    terminating: bool = False,
) -> dict:
    row = {
        "id": identity,
        "original": {"rva_start": rva, "rva_end": rva + 1},
        "outcome": outcome,
        "external_events": list(events or []),
    }
    if terminating:
        row["control_disposition"] = {
            "kind": "terminates_after_external_event",
            "authority": "test",
        }
    return row


class RootedDirectControlTests(unittest.TestCase):
    def test_ignores_missing_targets_from_unreachable_linear_views(self) -> None:
        rows = [
            _row("root", 0x1000, {"kind": "jump", "target_rva": 0x1200}),
            _row(
                "unreachable",
                0x2000,
                {"kind": "jump", "target_rva": 0x2100},
            ),
        ]

        result = _rooted_direct_reachability(
            rows, [{"kind": "pe_entrypoint", "rva": 0x1000}]
        )

        self.assertEqual(result["reachable_transfer_rvas"], [0x1000])
        self.assertEqual(result["missing_target_rvas"], [0x1200])

    def test_materialized_target_closes_rooted_direct_control(self) -> None:
        rows = [
            _row("root", 0x1000, {"kind": "jump", "target_rva": 0x1200}),
            _row("target", 0x1200, {"kind": "return"}),
        ]

        result = _rooted_direct_reachability(
            rows, [{"kind": "pe_entrypoint", "rva": 0x1000}]
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["reachable_transfer_rvas"], [0x1000, 0x1200])
        self.assertEqual(result["missing_target_rvas"], [])

    def test_internal_call_is_direct_and_indirect_call_remains_a_frontier(self) -> None:
        rows = [
            _row(
                "root",
                0x1000,
                {"kind": "fallthrough", "target_rva": 0x1100},
                events=[
                    {"kind": "internal_call", "target_rva": 0x1200},
                    {"kind": "indirect_call", "target": {"op": "reg", "name": "eax"}},
                ],
            ),
            _row("continuation", 0x1100, {"kind": "return"}),
            _row("callee", 0x1200, {"kind": "return"}),
        ]

        result = _rooted_direct_reachability(
            rows, [{"kind": "pe_entrypoint", "rva": 0x1000}]
        )

        self.assertEqual(
            result["reachable_transfer_rvas"], [0x1000, 0x1100, 0x1200]
        )
        self.assertEqual(result["counts"]["indirect_frontiers"], 1)

    def test_no_return_import_does_not_reach_its_linear_continuation(self) -> None:
        rows = [
            _row(
                "exit",
                0x1000,
                {"kind": "fallthrough", "target_rva": 0x1100},
                terminating=True,
            )
        ]

        result = _rooted_direct_reachability(
            rows, [{"kind": "pe_entrypoint", "rva": 0x1000}]
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["missing_target_rvas"], [])

    def test_malformed_internal_call_target_fails_closed(self) -> None:
        rows = [
            _row(
                "root",
                0x1000,
                {"kind": "return"},
                events=[{"kind": "internal_call", "target_rva": "0x1200"}],
            )
        ]

        with self.assertRaisesRegex(StageAInputError, "internal call target"):
            _rooted_direct_reachability(
                rows, [{"kind": "pe_entrypoint", "rva": 0x1000}]
            )

    def test_manifest_seeds_only_rooted_unmaterialized_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(_manifest()), encoding="utf-8")

            roots = _manifest_seed_roots(
                path,
                state_machine_sha256="1" * 64,
                original_sha256="2" * 64,
                reference_sha256="3" * 64,
                materialized_rvas={0x1000, 0x1100},
            )

        self.assertEqual([root["rva"] for root in roots], [0x1200, 0x1300])
        self.assertEqual(
            [root["kind"] for root in roots],
            [
                "provenance_recovered_direct_target",
                "provenance_recovered_indirect_target",
            ],
        )

    def test_manifest_binding_tampering_fails_closed(self) -> None:
        manifest = _manifest()
        manifest["inputs"]["state_machine"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(StageAInputError, "state machine binding"):
                _manifest_seed_roots(
                    path,
                    state_machine_sha256="1" * 64,
                    original_sha256="2" * 64,
                    reference_sha256="3" * 64,
                    materialized_rvas=set(),
                )

    def test_binary_root_takes_precedence_over_proposal_metadata(self) -> None:
        roots = _merge_roots(
            [{"kind": "pe_entrypoint", "rva": 0x1000}],
            [
                {
                    "kind": "provenance_recovered_behavioral_root",
                    "rva": 0x1000,
                },
                {
                    "kind": "provenance_recovered_direct_target",
                    "rva": 0x1200,
                },
            ],
        )

        self.assertEqual(
            roots,
            [
                {"kind": "pe_entrypoint", "rva": 0x1000},
                {
                    "kind": "provenance_recovered_direct_target",
                    "rva": 0x1200,
                },
            ],
        )


def _manifest() -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "inputs": {
            "state_machine": {"sha256": "1" * 64},
            "original_pe": {"sha256": "2" * 64},
            "reference_contract": {"sha256": "3" * 64},
        },
        "binary": {"sha256": "2" * 64},
        "source_map": [
            {"unit_id": "root", "rva_start": 0x1000},
            {"unit_id": "known", "rva_start": 0x1100},
            {"unit_id": "unreachable", "rva_start": 0x2000},
        ],
        "control": {
            "roots": [
                {"kind": "pe_entrypoint", "rva": 0x1000},
                {"kind": "callback", "rva": 0x1100},
            ],
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
                },
                {
                    "source_unit_id": "unreachable",
                    "status": "recovered",
                    "target_rvas": [0x2200],
                },
                {
                    "source_unit_id": "root",
                    "status": "incomplete",
                    "target_rvas": [0x1400],
                },
            ],
        },
    }


if __name__ == "__main__":
    unittest.main()
