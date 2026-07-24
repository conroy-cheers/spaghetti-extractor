from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    INTERPRETER_MIXED_ORIGINAL_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original_static_reachability import (
    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_FORMAT,
    InterpreterMixedOriginalStaticReachabilityGenerationError,
    build_interpreter_mixed_original_static_reachability_plan,
    interpreter_mixed_original_static_reachability_source,
    write_interpreter_mixed_original_static_reachability_bundle,
)


class StageARelationalInterpreterMixedOriginalStaticReachabilityTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plan_path = self.root / "interpreter-mixed-original-plan.json"
        self.payload = {
            "format": INTERPRETER_MIXED_ORIGINAL_FORMAT,
            "state_machine_sha256": "a" * 64,
            "counts": {
                "reachable_targets": 3,
                "reachable_missing_successors": 0,
                "blockers": 2,
            },
            "reachable_target_ids": [1, 2, 5],
            "blockers": [
                {"reason_code": "unresolved_indirect_control", "rva": 7},
                {"reason_code": "unresolved_indirect_control", "rva": 9},
            ],
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.plan_path.write_text(json.dumps(self.payload), encoding="utf-8")

    def test_static_certificate_keeps_runtime_frontiers_explicit(self) -> None:
        plan = build_interpreter_mixed_original_static_reachability_plan(
            mixed_original_plan=self.plan_path
        )
        payload = plan.payload()
        self.assertEqual(
            payload["format"],
            INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["scope"], "decoded-direct-successors-only")
        self.assertEqual(payload["counts"]["runtime_indirect_frontiers"], 2)
        self.assertEqual(
            payload["runtime_indirect_control"],
            {
                "status": "incomplete",
                "closed_by_this_artifact": False,
                "required_at": "mixed-component-composition",
            },
        )
        source = interpreter_mixed_original_static_reachability_source(plan)
        self.assertIn(
            "exactOriginalDecodedReachabilityOfCheckedStaticInventory", source
        )
        self.assertIn("generatedOriginalReachabilityInventoryChecked", source)
        for forbidden in ("axiom ", "sorry", "native_decide", "runtimeClosure"):
            self.assertNotIn(forbidden, source)

    def test_missing_static_successor_and_stale_counts_fail_closed(self) -> None:
        self.payload["counts"]["reachable_missing_successors"] = 1
        self._write()
        with self.assertRaisesRegex(
            InterpreterMixedOriginalStaticReachabilityGenerationError,
            "missing decoded successors",
        ):
            build_interpreter_mixed_original_static_reachability_plan(
                mixed_original_plan=self.plan_path
            )

        self.payload["counts"]["reachable_missing_successors"] = 0
        self.payload["counts"]["blockers"] = 1
        self._write()
        with self.assertRaisesRegex(
            InterpreterMixedOriginalStaticReachabilityGenerationError,
            "blocker count is stale",
        ):
            build_interpreter_mixed_original_static_reachability_plan(
                mixed_original_plan=self.plan_path
            )

    def test_inventory_must_be_sorted_unique_and_nonempty(self) -> None:
        for values in ([2, 1], [1, 1], []):
            with self.subTest(values=values):
                self.payload["reachable_target_ids"] = values
                self.payload["counts"]["reachable_targets"] = len(values)
                self._write()
                with self.assertRaises(
                    InterpreterMixedOriginalStaticReachabilityGenerationError
                ):
                    build_interpreter_mixed_original_static_reachability_plan(
                        mixed_original_plan=self.plan_path
                    )

    def test_writer_is_reproducible(self) -> None:
        out = self.root / "out"
        first = write_interpreter_mixed_original_static_reachability_bundle(
            mixed_original_plan=self.plan_path,
            out=out,
        )
        before = {path.name: path.read_bytes() for path in out.iterdir()}
        second = write_interpreter_mixed_original_static_reachability_bundle(
            mixed_original_plan=self.plan_path,
            out=out,
        )
        after = {path.name: path.read_bytes() for path in out.iterdir()}
        self.assertEqual(first, second)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
