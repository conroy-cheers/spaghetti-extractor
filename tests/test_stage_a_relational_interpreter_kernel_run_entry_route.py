from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_run_entry_route import (
    InterpreterKernelRunEntryRouteError,
    build_run_entry_route,
    run_entry_route_lean_source,
    write_run_entry_route_bundle,
)


def _manifest() -> dict[str, object]:
    def instructions(start: int) -> list[dict[str, int]]:
        return [
            {"ordinal": 0, "rva": start, "size": 1},
            {"ordinal": 1, "rva": start + 1, "size": 1},
        ]

    return {
        "format": (
            "stage-a-relational-interpreter-kernel-operation-instantiation-v1"
        ),
        "candidate": {"sha256": "a" * 64, "size": 4096},
        "checked_native_replay_inventory": {
            "function_replays": [
                {
                    "ordinal": 7,
                    "entry_rva": 0x1000,
                    "role": "runFunction",
                    "families": ["run"],
                    "block_graph": [
                        {
                            "ordinal": 0,
                            "entry_rva": 0x1000,
                            "terminal_class": "branch",
                            "successors": [0x1010, 0x1020],
                            "instructions": instructions(0x1000),
                        },
                        {
                            "ordinal": 1,
                            "entry_rva": 0x1010,
                            "terminal_class": "jump",
                            "successors": [0x1020],
                            "instructions": instructions(0x1010),
                        },
                        {
                            "ordinal": 2,
                            "entry_rva": 0x1020,
                            "terminal_class": "bulk",
                            "successors": [0x1030],
                            "instructions": instructions(0x1020),
                        },
                        {
                            "ordinal": 3,
                            "entry_rva": 0x1030,
                            "terminal_class": "call",
                            "successors": [0x2000, 0x1040],
                            "instructions": instructions(0x1030),
                        },
                    ],
                }
            ]
        },
    }


class RunEntryRouteTests(unittest.TestCase):
    def _write_manifest(
        self, root: Path, payload: dict[str, object]
    ) -> Path:
        path = root / "operation.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_generates_checked_unique_route(self) -> None:
        payload = _manifest()
        # Only the direct branch reaches the bulk block. The other branch is a
        # checked error path outside this successful Run-entry prefix.
        blocks = payload["checked_native_replay_inventory"]["function_replays"][
            0
        ]["block_graph"]
        blocks[1]["successors"] = [0x9000]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            route = build_run_entry_route(
                self._write_manifest(root, payload)
            )
            self.assertEqual(
                [block.entry_rva for block in route.controls], [0x1000]
            )
            self.assertEqual(route.bulk.entry_rva, 0x1020)
            self.assertEqual(route.loop.entry_rva, 0x1030)
            source = run_entry_route_lean_source(route)
            self.assertIn(
                "generatedNativeOperationFunctionReplay0007Block0000Proof",
                source,
            )
            for ordinal in (0, 2, 3):
                self.assertIn(
                    "import StageA."
                    "GeneratedRelationalInterpreterKernelOperation"
                    f"BlockFunction0007Block{ordinal:04d}",
                    source,
                )
            self.assertNotIn(
                "import StageA."
                "GeneratedRelationalInterpreterKernelOperation"
                "BlockFunction0007\n",
                source,
            )
            self.assertIn(
                "generatedRunEntryControlRouteChecked",
                source,
            )
            self.assertIn(
                "generatedNativeOperationFunctionReplay0007Block0000"
                "RunningBehaviors",
                source,
            )
            self.assertIn(".runningStaticPullback", source)
            self.assertNotIn(".runningPullback", source)
            self.assertNotIn("def generatedRunEntryStep1", source)
            self.assertIn("def generatedRunEntryBulkStep", source)
            self.assertIn(
                "theorem generatedRunEntryBulkTerminalInvariantTrivial",
                source,
            )
            self.assertIn("generatedRunEntryToLoopPath", source)
            self.assertIn(
                "generatedNativeOperationFunctionReplay0007Block0002"
                "TerminalOutcome",
                source,
            )
            self.assertIn(
                "(generatedRunEntryBlock2 environment)\n"
                "      (fun _ => True)",
                source,
            )
            self.assertNotIn(
                "generatedRunEntryInvariant0\n"
                "    (environment : NativeWorldEnvironment)",
                source,
            )
            self.assertNotIn("set_option linter.unusedSimpArgs false", source)

    def test_ambiguous_route_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(
                InterpreterKernelRunEntryRouteError, "absent or ambiguous"
            ):
                build_run_entry_route(
                    self._write_manifest(root, _manifest())
                )

    def test_writes_machine_readable_manifest_and_lean(self) -> None:
        payload = _manifest()
        blocks = payload["checked_native_replay_inventory"]["function_replays"][
            0
        ]["block_graph"]
        blocks[1]["successors"] = [0x9000]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "out"
            write_run_entry_route_bundle(
                operation_manifest=self._write_manifest(root, payload),
                out=output,
            )
            report = json.loads(
                (output / "interpreter-kernel-run-entry-route.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["status"], "locally_closed")
            self.assertFalse(report["proof_authority"])
            self.assertTrue(
                (
                    output
                    / "StageA"
                    / "GeneratedRelationalInterpreterKernelRunEntryRoute.lean"
                ).is_file()
            )
            request = json.loads(
                (
                    output
                    / "interpreter-kernel-run-entry-behavior-request.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(request["binary_sha256"], "a" * 64)
            self.assertEqual(len(request["regions"]), 4)


if __name__ == "__main__":
    unittest.main()
