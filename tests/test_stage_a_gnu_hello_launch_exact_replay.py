from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_launch_exact_replay import (
    GnuHelloLaunchExactReplayError,
    GnuHelloLaunchExactReplayFunction,
    GnuHelloLaunchExactReplayPlan,
    GnuHelloLaunchExactReplaySpec,
    _build_operation_blocks,
    _validate_candidate_data_inventory,
    _validate_exit_coverage,
    gnu_hello_launch_replay_bundle_source,
    gnu_hello_launch_replay_function_source,
    gnu_hello_launch_replay_index_source,
    gnu_hello_launch_replay_inventory_source,
)
from spaghetti_extractor.relational.lean.interpreter_kernel import (
    KernelBlockPlan,
    KernelFunctionPlan,
    KernelInstructionPlan,
)


def _function(
    *,
    entry: int = 100,
    successor: int = 200,
) -> GnuHelloLaunchExactReplayFunction:
    block = KernelBlockPlan(
        entry_rva=entry,
        instructions=(
            KernelInstructionPlan(entry, b"\x55", "push"),
            KernelInstructionPlan(entry + 1, b"\xeb\x61", "jmp"),
        ),
        successors=(successor,),
    )
    plan = KernelFunctionPlan(
        role="test",
        hint="test_function",
        start=entry,
        data=b"\x55\xeb\x61",
        blocks=(block,),
        x87_frames=(),
        x87_commands=(),
        padding=(),
        loops=(),
        frame_required=False,
        frame_push_rva=0,
        frame_setup_rva=0,
        frame_teardown_rvas=(),
        return_rvas=(),
    )
    return GnuHelloLaunchExactReplayFunction(0, plan)


def _plan(function: GnuHelloLaunchExactReplayFunction) -> GnuHelloLaunchExactReplayPlan:
    return GnuHelloLaunchExactReplayPlan(
        spec=GnuHelloLaunchExactReplaySpec(),
        candidate_sha256="1" * 64,
        candidate_size=2,
        candidate_data_inventory_format=(
            "stage-a-interpreter-kernel-data-inventory-v7"
        ),
        candidate_data_module_sha256="2" * 64,
        functions=(function,),
        boundary_targets=(200,),
    )


class StageAGnuHelloLaunchExactReplayTests(unittest.TestCase):
    def test_candidate_data_inventory_must_match_exact_binary(self) -> None:
        candidate = b"candidate"
        digest = hashlib.sha256(candidate).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "module-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "format": (
                            "stage-a-interpreter-kernel-data-inventory-v7"
                        ),
                        "candidate_sha256": digest,
                        "candidate_bytes": len(candidate),
                        "modules": [
                            {
                                "name": "GeneratedInterpreterKernelDataBase",
                                "source_sha256": "3" * 64,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            observed = _validate_candidate_data_inventory(
                inventory,
                candidate_sha256=digest,
                candidate_size=len(candidate),
                candidate_data_module=(
                    "StageA.GeneratedInterpreterKernelDataBase"
                ),
            )
            self.assertEqual(
                observed,
                (
                    "stage-a-interpreter-kernel-data-inventory-v7",
                    "3" * 64,
                ),
            )

            payload = json.loads(inventory.read_text(encoding="utf-8"))
            payload["candidate_sha256"] = "0" * 64
            inventory.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                GnuHelloLaunchExactReplayError,
                "SHA-256 does not match",
            ):
                _validate_candidate_data_inventory(
                    inventory,
                    candidate_sha256=digest,
                    candidate_size=len(candidate),
                    candidate_data_module=(
                        "StageA.GeneratedInterpreterKernelDataBase"
                    ),
                )

    def test_candidate_data_inventory_requires_named_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "module-inventory.json"
            inventory.write_text(
                json.dumps(
                    {
                        "format": (
                            "stage-a-interpreter-kernel-data-inventory-v7"
                        ),
                        "candidate_sha256": "4" * 64,
                        "candidate_bytes": 2,
                        "modules": [],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GnuHelloLaunchExactReplayError,
                "has 0 inventory entries",
            ):
                _validate_candidate_data_inventory(
                    inventory,
                    candidate_sha256="4" * 64,
                    candidate_size=2,
                    candidate_data_module=(
                        "StageA.GeneratedInterpreterKernelDataBase"
                    ),
                )

    def test_uncovered_decoded_exit_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            GnuHelloLaunchExactReplayError,
            "uncovered decoded exit",
        ):
            _validate_exit_coverage((_function(successor=201),), (200,))

    def test_operation_blocks_merge_analyzer_fallthrough(self) -> None:
        function = KernelFunctionPlan(
            role="test",
            hint="test_function",
            start=100,
            data=b"\x89\xc0\xeb\x61",
            blocks=(
                KernelBlockPlan(
                    entry_rva=100,
                    instructions=(
                        KernelInstructionPlan(100, b"\x89\xc0", "mov"),
                    ),
                    successors=(102,),
                ),
                KernelBlockPlan(
                    entry_rva=102,
                    instructions=(
                        KernelInstructionPlan(102, b"\xeb\x61", "jmp"),
                    ),
                    successors=(201,),
                ),
            ),
            x87_frames=(),
            x87_commands=(),
            padding=(),
            loops=(),
            frame_required=False,
            frame_push_rva=0,
            frame_setup_rva=0,
            frame_teardown_rvas=(),
            return_rvas=(),
        )
        blocks = _build_operation_blocks(function)
        self.assertEqual(tuple(block.entry_rva for block in blocks), (100, 102))
        self.assertEqual(
            tuple(row.rva for row in blocks[0].instructions), (100, 102)
        )
        self.assertEqual(blocks[0].successors, (201,))

    def test_direct_call_requires_exact_continuation(self) -> None:
        call = KernelBlockPlan(
            entry_rva=100,
            instructions=(
                KernelInstructionPlan(100, b"\xe8\x00\x00\x00\x00", "call"),
            ),
            successors=(200, 106),
        )
        function = GnuHelloLaunchExactReplayFunction(
            0,
            KernelFunctionPlan(
                role="test",
                hint="test_function",
                start=100,
                data=b"\xe8\x00\x00\x00\x00",
                blocks=(call,),
                x87_frames=(),
                x87_commands=(),
                padding=(),
                loops=(),
                frame_required=False,
                frame_push_rva=0,
                frame_setup_rva=0,
                frame_teardown_rvas=(),
                return_rvas=(),
            ),
        )
        with self.assertRaisesRegex(
            GnuHelloLaunchExactReplayError,
            "exact continuation",
        ):
            _validate_exit_coverage((function,), (200, 106))

    def test_conditional_branch_requires_both_guard_arms(self) -> None:
        branch = KernelBlockPlan(
            entry_rva=100,
            instructions=(
                KernelInstructionPlan(100, b"\x74\x00", "je"),
            ),
            successors=(102, 102),
        )
        function = GnuHelloLaunchExactReplayFunction(
            0,
            KernelFunctionPlan(
                role="test",
                hint="test_function",
                start=100,
                data=b"\x74\x00",
                blocks=(branch,),
                x87_frames=(),
                x87_commands=(),
                padding=(),
                loops=(),
                frame_required=False,
                frame_push_rva=0,
                frame_setup_rva=0,
                frame_teardown_rvas=(),
                return_rvas=(),
            ),
        )
        with self.assertRaisesRegex(
            GnuHelloLaunchExactReplayError,
            "two distinct guard arms",
        ):
            _validate_exit_coverage((function,), (102,))

    def test_function_source_uses_fixed_environment_and_parenthesized_trace(
        self,
    ) -> None:
        function = _function()
        source = gnu_hello_launch_replay_function_source(
            _plan(function), function
        )
        self.assertIn(
            "change checkedNativeOperationBlock\n"
            "      (some (generatedGnuHelloLaunchFunction0000"
            "Block0000RunningTrace "
            "generatedGnuHelloLaunchReplayCheckEnvironment))",
            source,
        )
        self.assertIn("decide +kernel", source)
        for forbidden in ("sorry", "admit", "native_decide", "axiom "):
            self.assertNotIn(forbidden, source)

    def test_control_inventory_is_checked_per_function(self) -> None:
        function = _function()
        plan = _plan(function)
        index_source = gnu_hello_launch_replay_index_source(plan)
        inventory_source = gnu_hello_launch_replay_inventory_source(
            plan, function
        )
        bundle_source = gnu_hello_launch_replay_bundle_source(plan)

        self.assertIn(
            "generatedGnuHelloLaunchReplayEntryRvas : List Nat",
            index_source,
        )
        self.assertIn(
            "checkedExactNativeLaunchControlInventoryAgainstEntries",
            inventory_source,
        )
        self.assertIn(
            "CheckedExactNativeLaunchReplayShard",
            inventory_source,
        )
        self.assertIn(
            "generatedGnuHelloLaunchReplayExact",
            bundle_source,
        )
        self.assertNotIn(
            "checkedNativeOperationGraphClosedWithBoundaries",
            bundle_source,
        )
        self.assertNotIn(
            "checkedExactNativeLaunchControlInventory\n",
            bundle_source,
        )
        for source in (index_source, inventory_source, bundle_source):
            for forbidden in ("sorry", "admit", "native_decide", "axiom "):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
