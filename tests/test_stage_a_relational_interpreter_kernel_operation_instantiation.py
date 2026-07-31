from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_operation import (
    INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_closed_call_tree import (
    INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME,
    INTERPRETER_KERNEL_CLOSED_CALL_TREE_PLAN_FILENAME,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_operation_instantiation import (
    INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE,
    INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX,
    INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE,
    INTERPRETER_KERNEL_OPERATION_CANDIDATE_MODULE,
    INTERPRETER_KERNEL_OPERATION_INSTANTIATION_INVENTORY_FILENAME,
    INTERPRETER_KERNEL_OPERATION_INSTANTIATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_OPERATION_INSTANTIATION_PLAN_FILENAME,
    NativeOperationBlockReplaySpec,
    NativeOperationInstructionReplaySpec,
    RelationalInterpreterKernelOperationInstantiationError,
    _split_native_bulk_boundaries,
    build_relational_interpreter_kernel_operation_instantiation_plan,
    relational_interpreter_kernel_operation_instantiation_source,
    write_relational_interpreter_kernel_operation_instantiation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.candidate = root / "candidate.exe"
        self.candidate.write_bytes(bytes(4096))
        candidate = {
            "sha256": _sha256(self.candidate),
            "size": self.candidate.stat().st_size,
        }

        def function(
            entry: int, end: int, role: str
        ) -> dict[str, object]:
            return {
                "role": role,
                "rva_start": entry,
                "rva_end": end,
                "blocks": [
                    {
                        "rva_start": entry,
                        "instructions": [
                            {"rva": entry, "size": 1, "bytes": "90"}
                        ],
                    }
                ],
            }

        self.kernel_plan = root / "kernel-plan.json"
        _write_json(
            self.kernel_plan,
            {
                "format": INTERPRETER_KERNEL_PLAN_FORMAT,
                "candidate": {
                    "pe_sha256": candidate["sha256"],
                    "size": candidate["size"],
                },
                "kernel_functions": [
                    function(0x2000, 0x2100, "interpreter_step"),
                    function(0x2200, 0x2201, "step_helper"),
                    function(0x2210, 0x2211, "step_helper"),
                    function(0x2300, 0x2301, "step_x87_callback"),
                    function(0x2400, 0x2401, "program_lookup"),
                    function(0x3000, 0x3100, "run_function"),
                    function(0x4000, 0x4100, "invoke_call"),
                    function(0x4300, 0x4301, "invoke_callback"),
                    function(0x4400, 0x4401, "invoke_external_helper"),
                ],
            },
        )
        kernel_digest = _sha256(self.kernel_plan)

        self.state_machine = root / "state-machine.jsonl"
        rows = [
            {
                "original": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1001,
                    "size": 1,
                },
                "external_events": [
                    {
                        "kind": "internal_call",
                        "target_rva": 0x1010,
                        "return_rva": 0x1001,
                    }
                ],
            },
            {
                "original": {
                    "rva_start": 0x1010,
                    "rva_end": 0x1012,
                    "size": 2,
                },
                "external_events": [
                    {
                        "kind": "indirect_call",
                        "target": {"op": "reg", "name": "eax", "width": 32},
                        "return_rva": 0x1012,
                    }
                ],
            },
        ]
        self.state_machine.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        self.data_inventory = root / "module-inventory.json"
        _write_json(
            self.data_inventory,
            {
                "format": "stage-a-interpreter-kernel-data-inventory-v7",
                "state_machine_sha256": _sha256(self.state_machine),
                "shard_size": 1,
                "counts": {"records": 2, "transfers": 2},
            },
        )
        data_digest = _sha256(self.data_inventory)
        self.step = root / "step.json"
        _write_json(
            self.step,
            {
                "format": INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
                "candidate": candidate,
                "inputs": {
                    "kernel_data_inventory": {"sha256": data_digest},
                    "kernel_plan": {"sha256": kernel_digest},
                },
                "checked_static_authority": {
                    "entry_rva": 0x2000,
                    "end_rva": 0x2100,
                    "program_lookup_call_rva": 0x2010,
                    "program_lookup_target_rva": 0x2400,
                    "invoke_call_rva": 0x2020,
                    "invoke_target_rva": 0x4000,
                    "helper_target_rvas": [0x2200, 0x2210],
                    "callback_site_rva": 0x2030,
                    "callback_target_rva": 0x2300,
                },
                "remaining_proof_premises": [
                    "finite_checked_semantic_call_tree",
                    "per_action_loop_chunks",
                ],
            },
        )
        self.run = root / "run.json"
        _write_json(
            self.run,
            {
                "format": INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
                "candidate": candidate,
                "inputs": {
                    "kernel_data_inventory": {"sha256": data_digest},
                    "kernel_plan": {"sha256": kernel_digest},
                },
                "checked_static_authority": {
                    "entry_rva": 0x3000,
                    "end_rva": 0x3100,
                    "loop_header_rva": 0x3010,
                    "completion_dispatch_rva": 0x3020,
                    "step_call_rva": 0x3030,
                    "step_entry_rva": 0x2000,
                    "resolver_call_rva": 0x3040,
                    "epilogue_rva": 0x30F0,
                },
                "remaining_proof_premises": [
                    "finite_checked_semantic_call_tree",
                    "checked_local_step_and_control_paths",
                ],
            },
        )
        self.invoke = root / "invoke.json"
        _write_json(
            self.invoke,
            {
                "format": INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT,
                "candidate": candidate,
                "inputs": {
                    "data_inventory": {"sha256": data_digest},
                    "kernel_plan": {"sha256": kernel_digest},
                    "run_operation_plan": {"sha256": _sha256(self.run)},
                },
                "checked_static_authority": {
                    "entry_rva": 0x4000,
                    "end_rva": 0x4100,
                    "internal_call_rva": 0x4010,
                    "internal_continuation_rva": 0x4015,
                    "resolver_site_rva": 0x4020,
                    "resolver_continuation_rva": 0x4022,
                    "callback_target_rvas": [0x4300],
                    "indirect_run_function_call_rva": 0x4023,
                    "indirect_continuation_rva": 0x4025,
                    "run_function_rva": 0x3000,
                    "external_helper_call_rva": 0x4030,
                    "external_continuation_rva": 0x4035,
                    "external_helper": {"entry_rva": 0x4400},
                },
                "remaining_proof_premises": [
                    "finite_checked_semantic_call_tree",
                    "external_environment_abi_frame_refinement",
                ],
            },
        )

    def kwargs(self) -> dict[str, Path]:
        return {
            "candidate_pe": self.candidate,
            "kernel_plan": self.kernel_plan,
            "state_machine": self.state_machine,
            "data_inventory": self.data_inventory,
            "step_operation_plan": self.step,
            "run_operation_plan": self.run,
            "invoke_operation_plan": self.invoke,
        }


class StageARelationalInterpreterKernelOperationInstantiationTests(
    unittest.TestCase
):
    def test_bulk_instruction_splits_operation_cutpoint_block(self) -> None:
        instructions = (
            NativeOperationInstructionReplaySpec(
                ordinal=0, rva=0x2000, bytes_hex="89f7", mnemonic="mov"
            ),
            NativeOperationInstructionReplaySpec(
                ordinal=1, rva=0x2002, bytes_hex="f3a5",
                mnemonic="rep movsd",
            ),
            NativeOperationInstructionReplaySpec(
                ordinal=2, rva=0x2004, bytes_hex="89c3", mnemonic="mov"
            ),
            NativeOperationInstructionReplaySpec(
                ordinal=3, rva=0x2006, bytes_hex="eb08", mnemonic="jmp"
            ),
        )
        blocks = _split_native_bulk_boundaries((
            NativeOperationBlockReplaySpec(
                ordinal=7,
                entry_rva=0x2000,
                instructions=instructions,
                successors=(0x2010,),
                terminal_class="jump",
            ),
        ))

        self.assertEqual(
            [(block.entry_rva, block.successors, block.terminal_class)
             for block in blocks],
            [
                (0x2000, (0x2004,), "bulk"),
                (0x2004, (0x2010,), "jump"),
            ],
        )
        self.assertEqual(
            [[instruction.ordinal for instruction in block.instructions]
             for block in blocks],
            [[0, 1], [0, 1]],
        )

    def test_bulk_split_interns_identical_overlapping_suffix(self) -> None:
        common_suffix = (
            NativeOperationInstructionReplaySpec(
                ordinal=2, rva=0x2004, bytes_hex="89c3", mnemonic="mov"
            ),
            NativeOperationInstructionReplaySpec(
                ordinal=3, rva=0x2006, bytes_hex="eb08", mnemonic="jmp"
            ),
        )
        overlapping_suffix = tuple(
            replace(instruction, ordinal=index)
            for index, instruction in enumerate(common_suffix)
        )

        blocks = _split_native_bulk_boundaries((
            NativeOperationBlockReplaySpec(
                ordinal=0,
                entry_rva=0x2000,
                instructions=(
                    NativeOperationInstructionReplaySpec(
                        ordinal=0, rva=0x2000, bytes_hex="f3a5",
                        mnemonic="rep movsd",
                    ),
                    *common_suffix,
                ),
                successors=(0x2010,),
                terminal_class="jump",
            ),
            NativeOperationBlockReplaySpec(
                ordinal=1,
                entry_rva=0x2004,
                instructions=overlapping_suffix,
                successors=(0x2010,),
                terminal_class="jump",
            ),
        ))

        suffixes = [block for block in blocks if block.entry_rva == 0x2004]
        self.assertEqual(len(suffixes), 1)
        self.assertEqual(
            [instruction.ordinal for instruction in suffixes[0].instructions],
            [0, 1],
        )

    def test_bulk_split_rejects_conflicting_overlapping_suffix(self) -> None:
        first = NativeOperationBlockReplaySpec(
            ordinal=0,
            entry_rva=0x2000,
            instructions=(
                NativeOperationInstructionReplaySpec(
                    ordinal=0, rva=0x2000, bytes_hex="f3a5",
                    mnemonic="rep movsd",
                ),
                NativeOperationInstructionReplaySpec(
                    ordinal=1, rva=0x2002, bytes_hex="90", mnemonic="nop"
                ),
            ),
            successors=(0x2010,),
            terminal_class="jump",
        )
        conflicting = NativeOperationBlockReplaySpec(
            ordinal=1,
            entry_rva=0x2002,
            instructions=(
                NativeOperationInstructionReplaySpec(
                    ordinal=0, rva=0x2002, bytes_hex="cc", mnemonic="int3"
                ),
            ),
            successors=(0x2010,),
            terminal_class="jump",
        )

        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationInstantiationError,
            "conflicting block entry 0x2002",
        ):
            _split_native_bulk_boundaries((first, conflicting))

    def test_binds_every_record_and_reports_exact_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            plan = (
                build_relational_interpreter_kernel_operation_instantiation_plan(
                    **fixture.kwargs()
                )
            )

        self.assertFalse(plan.constructed)
        self.assertEqual([item.source_rva for item in plan.functions], [0x1000, 0x1010])
        self.assertEqual(
            plan.functions[0].program_record,
            (
                "StageA.GeneratedRelational.InterpreterKernelData."
                "generatedInterpreterKernelSemanticRecordPack0000"
                "Entry0000.record"
            ),
        )
        self.assertEqual(
            plan.functions[1].program_record,
            (
                "StageA.GeneratedRelational.InterpreterKernelData."
                "generatedInterpreterKernelSemanticRecordPack0001"
                "Entry0000.record"
            ),
        )
        payload = plan.payload()
        self.assertFalse(payload["acceptance_authority"])
        self.assertFalse(payload["proof_authority"])
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["remaining_proof_premises"], [])
        locally_closed = replace(plan, endpoint_gaps=()).payload()
        self.assertTrue(locally_closed["result"]["constructed"])
        self.assertEqual(locally_closed["status"], "locally_closed")
        self.assertFalse(locally_closed["acceptance_authority"])
        self.assertFalse(locally_closed["proof_authority"])
        replay = payload["checked_native_replay_inventory"]
        self.assertEqual(replay["functions"], 7)
        self.assertEqual(replay["execution_equalities_submitted"], 0)
        self.assertEqual(replay["path_equalities_submitted"], 0)
        self.assertEqual(replay["post_state_equalities_submitted"], 0)
        routes = payload["checked_native_route_inventory"]
        self.assertEqual(routes["functions"], 7)
        self.assertEqual(routes["blocks"], 7)
        self.assertEqual(routes["edges"], 0)
        self.assertTrue(routes["exact_block_graph_bound"])
        self.assertEqual(
            routes["generic_trace_checker"],
            "CheckedNativeOperationRunningTrace",
        )
        self.assertEqual(
            routes["generic_cutpoint_checker"],
            "CheckedNativeOperationRunningCutpoint",
        )
        self.assertEqual(
            routes["generic_route_checker"],
            "CheckedNativeOperationStateRoute",
        )
        self.assertEqual(
            routes["generic_graph_checker"],
            "CheckedNativeOperationGraphSuccessor",
        )
        self.assertEqual(
            routes["boundary_route_checker"],
            "CheckedNativeOperationStateBoundaryRoute",
        )
        self.assertTrue(routes["boundary_route_checker_imported"])
        self.assertFalse(routes["boundary_route_checker_wired"])
        self.assertTrue(routes["checked_block_certificates_constructed"])
        self.assertTrue(routes["candidate_indirect_targets_wired"])
        self.assertEqual(
            routes["candidate_program"],
            "generatedClosedKernelOperationNativeProgram",
        )
        self.assertEqual(routes["anchors"]["run:loop-header"], 0x3010)
        self.assertEqual(
            routes["specialized_boundary_targets"]["step:program-lookup"],
            [0x2400],
        )
        self.assertEqual(routes["structural_boundary_targets"], [])
        self.assertEqual(
            routes["ranked_route_checker"],
            "checkedNativeOperationRankedRouteCertificate",
        )
        self.assertEqual(len(routes["ranked_route_policies"]), 7)
        self.assertTrue(
            all(
                len(policy["ranks"]) == 1
                for policy in routes["ranked_route_policies"]
            )
        )
        self.assertEqual(len(routes["ranked_route_clusters"]), 7)
        self.assertTrue(
            all(
                cluster["block_rvas"] == [cluster["source_rva"]]
                for cluster in routes["ranked_route_clusters"]
            )
        )
        self.assertEqual(
            payload["result"]["semantic_bindings_term"],
            "generatedFiniteCheckedSemanticFunctionBindings",
        )
        self.assertEqual(
            payload["checked_semantic_inventory"]["call_counts"],
            {"external": 0, "indirect": 1, "internal": 1},
        )
        gaps = {
            gap["id"]: gap for gap in payload["missing_checked_endpoints"]
        }
        self.assertFalse(
            any(identifier.startswith("semantic:") for identifier in gaps)
        )
        self.assertIn("native:run:entry", gaps)
        self.assertIn("native:invoke:external-environment", gaps)
        self.assertIn("native:step:action-loops", gaps)
        self.assertEqual(
            payload["observed_legacy_premises"]["runFunction"],
            [
                "finite_checked_semantic_call_tree",
                "checked_local_step_and_control_paths",
            ],
        )

    def test_bundle_contains_no_replacement_axiom_or_broad_premise(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            out = root / "out"
            plan = write_relational_interpreter_kernel_operation_instantiation_bundle(
                out=out, **fixture.kwargs()
            )
            payload = json.loads(
                (
                    out
                    / INTERPRETER_KERNEL_OPERATION_INSTANTIATION_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            )
            inventory = json.loads(
                (
                    out
                    / INTERPRETER_KERNEL_OPERATION_INSTANTIATION_INVENTORY_FILENAME
                ).read_text(encoding="utf-8")
            )
            source = (
                out
                / "StageA"
                / INTERPRETER_KERNEL_OPERATION_INSTANTIATION_LEAN_FILENAME
            ).read_text(encoding="ascii")
            block_source = (
                out
                / "StageA"
                / (
                    f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
                    "0000.lean"
                )
            ).read_text(encoding="ascii")
            function_core_source = (
                out
                / "StageA"
                / (
                    f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
                    "0000Core.lean"
                )
            ).read_text(encoding="ascii")
            individual_block_source = (
                out
                / "StageA"
                / (
                    f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
                    "0000Block0000.lean"
                )
            ).read_text(encoding="ascii")
            block_bundle_source = (
                out
                / "StageA"
                / f"{INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE}.lean"
            ).read_text(encoding="ascii")
            candidate_source = (
                out
                / "StageA"
                / f"{INTERPRETER_KERNEL_OPERATION_CANDIDATE_MODULE}.lean"
            ).read_text(encoding="ascii")
            candidate_core_source = (
                out
                / "StageA"
                / f"{INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE}.lean"
            ).read_text(encoding="ascii")
            closure_payload = json.loads(
                (
                    out / INTERPRETER_KERNEL_CLOSED_CALL_TREE_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            )
            closure_source = (
                out
                / "StageA"
                / INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME
            ).read_text(encoding="ascii")

        self.assertEqual(payload, plan.payload())
        self.assertEqual(inventory["count"], 2)
        self.assertEqual(payload["remaining_proof_premises"], [])
        self.assertEqual(closure_payload["remaining_proof_premises"], [])
        self.assertEqual(len(closure_payload["functions"]), 2)
        self.assertIn(
            "generatedFiniteCheckedSemanticFunctionBindings",
            closure_source,
        )
        self.assertIn("generatedSemanticFunctionBindings", source)
        self.assertIn("generatedSemanticCallTreeClosure", source)
        self.assertIn(
            "generatedClosedInterpreterStepOperationStatic", source
        )
        self.assertIn(
            "generatedClosedRunFunctionOperationStatic", source
        )
        self.assertIn(
            "generatedClosedInvokeCallOperationStatic", source
        )
        self.assertIn(
            f"StageA.{INTERPRETER_KERNEL_OPERATION_BLOCK_BUNDLE_MODULE}",
            source,
        )
        self.assertIn(
            "CheckedNativeOperationFunctionReplay\n", function_core_source
        )
        self.assertIn(
            "generatedNativeOperationFunctionReplay0000", function_core_source
        )
        self.assertIn(
            "generatedClosedKernelOperationNativeProgram",
            function_core_source,
        )
        self.assertIn(
            f"StageA.{INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE}",
            function_core_source,
        )
        self.assertNotIn(
            "GeneratedRelationalInterpreterKernelFunction",
            function_core_source,
        )
        self.assertIn("instructions := [", individual_block_source)
        self.assertIn("successors := [", individual_block_source)
        self.assertIn(
            (
                "import StageA."
                f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
                "0000Core"
            ),
            block_source,
        )
        self.assertIn(
            (
                "import StageA."
                f"{INTERPRETER_KERNEL_OPERATION_BLOCK_FUNCTION_PREFIX}"
                "0000Block0000"
            ),
            block_source,
        )
        self.assertNotIn(
            "canonicalNativeOperationInstructionCheckedStatic",
            block_source,
        )
        self.assertIn(
            "ExactNativeWorldProgram :=\n  {",
            candidate_core_source,
        )
        self.assertIn(
            "generatedInterpreterKernelCandidatePe",
            candidate_core_source,
        )
        self.assertIn(
            "generatedNativeIndirectTargetInventory",
            candidate_core_source,
        )
        self.assertNotIn(
            "GeneratedRelationalInterpreterKernelStepNative",
            candidate_core_source,
        )
        self.assertIn(
            "generatedClosedKernelOperationIndirectTargetsValid",
            candidate_core_source,
        )
        self.assertIn(
            "generatedClosedKernelOperationCallbackBinding",
            candidate_source,
        )
        self.assertIn(
            f"StageA.{INTERPRETER_KERNEL_OPERATION_CANDIDATE_CORE_MODULE}",
            candidate_source,
        )
        self.assertNotIn(
            "GeneratedRelationalInterpreterKernelStepNative",
            candidate_source,
        )
        self.assertIn(
            "generatedNativeOperationFunctionReplay0000Block0000Checked",
            individual_block_source,
        )
        self.assertIn(
            "generatedNativeOperationFunctionReplay0000Block0000Proof",
            individual_block_source,
        )
        self.assertIn(
            "RelationalInterpreterKernelOperationRouteChecker", source
        )
        self.assertIn(
            "RelationalInterpreterKernelOperationBoundaryChecker", source
        )
        self.assertIn(
            "RelationalInterpreterKernelOperationStateBoundaryChecker", source
        )
        self.assertIn(
            "RelationalInterpreterKernelOperationStateRouteChecker", source
        )
        self.assertIn("generatedNativeOperationRouteAnchors", source)
        self.assertIn("generatedNativeOperationBoundaryTargets", source)
        self.assertIn(
            "canonicalNativeOperationInstructionCheckedStatic",
            individual_block_source,
        )
        self.assertIn(".ofCanonicalStaticChecked", individual_block_source)
        self.assertIn(
            "canonicalNativeOperationInstructionBehaviorStatic",
            individual_block_source,
        )
        self.assertIn("BehaviorExact", individual_block_source)
        self.assertIn("TerminalOutcomeExact", individual_block_source)
        self.assertIn("checked := by rfl", individual_block_source)
        self.assertIn(
            "generatedNativeOperationCheckedBlockCountExact",
            block_bundle_source,
        )
        self.assertIn(
            "generatedNativeOperationCheckedBlockEntriesNodup",
            block_bundle_source,
        )
        self.assertIn(
            "RelationalInterpreterKernelOperationRankedStateRoute",
            block_bundle_source,
        )
        self.assertIn(
            "generatedNativeOperationFunctionReplay0000RankedRouteCluster0000Checked",
            block_bundle_source,
        )
        self.assertIn(
            "checkedNativeOperationRankedRouteCertificate_sound",
            block_bundle_source,
        )
        self.assertIn(
            "RelationalInterpreterKernelOperationGraphChecker", source
        )
        self.assertNotIn("Uninhabited", source)
        self.assertNotIn("\naxiom ", source)
        self.assertNotIn("\nsorry", source)

    def test_rejects_stale_state_machine_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            fixture.state_machine.write_text(
                fixture.state_machine.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RelationalInterpreterKernelOperationInstantiationError,
                "not bound to the exact state machine",
            ):
                build_relational_interpreter_kernel_operation_instantiation_plan(
                    **fixture.kwargs()
                )

    def test_generated_source_rejects_non_stage_a_data_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            plan = (
                build_relational_interpreter_kernel_operation_instantiation_plan(
                    **fixture.kwargs()
                )
            )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationInstantiationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_operation_instantiation_source(
                plan, data_module="Untrusted.GeneratedData"
            )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationInstantiationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_operation_instantiation_source(
                plan, native_module="Untrusted.GeneratedNative"
            )

    def test_rejects_noncontiguous_native_block_instructions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            payload = json.loads(
                fixture.kernel_plan.read_text(encoding="utf-8")
            )
            payload["kernel_functions"][0]["blocks"][0]["instructions"].append(
                {"rva": 0x2002, "size": 1, "bytes": "90"}
            )
            _write_json(fixture.kernel_plan, payload)
            kernel_digest = _sha256(fixture.kernel_plan)
            for operation in (fixture.step, fixture.run, fixture.invoke):
                operation_payload = json.loads(
                    operation.read_text(encoding="utf-8")
                )
                operation_payload["inputs"]["kernel_plan"]["sha256"] = (
                    kernel_digest
                )
                _write_json(operation, operation_payload)
            invoke_payload = json.loads(
                fixture.invoke.read_text(encoding="utf-8")
            )
            invoke_payload["inputs"]["run_operation_plan"]["sha256"] = (
                _sha256(fixture.run)
            )
            _write_json(fixture.invoke, invoke_payload)

            with self.assertRaisesRegex(
                RelationalInterpreterKernelOperationInstantiationError,
                "is not contiguous",
            ):
                build_relational_interpreter_kernel_operation_instantiation_plan(
                    **fixture.kwargs()
                )


if __name__ == "__main__":
    unittest.main()
