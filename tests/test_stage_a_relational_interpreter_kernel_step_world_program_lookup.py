from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_native_world_bridge import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_operation_instantiation import (
    INTERPRETER_KERNEL_OPERATION_INSTANTIATION_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_world_program_lookup import (
    INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_CERTIFICATE_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_FORMAT,
    INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_REMAINING_PREMISES,
    RelationalInterpreterKernelStepWorldProgramLookupGenerationError,
    build_relational_interpreter_kernel_step_world_program_lookup_plan,
    relational_interpreter_kernel_step_world_program_lookup_source,
    write_relational_interpreter_kernel_step_world_program_lookup_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelStepWorldProgramLookupTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.bridge = self.root / "program-lookup-world.json"
        self.step = self.root / "step-operation.json"
        self.operation = self.root / "operation-instantiation.json"
        self.candidate.write_bytes(b"gnu hello nested frame candidate" * 41)
        self._write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _identity(self) -> dict[str, object]:
        return {
            "sha256": sha256_file(self.candidate),
            "size": self.candidate.stat().st_size,
        }

    def _write_inputs(
        self,
        *,
        step_entry: int = 285378,
        call_site: int = 285402,
        target: int = 285217,
        continuation: int = 285407,
    ) -> None:
        identity = self._identity()
        self.bridge.write_text(
            json.dumps(
                {
                    "format": (
                        INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT
                    ),
                    "operation": "programLookup",
                    "candidate": identity,
                    "checked_static_authority": {
                        "entry_rva": target,
                        "step_call_site_rva": call_site,
                        "step_call_target_rva": target,
                        "step_continuation_rva": continuation,
                    },
                }
            ),
            encoding="utf-8",
        )
        self.step.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
                    "operation": "interpreterStep",
                    "candidate": identity,
                    "checked_static_authority": {"entry_rva": step_entry},
                    "result": {
                        "theorem": INTERPRETER_KERNEL_STEP_OPERATION_THEOREM
                    },
                }
            ),
            encoding="utf-8",
        )
        self.operation.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_OPERATION_INSTANTIATION_FORMAT,
                    "candidate": identity,
                    "checked_native_replay_inventory": {
                        "function_replays": [
                            {
                                "ordinal": 37,
                                "entry_rva": step_entry,
                                "block_graph": [
                                    {
                                        "ordinal": 0,
                                        "entry_rva": step_entry,
                                        "terminal_rva": step_entry + 11,
                                        "terminal_class": "call",
                                        "successors": [292476, step_entry + 16],
                                        "instructions": [
                                            {
                                                "ordinal": index,
                                                "rva": (
                                                    step_entry + 11
                                                    if index == 6
                                                    else step_entry + index
                                                ),
                                                "size": 5 if index == 6 else 1,
                                                "mnemonic": (
                                                    "call"
                                                    if index == 6
                                                    else "mov"
                                                ),
                                            }
                                            for index in range(7)
                                        ],
                                    },
                                    {
                                        "ordinal": 1,
                                        "entry_rva": step_entry + 16,
                                        "terminal_rva": call_site,
                                        "terminal_class": "call",
                                        "successors": [target, continuation],
                                        "instructions": [
                                            {
                                                "ordinal": 0,
                                                "rva": step_entry + 16,
                                                "size": 2,
                                                "mnemonic": "sub",
                                            },
                                            {
                                                "ordinal": 1,
                                                "rva": step_entry + 18,
                                                "size": 3,
                                                "mnemonic": "mov",
                                            },
                                            {
                                                "ordinal": 2,
                                                "rva": step_entry + 21,
                                                "size": 3,
                                                "mnemonic": "mov",
                                            },
                                            {
                                                "ordinal": 3,
                                                "rva": call_site,
                                                "size": 5,
                                                "mnemonic": "call",
                                            },
                                        ],
                                    },
                                ],
                            },
                            {
                                "ordinal": 40,
                                "entry_rva": 292476,
                                "block_graph": [
                                    {
                                        "ordinal": 0,
                                        "entry_rva": 292476,
                                        "terminal_rva": 292487,
                                        "terminal_class": "branch",
                                        "successors": [292489, 292510],
                                        "instructions": [
                                            {
                                                "ordinal": 0,
                                                "rva": 292476,
                                                "size": 1,
                                                "mnemonic": "nop",
                                            }
                                        ],
                                    },
                                    {
                                        "ordinal": 1,
                                        "entry_rva": 292489,
                                        "terminal_rva": 292508,
                                        "terminal_class": "branch",
                                        "successors": [292489, 292510],
                                        "instructions": [
                                            {
                                                "ordinal": 0,
                                                "rva": 292489,
                                                "size": 1,
                                                "mnemonic": "nop",
                                            }
                                        ],
                                    },
                                    {
                                        "ordinal": 2,
                                        "entry_rva": 292510,
                                        "terminal_rva": 292517,
                                        "terminal_class": "return",
                                        "successors": [],
                                        "instructions": [
                                            {
                                                "ordinal": 0,
                                                "rva": 292510,
                                                "size": 1,
                                                "mnemonic": "ret",
                                            }
                                        ],
                                    },
                                ],
                            },
                        ]
                    },
                }
            ),
            encoding="utf-8",
        )

    def _build(self):
        return build_relational_interpreter_kernel_step_world_program_lookup_plan(
            candidate_pe=self.candidate,
            program_lookup_native_world_bridge_plan=self.bridge,
            step_operation_plan=self.step,
            operation_instantiation_plan=self.operation,
        )

    def test_plan_binds_exact_gnu_call_and_reports_one_typed_residual(
        self,
    ) -> None:
        payload = self._build().payload()
        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_FORMAT,
        )
        self.assertEqual(
            payload["checked_static_authority"],
            {
                "step_entry_rva": 285378,
                "step_function_ordinal": 37,
                "step_entry_block_ordinal": 0,
                "step_entry_instruction_count": 7,
                "prefix_kind": "checked_entry_helper",
                "helper_target_rva": 292476,
                "helper_continuation_rva": 285394,
                "helper_function_ordinal": 40,
                "helper_entry_block_ordinal": 0,
                "helper_return_block_ordinal": 2,
                "helper_return_block_rva": 292510,
                "helper_block_ordinals": [0, 1, 2],
                "helper_route_budget": 4096,
                "call_site_rva": 285402,
                "call_block_entry_rva": 285394,
                "call_block_ordinal": 1,
                "call_block_instruction_count": 4,
                "target_rva": 285217,
                "continuation_rva": 285407,
            },
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_REMAINING_PREMISES
            ),
        )
        self.assertEqual(payload["proof_frontiers"], [])
        self.assertTrue(
            payload["result"]["requested_step_theorem_constructed"]
        )
        self.assertEqual(payload["failure_mode"], "none")

    def test_direct_entry_call_needs_no_synthetic_helper_prefix(self) -> None:
        step_entry = 285378
        call_site = step_entry + 11
        continuation = call_site + 5
        target = 285217
        self._write_inputs(
            call_site=call_site,
            target=target,
            continuation=continuation,
        )
        operation = json.loads(self.operation.read_text(encoding="utf-8"))
        step_function = operation["checked_native_replay_inventory"][
            "function_replays"
        ][0]
        entry = step_function["block_graph"][0]
        entry["successors"] = [target, continuation]
        step_function["block_graph"] = [entry]
        self.operation.write_text(json.dumps(operation), encoding="utf-8")

        plan = self._build()
        authority = plan.payload()["checked_static_authority"]
        self.assertEqual(authority["prefix_kind"], "direct_entry_call")
        self.assertIsNone(authority["helper_target_rva"])
        self.assertEqual(authority["helper_block_ordinals"], [])
        source = relational_interpreter_kernel_step_world_program_lookup_source(
            plan
        )
        self.assertNotIn(
            "generatedInterpreterStepEntryHelperCheckedBlocks",
            source,
        )
        self.assertNotIn("BlockFunction0040", source)
        self.assertIn("effect := .programLookupCall", source)
        self.assertIn(
            "generatedInterpreterStepWorldProgramLookupExactCallerComputed",
            source,
        )
        self.assertIn(
            "generatedInterpreterStepWorldProgramLookupCallAuthority",
            source,
        )

    def test_source_uses_per_call_frame_and_never_launch_specializes(
        self,
    ) -> None:
        source = relational_interpreter_kernel_step_world_program_lookup_source(
            self._build()
        )
        for required in (
            "InterpreterStepNativeWorldProgramLookupCallerSetup",
            "GeneratedInterpreterStepWorldProgramLookupExactCaller",
            "generatedInterpreterStepNestedProgramLookupRefines",
            "generatedInterpreterStepWorldProgramLookupCallAuthorityOfExact",
            "GeneratedInterpreterStepWorldExactActionClosure",
            "generatedInterpreterStepWorldCheckedOperationCertificateOfWorldExact",
            "generatedInterpreterStepWorldCheckedOperationCertificateOfExact",
            "generatedInterpreterStepWorldOperationRefinesUsingForAllWorlds",
            "checkedNativeWorldKernelOperationDispatchFamily",
            "generatedConcreteInterpreterKernelABI",
            "(environment : NativeWorldEnvironment) (world : RelationalWorld)",
        ):
            self.assertIn(required, source)
        for suffix in (
            "0037Block0000",
            "0037Block0001",
            "0040Block0000",
            "0040Block0001",
            "0040Block0002",
        ):
            self.assertIn(
                "import StageA."
                "GeneratedRelationalInterpreterKernelOperationBlockFunction"
                f"{suffix}",
                source,
            )
        self.assertNotIn(
            "import StageA."
            "GeneratedRelationalInterpreterKernelOperationBlockFunction0037\n",
            source,
        )
        self.assertNotIn(
            "import StageA."
            "GeneratedRelationalInterpreterKernelOperationBlockFunction0040\n",
            source,
        )
        self.assertIn(
            "generatedInterpreterStepEntryHelperEntryCheckedBlock "
            "environment).entryRva =\n        292476 /\\\n",
            source,
        )
        self.assertNotIn("generatedProgramLookupNativeWorldRefines", source)
        self.assertNotIn("generatedLaunchWorld", source)
        for marker in ("sorry", "axiom", "native_decide", "submittedEndpoint"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_identity_and_call_geometry_fail_closed(self) -> None:
        self._write_inputs(continuation=285408)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepWorldProgramLookupGenerationError,
            "RVAs are inconsistent",
        ):
            self._build()
        self._write_inputs()
        self.candidate.write_bytes(self.candidate.read_bytes() + b"x")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepWorldProgramLookupGenerationError,
            "identity mismatch",
        ):
            self._build()

    def test_unrelated_step_theorem_cannot_authorize_the_binding(self) -> None:
        payload = json.loads(self.step.read_text(encoding="utf-8"))
        payload["result"]["theorem"] = "StageA.Unchecked.step"
        self.step.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepWorldProgramLookupGenerationError,
            "stale or incompatible",
        ):
            self._build()

    def test_ambiguous_checked_replay_fails_closed(self) -> None:
        payload = json.loads(self.operation.read_text(encoding="utf-8"))
        functions = payload["checked_native_replay_inventory"][
            "function_replays"
        ]
        functions.append(dict(functions[0]))
        self.operation.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepWorldProgramLookupGenerationError,
            "Step function replay must identify exactly one",
        ):
            self._build()

    def test_unchecked_call_geometry_in_replay_fails_closed(self) -> None:
        payload = json.loads(self.operation.read_text(encoding="utf-8"))
        call_block = payload["checked_native_replay_inventory"][
            "function_replays"
        ][0]["block_graph"][1]
        call_block["successors"] = [285217, 285408]
        self.operation.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepWorldProgramLookupGenerationError,
            "checked ProgramLookup call block",
        ):
            self._build()

    def test_writer_is_reproducible(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "candidate_pe": self.candidate,
            "program_lookup_native_world_bridge_plan": self.bridge,
            "step_operation_plan": self.step,
            "operation_instantiation_plan": self.operation,
        }
        write_relational_interpreter_kernel_step_world_program_lookup_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_step_world_program_lookup_bundle(
            out=second, **kwargs
        )
        first_files = sorted(
            path.relative_to(first) for path in first.rglob("*")
            if path.is_file()
        )
        second_files = sorted(
            path.relative_to(second) for path in second.rglob("*")
            if path.is_file()
        )
        self.assertEqual(first_files, second_files)
        for relative in first_files:
            self.assertEqual(
                (first / relative).read_bytes(),
                (second / relative).read_bytes(),
            )
        authority = (
            first / INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_LEAN_FILENAME
        ).read_text(encoding="ascii")
        certificate = (
            first
            / INTERPRETER_KERNEL_STEP_WORLD_PROGRAM_LOOKUP_CERTIFICATE_LEAN_FILENAME
        ).read_text(encoding="ascii")
        self.assertIn(
            "GeneratedRelationalInterpreterKernelStepOperationInterface",
            authority,
        )
        self.assertNotIn(
            "abbrev GeneratedInterpreterStepWorldCheckedOperationCertificateFor",
            authority,
        )
        self.assertIn(
            "GeneratedRelationalInterpreterKernelStepWorldProgramLookup",
            certificate,
        )
        self.assertIn(
            "abbrev GeneratedInterpreterStepWorldCheckedOperationCertificateFor",
            certificate,
        )
        self.assertIn(
            "abbrev GeneratedInterpreterStepWorldExactActionClosureFor",
            authority,
        )
        self.assertIn(
            "RelationalInterpreterKernelStepWorldActionSimulation",
            authority,
        )
        self.assertIn(
            "GeneratedInterpreterStepWorldActionSimulationFor",
            authority,
        )
        self.assertIn(
            "generatedInterpreterStepWorldActionLoopsOfSimulationFor",
            authority,
        )
        self.assertIn("actionLoops.toWorld", certificate)


if __name__ == "__main__":
    unittest.main()
