from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_abi import (
    INTERPRETER_KERNEL_ABI_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_callback import (
    INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_native import (
    INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_lookup_native import (
    build_relational_interpreter_kernel_lookup_native_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_operation import (
    build_relational_interpreter_kernel_program_lookup_operation_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_native import (
    INTERPRETER_KERNEL_STEP_NATIVE_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_INTERFACE_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
    RelationalInterpreterKernelStepOperationGenerationError,
    build_relational_interpreter_kernel_step_operation_plan,
    relational_interpreter_kernel_step_operation_source,
    write_relational_interpreter_kernel_step_operation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_summary import (
    _PROGRAM_LOOKUP_TEMPLATE_BLOCKS,
    _program_lookup_template_bytes,
)
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_target import (
    X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT,
)
from spaghetti_extractor.util import sha256_file


def _program_lookup_function() -> dict[str, object]:
    start = 0x1000
    blob = _program_lookup_template_bytes(0x403020, 0x403000)
    offsets = sorted(
        offset
        for _, _, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        for offset in instructions
    )
    ends = {
        offset: offsets[index + 1] if index + 1 < len(offsets) else len(blob)
        for index, offset in enumerate(offsets)
    }
    return {
        "role": "programLookup",
        "rva_start": start,
        "rva_end": start + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": [
            {
                "entry_rva": start + entry,
                "successors": [start + successor for successor in successors],
                "instructions": [
                    {
                        "rva": start + offset,
                        "bytes": blob[offset : ends[offset]].hex(),
                    }
                    for offset in instructions
                ],
            }
            for entry, successors, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        ],
        "x87_frames": [],
    }


class StageARelationalInterpreterKernelStepOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.kernel = self.root / "interpreter-kernel-plan.json"
        self.data = self.root / "module-inventory.json"
        self.abi = self.root / "interpreter-kernel-abi-plan.json"
        self.callback = self.root / "interpreter-kernel-callback-plan.json"
        self.step = self.root / "interpreter-kernel-step-native-plan.json"
        self.lookup_native = (
            self.root / "interpreter-kernel-lookup-native-plan.json"
        )
        self.lookup_operation = (
            self.root / "interpreter-kernel-program-lookup-operation-plan.json"
        )
        self.invoke = self.root / "interpreter-kernel-invoke-native-plan.json"
        self.x87 = self.root / "x87-replay-bridge-target-plan.json"

        self.candidate.write_bytes(b"exact Step operation fixture" * 19)
        digest = sha256_file(self.candidate)
        size = self.candidate.stat().st_size
        step_function = {
            "role": "interpreterStep",
            "rva_start": 0x2000,
            "rva_end": 0x2080,
            "size": 0x80,
            "sha256": "2" * 64,
            "blocks": [
                {
                    "entry_rva": 0x2000,
                    "successors": [0x1000, 0x2005],
                    "instructions": [{"rva": 0x2000, "bytes": "e8fbffffff"}],
                },
                {
                    "entry_rva": 0x2020,
                    "successors": [0x3000, 0x2025],
                    "instructions": [{"rva": 0x2020, "bytes": "e8db0f0000"}],
                },
                {
                    "entry_rva": 0x2040,
                    "successors": [],
                    "instructions": [{"rva": 0x2040, "bytes": "c3"}],
                },
            ],
            "x87_frames": [],
        }
        invoke_function = {
            "role": "invokeCall",
            "rva_start": 0x3000,
            "rva_end": 0x3040,
            "size": 0x40,
            "sha256": "3" * 64,
            "blocks": [],
            "x87_frames": [],
        }
        kernel = {
            "format": INTERPRETER_KERNEL_PLAN_FORMAT,
            "candidate": {"pe_sha256": digest, "size": size},
            "program": {"transfer_count": 7},
            "kernel_functions": [
                _program_lookup_function(),
                step_function,
                invoke_function,
            ],
            "issues": [],
        }
        data = {
            "format": INTERPRETER_KERNEL_DATA_FORMAT,
            "candidate_sha256": digest,
            "candidate_bytes": size,
            "table_rva": 0x4000,
            "count_rva": 0x4020,
            "counts": {"transfers": 7},
        }
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self.data.write_text(json.dumps(data), encoding="utf-8")
        self.callback.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT,
                    "candidate": {"sha256": digest, "size": size},
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        self.abi.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_ABI_FORMAT,
                    "candidate_pe_sha256": digest,
                    "inputs": {
                        "kernel_plan": {
                            "path": self.kernel.name,
                            "sha256": sha256_file(self.kernel),
                        },
                        "data_inventory": {
                            "path": self.data.name,
                            "sha256": sha256_file(self.data),
                        },
                        "engine_layout": {
                            "path": "engine-layout.bin",
                            "sha256": "0" * 64,
                        },
                    },
                    "candidate_offsets": {
                        "engine_layout": {"start": 0x5000, "size": 64},
                        "program_table": 0x4000,
                        "program_count": 0x4020,
                    },
                    "program_records": 7,
                    "operations": [
                        {
                            "role": "programLookup",
                            "function_index": 0,
                            "image_offset": 0x1000,
                            "return_offsets": [0x10A0],
                        },
                        {
                            "role": "interpreterStep",
                            "function_index": 1,
                            "image_offset": 0x2000,
                            "return_offsets": [0x2040],
                        },
                    ],
                    "failure_mode": "none",
                }
            ),
            encoding="utf-8",
        )
        lookup_native = build_relational_interpreter_kernel_lookup_native_plan(
            kernel_plan=self.kernel,
            data_inventory=self.data,
            candidate_pe=self.candidate,
        )
        self.lookup_native.write_text(
            json.dumps(lookup_native.payload()), encoding="utf-8"
        )
        lookup_operation = (
            build_relational_interpreter_kernel_program_lookup_operation_plan(
                candidate_pe=self.candidate,
                kernel_plan=self.kernel,
                data_inventory=self.data,
                lookup_native_plan=self.lookup_native,
                abi_plan=self.abi,
            )
        )
        self.lookup_operation.write_text(
            json.dumps(lookup_operation.payload()), encoding="utf-8"
        )
        self.step.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_STEP_NATIVE_FORMAT,
                    "candidate": {"sha256": digest, "size": size},
                    "inputs": {
                        "kernel_plan": self.kernel.name,
                        "kernel_plan_sha256": sha256_file(self.kernel),
                        "callback_plan": self.callback.name,
                        "callback_plan_sha256": sha256_file(self.callback),
                    },
                    "function": {
                        "role": "interpreterStep",
                        "rva_start": 0x2000,
                        "rva_end": 0x2080,
                        "sha256": "2" * 64,
                        "blocks": 3,
                        "instructions": 3,
                    },
                    "calls": {
                        "program_lookup": {"offset": 0, "target_rva": 0x1000},
                        "invoke_call": {"offset": 0x20, "target_rva": 0x3000},
                        "direct_helpers": [0x3100, 0x3200],
                        "indirect_sites": [0x2060],
                        "callback_targets": [0x3300],
                    },
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        self.invoke.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT,
                    "candidate": {"sha256": digest, "size": size},
                    "inputs": {
                        "invoke_plan_sha256": sha256_file(self.kernel),
                        "callback_plan_sha256": sha256_file(self.callback),
                    },
                    "invoke": {"entry_rva": 0x3000},
                    "issues": [],
                    "status": "semantic_proof_required",
                }
            ),
            encoding="utf-8",
        )
        self.x87.write_text(
            json.dumps(
                {
                    "format": X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT,
                    "candidate": {
                        "path": self.candidate.name,
                        "sha256": digest,
                        "size": size,
                    },
                    "requested_call_site_rva": 0x3400,
                    "table": {"call_site_rva": 0x3400},
                    "status": "evidence_ready",
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self):
        return build_relational_interpreter_kernel_step_operation_plan(
            candidate_pe=self.candidate,
            kernel_plan=self.kernel,
            data_inventory=self.data,
            abi_plan=self.abi,
            step_native_plan=self.step,
            callback_plan=self.callback,
            lookup_native_plan=self.lookup_native,
            lookup_operation_plan=self.lookup_operation,
            invoke_native_plan=self.invoke,
            x87_replay_plan=self.x87,
        )

    def test_plan_closes_static_authority_and_reports_exact_dynamic_frontiers(
        self,
    ) -> None:
        payload = self._build().payload()

        self.assertEqual(payload["format"], INTERPRETER_KERNEL_STEP_OPERATION_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES),
        )
        self.assertEqual(len(payload["proof_frontiers"]), 6)
        self.assertEqual(
            payload["checked_static_authority"]["program_lookup_call_rva"],
            0x2000,
        )
        self.assertEqual(
            payload["checked_static_authority"]["invoke_call_rva"], 0x2020
        )
        self.assertEqual(
            payload["checked_static_authority"]["callback_target_rva"], 0x3300
        )
        self.assertEqual(payload["result"]["status"], "typed-interface-ready")
        self.assertEqual(len(payload["inputs"]), 10)
        self.assertEqual(
            [
                row["field"]
                for row in payload["checked_native_closure_interfaces"]
            ],
            [
                "programLookupCall",
                "invokeCallRefines",
                "actionLoops",
                "epilogue",
            ],
        )
        self.assertIn(
            "program_lookup_operation_result_extraction",
            payload["closed_components"],
        )
        self.assertIn(
            "exact_native_step_closure_adapters",
            payload["closed_components"],
        )

    def test_source_exposes_checked_request_local_operation_certificate(
        self,
    ) -> None:
        source = relational_interpreter_kernel_step_operation_source(self._build())
        for required in (
            "generatedInterpreterStepOperationStatic",
            "generatedInterpreterStepOperationABIEntry",
            "generatedInterpreterStepProgramLookupOperation",
            "GeneratedInterpreterStepProgramLookupWorldCall",
            "InterpreterStepNativeCheckedProgramLookupFrame",
            "generatedInterpreterStepInvokeCallStatic",
            "generatedInterpreterStepX87ReplayAuthority",
            "GeneratedInterpreterStepActionLoops",
            "GeneratedInterpreterStepEpilogue",
            "GeneratedInterpreterStepCheckedNativeEvidence",
            "GeneratedInterpreterStepExactProgramLookupClosure",
            "GeneratedInterpreterStepExactHelperClosure",
            "GeneratedInterpreterStepCheckedInvokeClosure",
            "GeneratedInterpreterStepExactActionClosure",
            "GeneratedInterpreterStepExactEpilogueClosure",
            "generatedInterpreterStepCheckedNativeEvidenceOfExact",
            "generatedInterpreterStepCheckedCertificate",
            "theorem generatedInterpreterStepOperationRefinesUsing",
            "(environment : NativeWorldEnvironment) (world : RelationalWorld)",
            "InterpreterStepNativeCheckedOperationCertificate",
            "InterpreterStepClosedCallTreeAuthority.ofClosure",
        ):
            self.assertIn(required, source)
        lookup_adapter = source.split(
            "structure GeneratedInterpreterStepProgramLookupWorldCall", 1
        )[1].split(
            "def GeneratedInterpreterStepProgramLookupWorldCall.toAuthority", 1
        )[0]
        self.assertIn("prepare : forall", lookup_adapter)
        self.assertNotIn("lookup : forall", lookup_adapter)
        self.assertNotIn("InterpreterStepNativeLookupPhase", lookup_adapter)
        theorem = source.split(
            "theorem generatedInterpreterStepOperationRefinesUsing", 1
        )[1].split("#print axioms", 1)[0]
        for premise in ("callTree", "native"):
            self.assertIn(f"({premise} :", theorem)
        self.assertIn("invokeCallRefines : forall", source)
        self.assertIn(
            "InterpreterStepNativeFramedRequestLocalInvokeEvidence", source
        )
        self.assertIn(
            "import StageA.RelationalInterpreterKernelStepOperationClosure",
            source,
        )
        self.assertIn("invokeCall.requestLocal derivation", source)
        self.assertNotIn("helpers.toAuthority", source)
        self.assertIn("actionLoops.toAuthority", source)
        self.assertIn("epilogue.toAuthority", source)
        self.assertLess(
            source.index(
                "structure GeneratedInterpreterStepCheckedNativeEvidence"
            ),
            source.index(
                "def generatedInterpreterStepCheckedNativeEvidenceOfExact"
            ),
        )
        self.assertNotIn("GeneratedInterpreterStepInvokeCallSubroutine", source)
        self.assertNotIn("InterpreterStepNativeOperationCertificate.mk", source)
        self.assertEqual(source.count("KernelOperationRefinesUsing"), 1)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_core_composition_consumes_lower_operation_results(self) -> None:
        core = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelStepOperation.lean"
        ).read_text(encoding="utf-8")

        lookup = core.split(
            "noncomputable def "
            "InterpreterStepNativeProgramLookupCallAuthority.lookup",
            1,
        )[1].split(
            "structure InterpreterStepNativeHelperSubroutineAuthority", 1
        )[0]
        self.assertIn("operation.refines eventIdentityNativeEnvironment", lookup)
        self.assertIn("prepared.finish", lookup)

        action = core.split(
            "def InterpreterStepNativeActionLoopAuthority.compose", 1
        )[1].split(
            "structure InterpreterStepNativeCDeclEpilogueAuthority", 1
        )[0]
        self.assertIn("helpers.execute", action)
        self.assertIn("invokeCall.refines", action)
        self.assertNotIn("x87Replay.execute", action)
        static_x87 = core.split(
            "structure InterpreterStepNativeX87ReplayAuthority", 1
        )[1].split("structure InterpreterStepNativeActionLoopAuthority", 1)[0]
        self.assertNotIn("execute :", static_x87)

    def test_rejects_stale_or_nonclosed_inputs(self) -> None:
        payload = json.loads(self.x87.read_text(encoding="utf-8"))
        payload["status"] = "incomplete"
        self.x87.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepOperationGenerationError,
            "checked static evidence",
        ):
            self._build()

        payload["status"] = "evidence_ready"
        self.x87.write_text(json.dumps(payload), encoding="utf-8")
        step = json.loads(self.step.read_text(encoding="utf-8"))
        step["calls"]["program_lookup"]["target_rva"] = 0x1004
        self.step.write_text(json.dumps(step), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepOperationGenerationError,
            "programLookup target",
        ):
            self._build()

    def test_writer_is_deterministic_and_module_names_fail_closed(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "candidate_pe": self.candidate,
            "kernel_plan": self.kernel,
            "data_inventory": self.data,
            "abi_plan": self.abi,
            "step_native_plan": self.step,
            "callback_plan": self.callback,
            "lookup_native_plan": self.lookup_native,
            "lookup_operation_plan": self.lookup_operation,
            "invoke_native_plan": self.invoke,
            "x87_replay_plan": self.x87,
        }
        write_relational_interpreter_kernel_step_operation_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_step_operation_bundle(
            out=second, **kwargs
        )
        self.assertEqual(
            sorted(path.name for path in first.iterdir()),
            sorted(path.name for path in second.iterdir()),
        )
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        interface = (
            first / INTERPRETER_KERNEL_STEP_OPERATION_INTERFACE_LEAN_FILENAME
        ).read_text(encoding="ascii")
        certificate = (
            first / INTERPRETER_KERNEL_STEP_OPERATION_LEAN_FILENAME
        ).read_text(encoding="ascii")
        self.assertNotIn(
            "GeneratedRelationalInterpreterKernelClosedCallTree", interface
        )
        self.assertIn(
            "GeneratedRelationalInterpreterKernelStepOperationInterface",
            certificate,
        )
        self.assertIn(
            "def generatedInterpreterStepCheckedCertificate", certificate
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepOperationGenerationError,
            "ABI module",
        ):
            relational_interpreter_kernel_step_operation_source(
                self._build(), abi_module="Bad.Module"
            )


if __name__ == "__main__":
    unittest.main()
