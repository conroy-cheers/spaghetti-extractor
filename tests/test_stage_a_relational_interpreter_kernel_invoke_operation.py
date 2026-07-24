from __future__ import annotations

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
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_operation import (
    INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT,
    INTERPRETER_KERNEL_INVOKE_OPERATION_REMAINING_PREMISES,
    RelationalInterpreterKernelInvokeOperationGenerationError,
    build_relational_interpreter_kernel_invoke_operation_plan,
    relational_interpreter_kernel_invoke_operation_source,
    write_relational_interpreter_kernel_invoke_operation_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelInvokeOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.kernel = self.root / "interpreter-kernel-plan.json"
        self.data = self.root / "module-inventory.json"
        self.abi = self.root / "interpreter-kernel-abi-plan.json"
        self.callback = self.root / "interpreter-kernel-callback-plan.json"
        self.invoke = self.root / "interpreter-kernel-invoke-native-plan.json"

        self.candidate.write_bytes(b"exact invoke operation fixture" * 23)
        digest = sha256_file(self.candidate)
        size = self.candidate.stat().st_size
        invoke_blocks = [
            {
                "entry_rva": 0x3000,
                "successors": [0x300C, 0x3016],
                "instructions": [
                    {"rva": 0x3000, "bytes": "55"},
                    {"rva": 0x3001, "bytes": "89e5"},
                ],
            },
            {
                "entry_rva": 0x303E,
                "successors": [0x3043],
                "instructions": [{"rva": 0x303E, "bytes": "e800000000"}],
            },
            {
                "entry_rva": 0x307C,
                "successors": [0x307E],
                "instructions": [{"rva": 0x307C, "bytes": "ffd0"}],
            },
            {
                "entry_rva": 0x309D,
                "successors": [0x30A2],
                "instructions": [{"rva": 0x309D, "bytes": "e800000000"}],
            },
            {
                "entry_rva": 0x30BF,
                "successors": [0x30C4],
                "instructions": [{"rva": 0x30BF, "bytes": "e800000000"}],
            },
            {
                "entry_rva": 0x30C4,
                "successors": [],
                "instructions": [{"rva": 0x30C9, "bytes": "c3"}],
            },
        ]
        kernel = {
            "format": INTERPRETER_KERNEL_PLAN_FORMAT,
            "candidate": {"pe_sha256": digest, "size": size},
            "program": {"transfer_count": 7},
            "kernel_functions": [
                {
                    "role": "runFunction",
                    "rva_start": 0x2000,
                    "rva_end": 0x2080,
                    "size": 0x80,
                    "sha256": "2" * 64,
                    "blocks": [],
                    "x87_frames": [],
                },
                {
                    "role": "invokeCall",
                    "rva_start": 0x3000,
                    "rva_end": 0x30CA,
                    "size": 0xCA,
                    "sha256": "3" * 64,
                    "blocks": invoke_blocks,
                    "x87_frames": [],
                },
                {
                    "role": "helper 16384",
                    "rva_start": 0x4000,
                    "rva_end": 0x4001,
                    "size": 1,
                    "sha256": "4" * 64,
                    "blocks": [
                        {
                            "entry_rva": 0x4000,
                            "successors": [],
                            "instructions": [
                                {"rva": 0x4000, "bytes": "c3"}
                            ],
                        }
                    ],
                    "x87_frames": [],
                },
            ],
            "issues": [],
        }
        data = {
            "format": INTERPRETER_KERNEL_DATA_FORMAT,
            "candidate_sha256": digest,
            "candidate_bytes": size,
            "table_rva": 0x5000,
            "count_rva": 0x5020,
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
                    },
                    "candidate_offsets": {
                        "program_table": 0x5000,
                        "program_count": 0x5020,
                    },
                    "program_records": 7,
                    "operations": [
                        {
                            "role": "invokeCall",
                            "function_index": 1,
                            "image_offset": 0x3000,
                            "return_offsets": [0x30C9],
                        }
                    ],
                    "failure_mode": "none",
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
                    "invoke": {
                        "entry_rva": 0x3000,
                        "run_function_rva": 0x2000,
                        "external_dispatch_rva": 0x4000,
                    },
                    "arms": {
                        "internal": {
                            "call_rva": 0x303E,
                            "continuation_rva": 0x3043,
                        },
                        "indirect": {
                            "resolver_site_rva": 0x307C,
                            "resolver_continuation_rva": 0x307E,
                            "resolver_target_rvas": [0x4100, 0x4200],
                            "run_function_call_rva": 0x309D,
                            "run_function_continuation_rva": 0x30A2,
                        },
                        "external": {
                            "helper_call_rva": 0x30BF,
                            "wrapper_continuation_rva": 0x30C4,
                            "helper_rva": 0x4000,
                        },
                    },
                    "issues": [],
                    "status": "semantic_proof_required",
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self):
        return build_relational_interpreter_kernel_invoke_operation_plan(
            candidate_pe=self.candidate,
            kernel_plan=self.kernel,
            data_inventory=self.data,
            abi_plan=self.abi,
            callback_plan=self.callback,
            invoke_native_plan=self.invoke,
        )

    def test_plan_closes_static_authority_and_reports_dynamic_frontiers(
        self,
    ) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"], INTERPRETER_KERNEL_INVOKE_OPERATION_FORMAT
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_INVOKE_OPERATION_REMAINING_PREMISES),
        )
        self.assertEqual(len(payload["proof_frontiers"]), 5)
        static = payload["checked_static_authority"]
        self.assertEqual(static["entry_rva"], 0x3000)
        self.assertEqual(static["run_function_rva"], 0x2000)
        self.assertEqual(static["resolver_site_rva"], 0x307C)
        self.assertEqual(static["callback_target_rvas"], [0x4100, 0x4200])
        self.assertEqual(
            static["external_helper"],
            {
                "function_index": 2,
                "function_symbol": "generatedKernelFunction0002",
                "entry_rva": 0x4000,
                "end_rva": 0x4001,
                "sha256": "4" * 64,
                "blocks": 1,
                "instructions": 1,
            },
        )
        self.assertEqual(payload["result"]["status"], "typed-interface-ready")

    def test_source_exposes_universal_theorem_with_five_typed_inputs(
        self,
    ) -> None:
        source = relational_interpreter_kernel_invoke_operation_source(
            self._build()
        )
        for required in (
            "generatedInvokeCallOperationTemplateChecked",
            "generatedInvokeCallOperationInstructionDecodes",
            "generatedInvokeCallOperationStatic",
            "generatedInvokeCallOperationABIEntry",
            "generatedInvokeCallExternalHelperChecked",
            "generatedInvokeCallExternalHelperInstructionDecodes",
            "generatedInvokeCallExternalHelperBinding",
            "GeneratedInvokeCallRunFunctionCertificates",
            "RunFunctionNativeOperationCertificate",
            "GeneratedInvokeCallExternalHelperExecution",
            "GeneratedInvokeCallExternalEnvironmentRefinement",
            "generatedInvokeCallExternalArm",
            "GeneratedInvokeCallInternalArm",
            "GeneratedInvokeCallIndirectArm",
            "theorem generatedInvokeCallOperationRefinesUsing",
            "InvokeCallNativeOperationCertificate.mk",
        ):
            self.assertIn(required, source)
        theorem = source.split(
            "theorem generatedInvokeCallOperationRefinesUsing", 1
        )[1].split("#print axioms", 1)[0]
        for premise in (
            "runFunction",
            "externalExecution",
            "externalEnvironment",
            "internal",
            "indirect",
        ):
            self.assertIn(f"({premise} :", theorem)
        self.assertIn(
            "InvokeCallNativeExternalHelperBinding generatedCompiledKernelProgram",
            source,
        )
        self.assertIn(
            "InvokeCallNativeExternalEnvironmentRefinement "
            "generatedCompiledKernelProgram",
            source,
        )
        self.assertNotIn("forall continuationRva returnAddress", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_mismatched_or_unclassified_external_helper(self) -> None:
        kernel = json.loads(self.kernel.read_text(encoding="utf-8"))
        helper = kernel["kernel_functions"][2]
        helper["role"] = "helper 16385"
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self._refresh_dependent_hashes()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeOperationGenerationError,
            "helper role does not bind its exact entry",
        ):
            self._build()

        helper["role"] = "helper 16384"
        helper["blocks"] = []
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self._refresh_dependent_hashes()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeOperationGenerationError,
            "no exact nonempty function body",
        ):
            self._build()

    def _refresh_dependent_hashes(self) -> None:
        kernel_hash = sha256_file(self.kernel)
        abi = json.loads(self.abi.read_text(encoding="utf-8"))
        abi["inputs"]["kernel_plan"]["sha256"] = kernel_hash
        self.abi.write_text(json.dumps(abi), encoding="utf-8")
        invoke = json.loads(self.invoke.read_text(encoding="utf-8"))
        invoke["inputs"]["invoke_plan_sha256"] = kernel_hash
        self.invoke.write_text(json.dumps(invoke), encoding="utf-8")

    def test_rejects_stale_ambiguous_or_unclosed_inputs(self) -> None:
        invoke = json.loads(self.invoke.read_text(encoding="utf-8"))
        invoke["arms"]["indirect"]["resolver_target_rvas"] = [0x4100, 0x4100]
        self.invoke.write_text(json.dumps(invoke), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeOperationGenerationError,
            "finite, nonempty, and unique",
        ):
            self._build()

        invoke["arms"]["indirect"]["resolver_target_rvas"] = [0x4100]
        invoke["status"] = "incomplete"
        self.invoke.write_text(json.dumps(invoke), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeOperationGenerationError,
            "checked static evidence",
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
            "callback_plan": self.callback,
            "invoke_native_plan": self.invoke,
        }
        write_relational_interpreter_kernel_invoke_operation_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_invoke_operation_bundle(
            out=second, **kwargs
        )
        self.assertEqual(
            sorted(path.name for path in first.iterdir()),
            sorted(path.name for path in second.iterdir()),
        )
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeOperationGenerationError,
            "ABI module",
        ):
            relational_interpreter_kernel_invoke_operation_source(
                self._build(), abi_module="Bad.Module"
            )


if __name__ == "__main__":
    unittest.main()
