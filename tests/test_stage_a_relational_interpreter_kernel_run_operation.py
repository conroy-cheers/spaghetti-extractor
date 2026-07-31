from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_abi import (
    INTERPRETER_KERNEL_ABI_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_native import (
    _BLOCK_INSTRUCTION_COUNTS,
    _BLOCK_OFFSETS,
    _LOOP_BODY_OFFSETS,
    _O0_PREFIX,
    _O0_SUFFIX,
    build_relational_interpreter_kernel_run_native_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_ACCEPTANCE_REFINEMENT_THEOREM,
    INTERPRETER_KERNEL_RUN_ENDPOINT_REPLAY_THEOREM,
    INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
    INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES,
    RelationalInterpreterKernelRunOperationGenerationError,
    build_relational_interpreter_kernel_run_operation_plan,
    relational_interpreter_kernel_run_operation_source,
    write_relational_interpreter_kernel_run_operation_bundle,
)
from spaghetti_extractor.util import sha256_file


_RUN_START = 0x1000
_STEP_START = 0x2800


def _rel32(source: int, target: int) -> bytes:
    displacement = (target - (source + 5)) & 0xFFFFFFFF
    return bytes([0xE8]) + displacement.to_bytes(4, "little")


def _canonical_blob() -> bytes:
    return _O0_PREFIX + _rel32(_RUN_START + 91, _STEP_START)[1:] + _O0_SUFFIX


def _run_function() -> dict[str, object]:
    blob = _canonical_blob()
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(blob, _RUN_START))
    blocks: list[dict[str, object]] = []
    for index, offset in enumerate(_BLOCK_OFFSETS):
        stop = (
            _BLOCK_OFFSETS[index + 1]
            if index + 1 < len(_BLOCK_OFFSETS)
            else len(blob)
        )
        instructions = [
            {
                "rva": instruction.address,
                "bytes": bytes(instruction.bytes).hex(),
                "mnemonic": instruction.mnemonic,
            }
            for instruction in decoded
            if _RUN_START + offset <= instruction.address < _RUN_START + stop
        ]
        assert len(instructions) == _BLOCK_INSTRUCTION_COUNTS[index]
        blocks.append(
            {
                "entry_rva": _RUN_START + offset,
                "instructions": instructions,
                "successors": [],
            }
        )
    return {
        "role": "runFunction",
        "rva_start": _RUN_START,
        "rva_end": _RUN_START + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": blocks,
        "loops": [
            {
                "header_rva": _RUN_START + 58,
                "latch_rva": _RUN_START + 321,
                "body_entries": [
                    _RUN_START + value for value in _LOOP_BODY_OFFSETS
                ],
            }
        ],
        "x87_frames": [],
        "x87_commands": [],
        "padding": [],
        "frame": {
            "required": True,
            "push_rva": _RUN_START,
            "setup_rva": _RUN_START + 1,
            "teardown_rvas": [_RUN_START + 335],
            "return_rvas": [_RUN_START + 340],
        },
    }


class StageARelationalInterpreterKernelRunOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.kernel = self.root / "interpreter-kernel-plan.json"
        self.data = self.root / "module-inventory.json"
        self.abi = self.root / "interpreter-kernel-abi-plan.json"
        self.run_native = self.root / "interpreter-kernel-run-native-plan.json"

        self.candidate.write_bytes(b"exact Run operation fixture" * 23)
        digest = sha256_file(self.candidate)
        size = self.candidate.stat().st_size
        kernel = {
            "format": INTERPRETER_KERNEL_PLAN_FORMAT,
            "candidate": {"pe_sha256": digest, "size": size},
            "program": {"transfer_count": 7},
            "kernel_functions": [
                {"role": "interpreterStep", "rva_start": _STEP_START},
                _run_function(),
            ],
            "issues": [
                {
                    "code": "unsupported_indirect_kernel_call",
                    "function_role": "runFunction",
                    "rva_start": _RUN_START + 180,
                    "rva_end": _RUN_START + 182,
                }
            ],
        }
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self.data.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_DATA_FORMAT,
                    "candidate_sha256": digest,
                    "candidate_bytes": size,
                    "counts": {"transfers": 7},
                }
            ),
            encoding="utf-8",
        )
        self.abi.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_ABI_FORMAT,
                    "candidate_pe_sha256": digest,
                    "program_records": 7,
                    "operations": [
                        {
                            "role": "runFunction",
                            "function_index": 1,
                            "image_offset": _RUN_START,
                            "return_offsets": [_RUN_START + 340],
                        }
                    ],
                    "failure_mode": "none",
                }
            ),
            encoding="utf-8",
        )
        run_native = build_relational_interpreter_kernel_run_native_plan(
            kernel_plan=self.kernel, candidate_pe=self.candidate
        )
        self.run_native.write_text(
            json.dumps(run_native.payload()), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self):
        return build_relational_interpreter_kernel_run_operation_plan(
            candidate_pe=self.candidate,
            kernel_plan=self.kernel,
            data_inventory=self.data,
            abi_plan=self.abi,
            run_native_plan=self.run_native,
        )

    def test_plan_binds_static_authority_and_reports_checked_frontiers(
        self,
    ) -> None:
        payload = self._build().payload()

        self.assertEqual(payload["format"], INTERPRETER_KERNEL_RUN_OPERATION_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES),
        )
        self.assertEqual(len(payload["proof_frontiers"]), 4)
        self.assertEqual(
            payload["checked_static_authority"]["step_call_rva"],
            _RUN_START + 91,
        )
        self.assertEqual(
            payload["checked_static_authority"]["resolver_call_rva"],
            _RUN_START + 180,
        )
        self.assertNotIn("status", payload["result"])
        self.assertEqual(len(payload["inputs"]), 5)
        constructor = payload["checked_native_endpoint_constructor"]
        self.assertEqual(
            payload["result"]["checked_endpoint_replay"],
            INTERPRETER_KERNEL_RUN_ENDPOINT_REPLAY_THEOREM,
        )
        self.assertEqual(
            payload["result"]["acceptance_refinement_theorem"],
            INTERPRETER_KERNEL_RUN_ACCEPTANCE_REFINEMENT_THEOREM,
        )
        self.assertEqual(
            constructor["constructor"],
            "RunFunctionNativeCheckedEndpointReplay.ofCanonicalChecked",
        )
        self.assertEqual(
            constructor["lean_type"],
            "RunFunctionNativeCheckedEndpointReplay "
            "(generatedRunFunctionOperationStatic environment)",
        )
        self.assertIn(
            "exact_candidate_function_bytes",
            constructor["derived_facts"],
        )
        self.assertIn(
            "checked_resolver_indirect_target_inventory",
            constructor["derived_facts"],
        )
        self.assertEqual(
            constructor["computed_phase_constructors"],
            [
                "RunFunctionNativeCheckedInternalSegment.terminalPhase",
                "RunFunctionNativeCheckedInternalSegment.directContinuation",
            ],
        )
        self.assertEqual(
            constructor["residual_declarations"],
            [
                "RunFunctionNativeCheckedResultIndexedLocalSemantics.stepCall",
                "RunFunctionNativeCheckedResultIndexedLocalSemantics.unavailableExit",
                "RunFunctionNativeCheckedResultIndexedLocalSemantics.terminalExit",
                "RunFunctionNativeCheckedResultIndexedLocalSemantics.continuation",
                "RunFunctionNativeCheckedEntryAuthority.entry",
                "RunFunctionNativeResultIndexedCDeclSuffixAuthority.suffix",
            ],
        )

    def test_source_exposes_checked_call_tree_certificate(self) -> None:
        source = relational_interpreter_kernel_run_operation_source(self._build())
        for required in (
            "generatedRunFunctionOperationStatic",
            "generatedRunFunctionOperationABIEntry",
            "GeneratedRunFunctionCallTree",
            "GeneratedRunFunctionCheckedLocalSemantics",
            "generatedRunFunctionLoopInvariant",
            "GeneratedRunFunctionCheckedNativeEvidence",
            "generatedRunFunctionOperationFunctionReplay",
            "generatedRunFunctionOperationEndpointReplay",
            "GeneratedRunFunctionResolverTargetInventoryGoal",
            "runFunctionNativeResolverTargetInventoryChecked",
            "generatedRunFunctionResolverTargetInventoryChecked",
            "generatedRunFunctionResolverTargetInventoryGoal",
            "generatedClosedKernelOperationNativeProgram",
            "RunFunctionNativeCheckedEndpointReplay",
            ".ofCanonicalChecked",
            "generatedRunFunctionCheckedCertificate",
            "theorem generatedRunFunctionOperationRefinesUsing",
            "generatedRunFunctionCanonicalContinuationRva",
            "generatedRunFunctionCanonicalReturnAddress",
            "GeneratedRunFunctionCanonicalCheckedNativeEvidence",
            "theorem generatedRunFunctionOperationRefinesUsingCheckedFamily",
            "RunFunctionNativeCheckedResultIndexedOperationCertificate",
            "RunFunctionNativeCheckedResultIndexedLocalSemantics",
            "RunFunctionNativeResultIndexedCDeclSuffixAuthority",
            "RunFunctionClosedCallTreeAuthority.ofClosure",
            "checkedNativeWorldKernelOperationDispatchFamily",
        ):
            self.assertIn(required, source)
        theorem = source.split(
            "theorem generatedRunFunctionOperationRefinesUsing", 1
        )[1].split("#print axioms", 1)[0]
        for premise in ("callTree", "native"):
            self.assertIn(f"({premise} :", theorem)
        self.assertNotIn("GeneratedRunFunctionFrameParametricStep", source)
        self.assertNotIn("InterpreterKernelStepOperation", source)
        self.assertIn(
            "RelationalInterpreterKernelRunOperationResultBridge", source
        )
        self.assertNotIn(
            "(generatedInterpreterStepNativeProgram environment)", source
        )
        self.assertNotIn("RunFunctionNativeOperationCertificate.mk", theorem)
        self.assertIn(
            "GeneratedRunFunctionCheckedLocalSemantics environment", source
        )
        self.assertNotIn(
            "GeneratedRelationalInterpreterKernelRunEntryABI", source
        )
        self.assertNotIn(
            "generatedRunFunctionCheckedEntryAuthority", source
        )
        self.assertNotIn("stepABI := native", source)
        self.assertEqual(source.count("KernelOperationRefinesUsing"), 2)
        acceptance = source.split(
            "theorem generatedRunFunctionOperationRefinesUsingCheckedFamily", 1
        )[1].split("#print axioms", 1)[0]
        self.assertIn(
            "generatedFiniteCheckedSemanticFunctionBindings native",
            acceptance,
        )
        self.assertIn(
            "kernelOperationRefinesUsing_runFunction_mono",
            acceptance,
        )
        self.assertIn(
            "generatedRunFunctionCanonicalContinuationRva",
            acceptance,
        )
        self.assertIn(
            "generatedRunFunctionCanonicalReturnAddress",
            acceptance,
        )
        self.assertNotIn("let continuationRva := 0", acceptance)
        self.assertNotIn("let returnAddress : Word := 0", acceptance)
        endpoint = source.split(
            "def generatedRunFunctionOperationEndpointReplay", 1
        )[1].split("def generatedRunFunctionOperationABIEntry", 1)[0]
        for forbidden in (
            "NonemptyRelatedPath",
            "postState",
            "afterState",
            "CallStatus",
        ):
            self.assertNotIn(forbidden, endpoint)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_stale_native_and_abi_inputs(self) -> None:
        native = json.loads(self.run_native.read_text(encoding="utf-8"))
        native["template"]["entry_rva"] += 1
        self.run_native.write_text(json.dumps(native), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunOperationGenerationError,
            "reviewed template",
        ):
            self._build()

        native["template"]["entry_rva"] -= 1
        self.run_native.write_text(json.dumps(native), encoding="utf-8")
        abi = json.loads(self.abi.read_text(encoding="utf-8"))
        abi["operations"][0]["function_index"] = 0
        self.abi.write_text(json.dumps(abi), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunOperationGenerationError,
            "does not bind",
        ):
            self._build()

    def test_no_step_operation_status_can_enter_run_plan(self) -> None:
        payload = self._build().payload()
        self.assertNotIn("status", payload["result"])
        self.assertEqual(
            payload["remaining_proof_premises"][0],
            "finite_checked_semantic_call_tree",
        )
        self.assertNotIn("step_operation_plan", payload["inputs"])

    def test_writer_is_deterministic_and_module_names_fail_closed(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "candidate_pe": self.candidate,
            "kernel_plan": self.kernel,
            "data_inventory": self.data,
            "abi_plan": self.abi,
            "run_native_plan": self.run_native,
        }
        write_relational_interpreter_kernel_run_operation_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_run_operation_bundle(
            out=second, **kwargs
        )
        self.assertEqual(
            sorted(path.name for path in first.iterdir()),
            sorted(path.name for path in second.iterdir()),
        )
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunOperationGenerationError,
            "Run-native module",
        ):
            relational_interpreter_kernel_run_operation_source(
                self._build(), run_native_module="Bad.Module"
            )


if __name__ == "__main__":
    unittest.main()
