from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_lookup_native import (
    build_relational_interpreter_kernel_lookup_native_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_operation import (
    build_relational_interpreter_kernel_program_lookup_operation_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_call import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_PLAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES,
    RelationalInterpreterKernelStepProgramLookupCallGenerationError,
    build_relational_interpreter_kernel_step_program_lookup_call_plan,
    relational_interpreter_kernel_step_program_lookup_call_source,
    write_relational_interpreter_kernel_step_program_lookup_call_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelStepProgramLookupCallTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        from test_stage_a_relational_interpreter_kernel_step_operation import (
            StageARelationalInterpreterKernelStepOperationTests,
        )

        self.fixture = StageARelationalInterpreterKernelStepOperationTests(
            "test_plan_closes_static_authority_and_reports_exact_dynamic_frontiers"
        )
        self.fixture.setUp()
        self.step_operation = (
            self.fixture.root / "interpreter-kernel-step-operation-plan.json"
        )
        self._install_exact_call_fixture()

    def tearDown(self) -> None:
        self.fixture.tearDown()

    def _install_exact_call_fixture(
        self, instruction_bytes: bytes | None = None
    ) -> None:
        kernel = json.loads(self.fixture.kernel.read_text(encoding="utf-8"))
        call = instruction_bytes or (
            b"\xe8"
            + (0x1000 - (0x2000 + 5)).to_bytes(4, "little", signed=True)
        )
        kernel["kernel_functions"][1]["blocks"][0]["instructions"][0][
            "bytes"
        ] = call.hex()
        self.fixture.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        kernel_hash = sha256_file(self.fixture.kernel)

        abi = json.loads(self.fixture.abi.read_text(encoding="utf-8"))
        abi["inputs"]["kernel_plan"]["sha256"] = kernel_hash
        self.fixture.abi.write_text(json.dumps(abi), encoding="utf-8")

        step = json.loads(self.fixture.step.read_text(encoding="utf-8"))
        step["inputs"]["kernel_plan_sha256"] = kernel_hash
        step["cutpoints"] = [
            {
                "entry_rva": 0x2005,
                "instruction_count": 1,
                "effect": "internal",
                "allowed_rvas": [0x2020],
            }
        ]
        self.fixture.step.write_text(json.dumps(step), encoding="utf-8")

        invoke = json.loads(self.fixture.invoke.read_text(encoding="utf-8"))
        invoke["inputs"]["invoke_plan_sha256"] = kernel_hash
        self.fixture.invoke.write_text(json.dumps(invoke), encoding="utf-8")

        lookup_native = build_relational_interpreter_kernel_lookup_native_plan(
            kernel_plan=self.fixture.kernel,
            data_inventory=self.fixture.data,
            candidate_pe=self.fixture.candidate,
        )
        self.fixture.lookup_native.write_text(
            json.dumps(lookup_native.payload()), encoding="utf-8"
        )
        lookup_operation = (
            build_relational_interpreter_kernel_program_lookup_operation_plan(
                candidate_pe=self.fixture.candidate,
                kernel_plan=self.fixture.kernel,
                data_inventory=self.fixture.data,
                lookup_native_plan=self.fixture.lookup_native,
                abi_plan=self.fixture.abi,
            )
        )
        self.fixture.lookup_operation.write_text(
            json.dumps(lookup_operation.payload()), encoding="utf-8"
        )

        self.step_operation.write_text(
            json.dumps(self.fixture._build().payload()), encoding="utf-8"
        )

    def _kwargs(self) -> dict[str, Path]:
        return {
            "candidate_pe": self.fixture.candidate,
            "kernel_plan": self.fixture.kernel,
            "data_inventory": self.fixture.data,
            "abi_plan": self.fixture.abi,
            "step_native_plan": self.fixture.step,
            "callback_plan": self.fixture.callback,
            "lookup_native_plan": self.fixture.lookup_native,
            "lookup_operation_plan": self.fixture.lookup_operation,
            "invoke_native_plan": self.fixture.invoke,
            "x87_replay_plan": self.fixture.x87,
            "step_operation_plan": self.step_operation,
        }

    def test_plan_closes_static_call_and_reports_only_dynamic_path_premises(
        self,
    ) -> None:
        plan = build_relational_interpreter_kernel_step_program_lookup_call_plan(
            **self._kwargs()
        )
        payload = plan.payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(plan.call_site_rva, 0x2000)
        self.assertEqual(plan.target_rva, 0x1000)
        self.assertEqual(plan.continuation_rva, 0x2005)
        self.assertEqual(plan.instruction_bytes.hex(), "e8fbefffff")
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES),
        )
        self.assertEqual(len(payload["proof_frontiers"]), 3)
        self.assertIn(
            "program_lookup_abi_response_from_closed_operation",
            payload["closed_components"],
        )
        self.assertIn(
            "program_lookup_memory_footprint_from_closed_operation",
            payload["closed_components"],
        )

    def test_source_closes_existing_world_call_from_exact_composition(self) -> None:
        source = relational_interpreter_kernel_step_program_lookup_call_source(
            build_relational_interpreter_kernel_step_program_lookup_call_plan(
                **self._kwargs()
            )
        )

        for required in (
            "generatedInterpreterStepProgramLookupCallSiteParameters",
            "generatedInterpreterStepProgramLookupCallSiteChecked",
            "InterpreterStepProgramLookupCallSiteCertificate",
            "GeneratedInterpreterStepProgramLookupCallComposition",
            "def generatedInterpreterStepProgramLookupWorldCall",
            "GeneratedInterpreterStepProgramLookupWorldCall environment world",
            "generatedInterpreterStepProgramLookupOperation environment",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_a_stale_or_mutated_step_operation_plan(self) -> None:
        submitted = json.loads(self.step_operation.read_text(encoding="utf-8"))
        submitted["checked_static_authority"]["program_lookup_target_rva"] = 0x1004
        self.step_operation.write_text(json.dumps(submitted), encoding="utf-8")

        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupCallGenerationError,
            "does not match the recomputed exact plan",
        ):
            build_relational_interpreter_kernel_step_program_lookup_call_plan(
                **self._kwargs()
            )

    def test_rejects_non_call_bytes_after_all_artifacts_are_rebound(self) -> None:
        self._install_exact_call_fixture(b"\x90" * 5)

        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupCallGenerationError,
            "not a five-byte x86 call rel32",
        ):
            build_relational_interpreter_kernel_step_program_lookup_call_plan(
                **self._kwargs()
            )

    def test_writes_deterministic_plan_and_lean_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            first = write_relational_interpreter_kernel_step_program_lookup_call_bundle(
                out=out, **self._kwargs()
            )
            plan_text = (
                out / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_PLAN_FILENAME
            ).read_text(encoding="utf-8")
            lean_text = (
                out / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_LEAN_FILENAME
            ).read_text(encoding="ascii")
            second = write_relational_interpreter_kernel_step_program_lookup_call_bundle(
                out=out, **self._kwargs()
            )

        self.assertEqual(first, second)
        self.assertEqual(
            json.loads(plan_text),
            first.payload(),
        )
        self.assertEqual(
            lean_text,
            relational_interpreter_kernel_step_program_lookup_call_source(first),
        )

    def test_core_resume_consumes_exact_lower_operation_outputs(self) -> None:
        core = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelStepProgramLookupCall.lean"
        ).read_text(encoding="utf-8")
        caller = core.split(
            "structure InterpreterStepNativeProgramLookupCallerFrame", 1
        )[1].split(
            "def InterpreterStepNativeProgramLookupCallerFrame.lookupPhase", 1
        )[0]

        self.assertIn("prefixPath : InterpreterStepNativePath", caller)
        self.assertIn("callFrameExact", caller)
        self.assertIn("requestRelated", caller)
        self.assertIn("NativeDispatches candidate.pe candidate.imports", caller)
        self.assertIn("abi.responseRelated", caller)
        self.assertIn("MemoryAgreesOutside", caller)
        self.assertIn(
            "InterpreterStepNativeProgramLookupReturnPath",
            caller,
        )
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", core), marker)


if __name__ == "__main__":
    unittest.main()
