from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_call_closure import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_exact_computation import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_DERIVED,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_FORMAT,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_REMAINING,
    RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError,
    build_relational_interpreter_kernel_step_program_lookup_exact_computation_plan,
    relational_interpreter_kernel_step_program_lookup_exact_computation_source,
    write_relational_interpreter_kernel_step_program_lookup_exact_computation_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelStepProgramLookupExactComputationTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.closure = self.root / "closure.json"
        self.candidate.write_bytes(b"generic exact computation" * 19)
        self.payload = {
            "format": (
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT
            ),
            "acceptance_authority": False,
            "operation": "interpreterStep.programLookupCall",
            "candidate": {
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "inputs": {
                "candidate": {
                    "path": "candidate.exe",
                    "sha256": sha256_file(self.candidate),
                },
                "program_lookup_call_plan": {
                    "path": "call-plan.json",
                    "sha256": "0" * 64,
                },
            },
            "checked_static_authority": {
                "call_site_rva": 0x2300,
                "call_block_rva": 0x22F0,
                "target_rva": 0x1800,
                "continuation_rva": 0x2305,
            },
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES
            ),
            "checked_authority": {
                "caller_path": "ExactComputedInterpreterStepPath",
                "return_replay": (
                    "ExactComputedInterpreterStepProgramLookupReturn"
                ),
            },
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.closure.write_text(json.dumps(self.payload), encoding="utf-8")

    def _build(self):
        return build_relational_interpreter_kernel_step_program_lookup_exact_computation_plan(
            candidate_pe=self.candidate,
            closure_plan=self.closure,
        )

    def test_plan_names_derived_and_explicit_premises_without_status(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["derived_computation_facts"],
            list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_DERIVED
            ),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_EXACT_COMPUTATION_REMAINING
            ),
        )
        self.assertNotIn('"status":', json.dumps(payload))
        self.assertEqual(
            payload["proof_authority"]["executor"],
            "runRelatedSteps candidate.transitionSystem",
        )

    def test_source_exposes_constructive_replay_only(self) -> None:
        source = (
            relational_interpreter_kernel_step_program_lookup_exact_computation_source(
                self._build()
            )
        )
        for fragment in (
            "ExactInterpreterStepHelperReplay",
            "ExactInterpreterStepProgramLookupCallReplay",
            "ExactInterpreterStepProgramLookupReturnReplay",
            "ExecutorClosedInterpreterStepProgramLookupCallerFrame",
            "generatedExactComputationBindings",
        ):
            self.assertIn(fragment, source)
        for forbidden in (
            "axiom ",
            "native_decide",
            "sorry",
            "runtimeFuel :=",
            "returnPath :=",
        ):
            self.assertNotIn(forbidden, source)

    def test_runtime_or_status_evidence_fails_closed(self) -> None:
        for key, value in (
            ("fuel", 9),
            ("endpoint", 0x2305),
            ("return_path", []),
            ("status", "proved"),
        ):
            with self.subTest(key=key):
                self.payload[key] = value
                self._write()
                with self.assertRaisesRegex(
                    RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError,
                    "submitted runtime or status evidence",
                ):
                    self._build()
                del self.payload[key]

    def test_stale_candidate_and_schema_fail_closed(self) -> None:
        self.candidate.write_bytes(b"changed")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic exact computation" * 19)
        self.payload["candidate"] = {
            "sha256": sha256_file(self.candidate),
            "size": self.candidate.stat().st_size,
        }
        self.payload["remaining_proof_premises"].pop()
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError,
            "stale or incompatible",
        ):
            self._build()

    def test_inconsistent_rel32_continuation_fails_closed(self) -> None:
        self.payload["checked_static_authority"]["continuation_rva"] = 0x2306
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError,
            "rel32 call continuation is inconsistent",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_is_checked(self) -> None:
        out = self.root / "out"
        first = (
            write_relational_interpreter_kernel_step_program_lookup_exact_computation_bundle(
                out=out,
                candidate_pe=self.candidate,
                closure_plan=self.closure,
            )
        )
        first_files = {
            path.name: path.read_bytes() for path in out.iterdir()
        }
        second = (
            write_relational_interpreter_kernel_step_program_lookup_exact_computation_bundle(
                out=out,
                candidate_pe=self.candidate,
                closure_plan=self.closure,
            )
        )
        self.assertEqual(first, second)
        self.assertEqual(
            first_files,
            {path.name: path.read_bytes() for path in out.iterdir()},
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupExactComputationGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_step_program_lookup_exact_computation_source(
                first,
                generated_closure_module="Injected\naxiom bad : False",
            )


if __name__ == "__main__":
    unittest.main()
