from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_call import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_call_closure import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_CLOSED_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_PLAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM,
    RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError,
    build_relational_interpreter_kernel_step_program_lookup_call_closure_plan,
    relational_interpreter_kernel_step_program_lookup_call_closure_source,
    write_relational_interpreter_kernel_step_program_lookup_call_closure_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelStepProgramLookupCallClosureTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.call_plan = (
            self.root / "interpreter-kernel-step-program-lookup-call-plan.json"
        )
        self.candidate.write_bytes(b"generic exact call closure" * 23)
        digest = sha256_file(self.candidate)
        size = self.candidate.stat().st_size
        call_site = 0x2300
        target = 0x1800
        continuation = call_site + 5
        self.payload = {
            "format": INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
            "acceptance_authority": False,
            "operation": "interpreterStep.programLookupCall",
            "candidate": {"sha256": digest, "size": size},
            "checked_static_authority": {
                "call_site_rva": call_site,
                "call_block_rva": 0x22F0,
                "target_rva": target,
                "continuation_rva": continuation,
            },
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES
            ),
            "proof_frontiers": [
                {
                    "premise": (
                        "exact_step_caller_prefix_and_program_lookup_call_chunk"
                    )
                },
                {
                    "premise": (
                        "program_lookup_request_at_exact_nested_caller_frame"
                    )
                },
                {
                    "premise": (
                        "exact_program_lookup_native_return_path_at_checked_"
                        "continuation"
                    )
                },
            ],
            "result": {
                "status": "typed-interface-ready",
                "theorem": (
                    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM
                ),
            },
            "failure_mode": "incomplete",
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.call_plan.write_text(
            json.dumps(self.payload),
            encoding="utf-8",
        )

    def _build(self):
        return (
            build_relational_interpreter_kernel_step_program_lookup_call_closure_plan(
                candidate_pe=self.candidate,
                program_lookup_call_plan=self.call_plan,
            )
        )

    def test_plan_replaces_submitted_paths_with_exact_computation(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["closed_premise_families"],
            list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_CLOSED_PREMISES
            ),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES
            ),
        )
        self.assertEqual(
            payload["result"],
            {
                "theorem": (
                    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM
                )
            },
        )
        self.assertNotIn('"status":', json.dumps(payload))
        self.assertEqual(
            payload["checked_authority"],
            {
                "caller_path": "ExactComputedInterpreterStepPath",
                "nested_request": "ConcreteProgramLookupNestedRequestFacts",
                "return_replay": (
                    "ExactComputedInterpreterStepProgramLookupReturn"
                ),
                "constructor": (
                    "SymbolicallyClosedInterpreterStepProgramLookupCallerFrame."
                    "toCallerFrame"
                ),
            },
        )

    def test_source_exposes_only_exact_generic_bindings(self) -> None:
        source = (
            relational_interpreter_kernel_step_program_lookup_call_closure_source(
                self._build()
            )
        )

        self.assertIn(
            "import StageA.GeneratedRelational"
            "InterpreterKernelStepProgramLookupCall\n",
            source,
        )
        self.assertNotIn(
            "import StageA.GeneratedRelational."
            "InterpreterKernelStepProgramLookupCall\n",
            source,
        )
        self.assertIn(
            "open StageA.GeneratedRelational."
            "InterpreterKernelStepProgramLookupCall\n",
            source,
        )
        for fragment in (
            "RelationalInterpreterKernelStepProgramLookupCallClosure",
            "SymbolicallyClosedInterpreterStepProgramLookupCallerFrame",
            "GeneratedInterpreterStepProgramLookupClosedComposition",
            "ConcreteProgramLookupNestedRequestFacts",
            "generatedInterpreterStepProgramLookupCallClosureBindings",
        ):
            self.assertIn(fragment, source)
        for forbidden in (
            "axiom ",
            "native_decide",
            "sorry",
            "unsafe ",
            "runtimeFuel :=",
            "returnPath :=",
        ):
            self.assertNotIn(forbidden, source)

    def test_stale_candidate_and_submitted_runtime_evidence_fail_closed(
        self,
    ) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic exact call closure" * 23)
        self.payload["return_path"] = {"fuel": 3}
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError,
            "submitted runtime evidence",
        ):
            self._build()

    def test_stale_status_and_ambiguous_frontiers_fail_closed(self) -> None:
        self.payload["result"]["status"] = "checked"
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.payload["result"]["status"] = "typed-interface-ready"
        self.payload["proof_frontiers"].pop()
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError,
            "frontiers are stale",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_name_is_checked(self) -> None:
        out = self.root / "out"
        plan = (
            write_relational_interpreter_kernel_step_program_lookup_call_closure_bundle(
                out=out,
                candidate_pe=self.candidate,
                program_lookup_call_plan=self.call_plan,
            )
        )
        self.assertEqual(
            json.loads(
                (
                    out
                    / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                out
                / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_step_program_lookup_call_closure_source(
                plan
            ),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_step_program_lookup_call_closure_source(
                plan,
                generated_call_module="Injected\naxiom falseProof : False",
            )


if __name__ == "__main__":
    unittest.main()
