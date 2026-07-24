from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_abstract_operation_transition import (
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_CLOSED_PREMISES,
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FORMAT,
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FRONTIER,
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_LEAN_FILENAME,
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_PLAN_FILENAME,
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_THEOREM,
    RelationalInterpreterKernelAbstractOperationTransitionGenerationError,
    build_relational_interpreter_kernel_abstract_operation_transition_plan,
    relational_interpreter_kernel_abstract_operation_transition_source,
    write_relational_interpreter_kernel_abstract_operation_transition_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_operation_result_encoding import (
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelAbstractOperationTransitionTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.result_encoding = self.root / "operation-result-encoding.json"
        self.candidate.write_bytes(b"generic abstract transition" * 17)
        self.payload = {
            "format": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT,
            "acceptance_authority": False,
            "candidate": {
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "frontier": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER,
            "closed_premise_families": [
                "program_lookup_exact_operation_result_encoding",
                "endpoint_indexed_operation_result_evidence_construction",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES
            ),
            "checked_authority": {
                "program_lookup": (
                    "ProgramLookupNativeReturnState."
                    "toCheckedOperationResultEvidence"
                ),
                "interpreter_step_residual": (
                    "InterpreterStepResultEncodingResidual"
                ),
                "call_result_residual": "CallResultEncodingResidual",
            },
            "forbidden_submitted_evidence": [
                "endpoint",
                "response_related",
                "status",
            ],
            "result": {
                "theorem": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM
            },
            "failure_mode": "incomplete",
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.result_encoding.write_text(
            json.dumps(self.payload), encoding="utf-8"
        )

    def _build(self):
        return (
            build_relational_interpreter_kernel_abstract_operation_transition_plan(
                candidate_pe=self.candidate,
                operation_result_encoding_plan=self.result_encoding,
            )
        )

    def test_plan_closes_only_the_abstract_transition_residual(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["frontier"],
            INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FRONTIER,
        )
        self.assertEqual(
            payload["closed_premise_families"],
            list(
                INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_CLOSED_PREMISES
            ),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_REMAINING_PREMISES
            ),
        )
        self.assertNotIn(
            "exact_abstract_operation_transition",
            payload["remaining_proof_premises"],
        )
        self.assertEqual(
            payload["result"],
            {
                "theorem": (
                    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_THEOREM
                )
            },
        )
        residuals = payload["checked_authority"]["typed_residuals"]
        self.assertEqual(residuals["program_lookup"], [])
        self.assertEqual(residuals["interpreter_step"], [])
        self.assertEqual(residuals["run_function"], ["AbstractRunFunction"])
        self.assertEqual(
            residuals["invoke_indirect"],
            [
                "event_kind_indirect",
                "exact_resolver_target",
                "AbstractRunFunction",
            ],
        )

    def test_source_uses_dependent_derivation_not_submitted_authority(self) -> None:
        source = relational_interpreter_kernel_abstract_operation_transition_source(
            self._build()
        )

        for fragment in (
            "RelationalInterpreterKernelAbstractOperationTransition",
            "CheckedAbstractOperationDerivation",
            "generatedCheckedAbstractOperationTransition",
            "derivation.toTransition",
        ):
            self.assertIn(fragment, source)
        for forbidden in (
            "axiom ",
            "native_decide",
            "responseRelated",
            "returnEndpoint",
            "sorry",
            "unsafe ",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("0x", source)

    def test_stale_and_submitted_transition_authority_fail_closed(self) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelAbstractOperationTransitionGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic abstract transition" * 17)
        self.payload["transition"] = True
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelAbstractOperationTransitionGenerationError,
            "submitted transition, response, endpoint, response relation, "
            "report, or status",
        ):
            self._build()

    def test_stale_frontier_and_response_authority_fail_closed(self) -> None:
        self.payload["remaining_proof_premises"] = []
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelAbstractOperationTransitionGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.payload["remaining_proof_premises"] = list(
            INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES
        )
        self.payload["response"] = {}
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelAbstractOperationTransitionGenerationError,
            "submitted transition, response, endpoint, response relation, "
            "report, or status",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_name_is_checked(self) -> None:
        out = self.root / "out"
        plan = (
            write_relational_interpreter_kernel_abstract_operation_transition_bundle(
                out=out,
                candidate_pe=self.candidate,
                operation_result_encoding_plan=self.result_encoding,
            )
        )
        self.assertEqual(
            json.loads(
                (
                    out
                    / INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                out
                / INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_abstract_operation_transition_source(
                plan
            ),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelAbstractOperationTransitionGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_abstract_operation_transition_source(
                plan,
                generated_operation_result_module=(
                    "Injected\naxiom falseProof : False"
                ),
            )


if __name__ == "__main__":
    unittest.main()
