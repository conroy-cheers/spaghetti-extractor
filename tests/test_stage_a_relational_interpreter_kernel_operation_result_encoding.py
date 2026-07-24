from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_external_payload import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_operation_result_encoding import (
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_CLOSED_PREMISES,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_LEAN_FILENAME,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_PLAN_FILENAME,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM,
    RelationalInterpreterKernelOperationResultEncodingGenerationError,
    build_relational_interpreter_kernel_operation_result_encoding_plan,
    relational_interpreter_kernel_operation_result_encoding_source,
    write_relational_interpreter_kernel_operation_result_encoding_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelOperationResultEncodingTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.external = self.root / "external-payload.json"
        self.candidate.write_bytes(b"generic operation result encoding" * 19)
        self.payload = {
            "format": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT
            ),
            "acceptance_authority": False,
            "candidate": {
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "frontier": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER
            ),
            "closed_premise_families": [
                "environmental_typed_response_payload"
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES
            ),
            "checked_authority": {
                "operation_result": "CheckedOperationResultEvidence",
                "external_trace": "CheckedResponseExternalTrace",
            },
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.external.write_text(json.dumps(self.payload), encoding="utf-8")

    def _build(self):
        return build_relational_interpreter_kernel_operation_result_encoding_plan(
            candidate_pe=self.candidate,
            external_payload_plan=self.external,
        )

    def test_plan_splits_the_umbrella_residual_by_exact_executor_family(
        self,
    ) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"], INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["frontier"],
            INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER,
        )
        self.assertEqual(
            payload["closed_premise_families"],
            list(INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_CLOSED_PREMISES),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES),
        )
        self.assertNotIn(
            "exact_operation_result_encoding",
            payload["remaining_proof_premises"],
        )
        self.assertEqual(
            payload["result"],
            {"theorem": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM},
        )

    def test_source_binds_only_endpoint_indexed_typed_residuals(self) -> None:
        source = relational_interpreter_kernel_operation_result_encoding_source(
            self._build()
        )

        for fragment in (
            "RelationalInterpreterKernelOperationResultEncoding",
            "InterpreterStepResultEncodingResidual",
            "CallResultEncodingResidual",
            "generatedInterpreterStepOperationResultEvidence",
            "generatedRunFunctionOperationResultEvidence",
            "generatedInvokeCallOperationResultEvidence",
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

    def test_stale_candidate_and_submitted_authority_fail_closed(self) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationResultEncodingGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic operation result encoding" * 19)
        self.payload["response_related"] = True
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationResultEncodingGenerationError,
            "submitted endpoint, response relation, report, or status",
        ):
            self._build()

    def test_stale_frontier_and_status_authority_fail_closed(self) -> None:
        self.payload["remaining_proof_premises"] = []
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationResultEncodingGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.payload["remaining_proof_premises"] = list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES
        )
        self.payload["status"] = "checked"
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationResultEncodingGenerationError,
            "submitted endpoint, response relation, report, or status",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_name_is_checked(self) -> None:
        out = self.root / "out"
        plan = (
            write_relational_interpreter_kernel_operation_result_encoding_bundle(
                out=out,
                candidate_pe=self.candidate,
                external_payload_plan=self.external,
            )
        )
        self.assertEqual(
            json.loads(
                (
                    out / INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                out / INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_operation_result_encoding_source(plan),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationResultEncodingGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_operation_result_encoding_source(
                plan,
                generated_external_payload_module=(
                    "Injected\naxiom falseProof : False"
                ),
            )


if __name__ == "__main__":
    unittest.main()
