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
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_mixed_environment_adapter import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_CLOSED_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_THEOREM,
    RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError,
    build_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_plan,
    relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_source,
    write_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.external = self.root / "external-payload.json"
        self.candidate.write_bytes(b"generic mixed cdecl adapter" * 29)
        self.payload = {
            "format": INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT,
            "acceptance_authority": False,
            "candidate": {
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "frontier": INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER,
            "closed_premise_families": ["environmental_typed_response_payload"],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES
            ),
            "checked_authority": {
                "operation_result": "CheckedOperationResultEvidence",
                "external_response": "CheckedOneToOneKernelExternalResponse",
                "external_trace": "CheckedResponseExternalTrace",
                "constructor": "EnvironmentClosedCDeclEpilogueCertificate.toChecked",
            },
            "forbidden_submitted_evidence": [
                "endpoint",
                "response_related",
                "status",
            ],
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
        return build_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_plan(
            candidate_pe=self.candidate,
            external_payload_plan=self.external,
        )

    def test_plan_records_only_the_dependent_residual(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["frontier"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FRONTIER,
        )
        self.assertEqual(
            payload["closed_premise_families"],
            list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_CLOSED_PREMISES
            ),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_REMAINING_PREMISES
            ),
        )
        self.assertEqual(
            payload["lean_interface"],
            {
                "theorem": (
                    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_THEOREM
                )
            },
        )
        self.assertEqual(
            payload["dependent_residual"]["lean_type"],
            "MixedCDeclExternalReturnResidual",
        )
        self.assertEqual(
            payload["dependent_residual"]["fields"],
            [
                "checkedMachineCall",
                "originalReturned",
                "siteIdExact",
                "importExact",
                "worldExact",
                "boundaryState",
                "boundaryArguments",
                "originalResultExact",
                "candidateResultExact",
                "semanticKind",
                "semanticImport",
                "semanticArguments",
            ],
        )

    def test_source_exposes_checked_adapter_without_authority_escape_hatches(
        self,
    ) -> None:
        source = (
            relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_source(
                self._build()
            )
        )

        for fragment in (
            "RelationalInterpreterKernelCdeclEpilogueMixedEnvironmentAdapter",
            "GeneratedMixedCDeclExternalReturnResidual",
            "GeneratedCheckedMixedCDeclKernelExternalResponse",
            "generatedMixedEnvironmentCDeclAdapterBindings",
        ):
            self.assertIn(fragment, source)
        for forbidden in (
            "axiom ",
            "native_decide",
            "sorry",
            "unsafe ",
            "status :=",
            "verdict :=",
        ):
            self.assertNotIn(forbidden, source)

    def test_stale_candidate_and_submitted_authority_fail_closed(self) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic mixed cdecl adapter" * 29)
        self.payload["response_related"] = True
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError,
            "submitted response authority",
        ):
            self._build()

    def test_stale_frontier_and_status_fail_closed(self) -> None:
        self.payload["remaining_proof_premises"] = []
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.payload["remaining_proof_premises"] = list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES
        )
        self.payload["status"] = "checked"
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError,
            "status, verdict",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_name_is_checked(self) -> None:
        output = self.root / "out"
        plan = write_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_bundle(
            out=output,
            candidate_pe=self.candidate,
            external_payload_plan=self.external,
        )
        self.assertEqual(
            json.loads(
                (
                    output
                    / INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                output
                / INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_source(
                plan
            ),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_source(
                plan,
                generated_external_payload_module="StageA.bad-module",
            )


if __name__ == "__main__":
    unittest.main()
