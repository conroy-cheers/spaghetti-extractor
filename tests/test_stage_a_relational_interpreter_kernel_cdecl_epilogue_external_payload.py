from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_external_payload import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_CLOSED_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM,
    RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError,
    build_relational_interpreter_kernel_cdecl_epilogue_external_payload_plan,
    relational_interpreter_kernel_cdecl_epilogue_external_payload_source,
    write_relational_interpreter_kernel_cdecl_epilogue_external_payload_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_static_preservation import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelCDeclEpilogueExternalPayloadTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.static = self.root / "static-preservation.json"
        self.candidate.write_bytes(b"generic cdecl external payload" * 23)
        self.payload = {
            "format": INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT,
            "acceptance_authority": False,
            "candidate": {
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "frontier": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER
            ),
            "closed_premise_families": [
                "loaded_image_and_original_program_table_preservation"
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES
            ),
            "checked_authority": {
                "exact_write_frame": (
                    "ExactDecodedCDeclSymbolicExecution.exactWriteFootprint"
                ),
                "workspace_disjointness": (
                    "ConcreteKernelABI.cdeclStaticPreservationFacts"
                ),
                "constructor": (
                    "StaticallyPreservedCDeclEpilogueCertificate.toChecked"
                ),
            },
            "forbidden_submitted_evidence": [
                "candidate_image_preserved",
                "original_program_table_preserved",
                "status",
            ],
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.static.write_text(json.dumps(self.payload), encoding="utf-8")

    def _build(self):
        return build_relational_interpreter_kernel_cdecl_epilogue_external_payload_plan(
            candidate_pe=self.candidate,
            static_preservation_plan=self.static,
        )

    def test_plan_reduces_payload_to_typed_operation_and_trace_evidence(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["frontier"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER,
        )
        self.assertEqual(
            payload["closed_premise_families"],
            list(INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_CLOSED_PREMISES),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES),
        )
        self.assertEqual(
            payload["result"],
            {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM},
        )
        serialized = json.dumps(payload)
        for forbidden in (
            '"status":',
            '"endpoint":',
            '"environmental_payload":',
            '"response_payload_holds":',
            '"response_related":',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_source_exposes_checked_operation_and_external_response_types(self) -> None:
        source = relational_interpreter_kernel_cdecl_epilogue_external_payload_source(
            self._build()
        )

        for fragment in (
            "RelationalInterpreterKernelCdeclEpilogueExternalPayload",
            "EnvironmentClosedCDeclEpilogueCertificate",
            "CheckedOperationResultEvidence",
            "CheckedResponseExternalTrace",
            "GeneratedInterpreterStepCDeclExternalPayloadCertificate",
            "GeneratedRunFunctionCDeclExternalPayloadCertificate",
            "generatedKernelCDeclExternalPayloadBindings",
        ):
            self.assertIn(fragment, source)
        for forbidden in (
            "axiom ",
            "native_decide",
            "operationStatus",
            "returnEndpoint",
            "sorry",
            "unsafe ",
        ):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("0x", source)

    def test_stale_and_submitted_payload_evidence_fail_closed(self) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic cdecl external payload" * 23)
        self.payload["response_related"] = True
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError,
            "submitted endpoint, payload, response relation, or status",
        ):
            self._build()

    def test_status_and_stale_frontier_fail_closed(self) -> None:
        self.payload["result"] = {
            "theorem": (INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM),
            "status": "checked",
        }
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.payload["result"] = {
            "theorem": (INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM)
        }
        self.payload["remaining_proof_premises"] = []
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError,
            "stale or incompatible",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_name_is_checked(self) -> None:
        out = self.root / "out"
        plan = (
            write_relational_interpreter_kernel_cdecl_epilogue_external_payload_bundle(
                out=out,
                candidate_pe=self.candidate,
                static_preservation_plan=self.static,
            )
        )
        self.assertEqual(
            json.loads(
                (
                    out
                    / INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                out / INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_cdecl_epilogue_external_payload_source(plan),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_cdecl_epilogue_external_payload_source(
                plan,
                generated_static_preservation_module=(
                    "Injected\naxiom falseProof : False"
                ),
            )


if __name__ == "__main__":
    unittest.main()
