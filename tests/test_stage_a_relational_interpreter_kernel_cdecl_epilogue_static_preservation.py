from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_static_preservation import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_CLOSED_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM,
    RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError,
    build_relational_interpreter_kernel_cdecl_epilogue_static_preservation_plan,
    relational_interpreter_kernel_cdecl_epilogue_static_preservation_source,
    write_relational_interpreter_kernel_cdecl_epilogue_static_preservation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_symbolic_closure import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelCDeclEpilogueStaticPreservationTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.symbolic = self.root / "symbolic-closure.json"
        self.candidate.write_bytes(b"generic static cdecl preservation" * 17)
        self.payload = {
            "format": INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT,
            "acceptance_authority": False,
            "candidate": {
                "sha256": sha256_file(self.candidate),
                "size": self.candidate.stat().st_size,
            },
            "frontier": (INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER),
            "closed_premise_families": [
                "checked_stack_return_word",
                "preserved_cdecl_registers_and_stack_pop",
                "checked_write_footprint_disjointness",
            ],
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES
            ),
            "checked_authority": {
                "exact_execution": "ExactDecodedCDeclSymbolicExecution",
                "abi_frame": "CDeclSymbolicABIFrameFacts",
                "constructor": ("SymbolicallyClosedCDeclEpilogueCertificate.toChecked"),
            },
            "forbidden_submitted_evidence": [
                "final_machine_state",
                "return_endpoint",
                "operation_status",
            ],
            "result": {
                "theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM
            },
            "failure_mode": "incomplete",
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.symbolic.write_text(json.dumps(self.payload), encoding="utf-8")

    def _build(self):
        return (
            build_relational_interpreter_kernel_cdecl_epilogue_static_preservation_plan(
                candidate_pe=self.candidate,
                symbolic_closure_plan=self.symbolic,
            )
        )

    def test_plan_closes_static_memory_and_leaves_only_payload(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["frontier"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER,
        )
        self.assertEqual(
            payload["closed_premise_families"],
            list(INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_CLOSED_PREMISES),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES
            ),
        )
        self.assertEqual(
            payload["result"],
            {
                "theorem": (
                    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM
                )
            },
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            ["environmental_typed_response_payload"],
        )
        serialized = json.dumps(payload)
        self.assertNotIn('"status":', serialized)
        self.assertNotIn('"candidate_image_preserved":', serialized)
        self.assertNotIn('"original_program_table_preserved":', serialized)

    def test_source_exposes_checked_preservation_constructor(self) -> None:
        source = (
            relational_interpreter_kernel_cdecl_epilogue_static_preservation_source(
                self._build()
            )
        )

        for fragment in (
            "RelationalInterpreterKernelCdeclEpilogueStaticPreservation",
            "StaticallyPreservedCDeclEpilogueCertificate",
            "GeneratedInterpreterStepCDeclStaticPreservationCertificate",
            "GeneratedRunFunctionCDeclStaticPreservationCertificate",
            "GeneratedCDeclEnvironmentalPayload",
            "generatedKernelCDeclStaticPreservationBindings",
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

    def test_stale_and_submitted_preservation_evidence_fail_closed(self) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic static cdecl preservation" * 17)
        self.payload["candidate_image_preserved"] = True
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError,
            "submitted preservation",
        ):
            self._build()

    def test_status_and_stale_frontier_fail_closed(self) -> None:
        self.payload["result"] = {
            "theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM,
            "status": "checked",
        }
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.payload["result"] = {
            "theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM
        }
        self.payload["remaining_proof_premises"] = [
            "environmental_typed_response_payload"
        ]
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError,
            "stale or incompatible",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_name_is_checked(self) -> None:
        out = self.root / "out"
        plan = write_relational_interpreter_kernel_cdecl_epilogue_static_preservation_bundle(
            out=out,
            candidate_pe=self.candidate,
            symbolic_closure_plan=self.symbolic,
        )
        self.assertEqual(
            json.loads(
                (
                    out
                    / INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                out
                / INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_cdecl_epilogue_static_preservation_source(
                plan
            ),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_cdecl_epilogue_static_preservation_source(
                plan,
                generated_symbolic_closure_module=(
                    "Injected\naxiom falseProof : False"
                ),
            )


if __name__ == "__main__":
    unittest.main()
