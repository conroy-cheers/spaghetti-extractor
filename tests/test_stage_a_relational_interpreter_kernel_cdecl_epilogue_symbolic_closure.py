from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue_symbolic_closure import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_CLOSED_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM,
    RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError,
    build_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_plan,
    relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_source,
    write_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_bundle,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelCDeclEpilogueSymbolicClosureTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.cdecl = self.root / "interpreter-kernel-cdecl-epilogue-plan.json"
        self.candidate.write_bytes(b"generic symbolic cdecl closure" * 19)
        digest = sha256_file(self.candidate)
        size = self.candidate.stat().st_size
        self.payload = {
            "format": INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT,
            "acceptance_authority": False,
            "candidate": {"sha256": digest, "size": size},
            "frontier": INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER,
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES
            ),
            "proof_frontiers": [
                {
                    "id": "interpreter-step:cdecl-epilogue-certificate",
                    "operation": "interpreterStep",
                    "premises": list(
                        INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES
                    ),
                },
                {
                    "id": "run-function:cdecl-epilogue-certificate",
                    "operation": "runFunction",
                    "premises": list(
                        INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES
                    ),
                },
            ],
            "forbidden_submitted_evidence": [
                "final_machine_state",
                "return_endpoint",
                "operation_status",
            ],
            "result": {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM},
            "failure_mode": "incomplete",
        }
        self._write()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self) -> None:
        self.cdecl.write_text(json.dumps(self.payload), encoding="utf-8")

    def _build(self):
        return build_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_plan(
            candidate_pe=self.candidate,
            cdecl_epilogue_plan=self.cdecl,
        )

    def test_plan_closes_mechanical_premises_without_endpoint_or_status(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["frontier"],
            INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER,
        )
        self.assertEqual(
            payload["closed_premise_families"],
            list(INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_CLOSED_PREMISES),
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES),
        )
        self.assertEqual(
            payload["result"],
            {"theorem": (INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM)},
        )
        serialized = json.dumps(payload)
        self.assertNotIn('"status":', serialized)
        self.assertNotIn('"endpoint":', serialized)
        for family in (
            "checked_stack_return_word",
            "preserved_cdecl_registers_and_stack_pop",
            "checked_write_footprint_disjointness",
        ):
            self.assertNotIn(family, payload["remaining_proof_premises"])

    def test_source_exposes_only_generic_symbolic_bindings(self) -> None:
        source = relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_source(
            self._build()
        )

        for fragment in (
            "RelationalInterpreterKernelCdeclEpilogueSymbolicClosure",
            "SymbolicallyClosedCDeclEpilogueCertificate",
            "GeneratedInterpreterStepCDeclSymbolicClosureCertificate",
            "GeneratedRunFunctionCDeclSymbolicClosureCertificate",
            "GeneratedCDeclSymbolicClosureRemaining",
            "generatedKernelCDeclSymbolicClosureBindings",
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

    def test_stale_or_derived_upstream_evidence_fails_closed(self) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError,
            "candidate is stale",
        ):
            self._build()

        self.candidate.write_bytes(b"generic symbolic cdecl closure" * 19)
        self.payload["stack_return_word"] = 0x401000
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError,
            "submitted endpoint, status, or derived cdecl evidence",
        ):
            self._build()

    def test_status_and_stale_frontiers_fail_closed(self) -> None:
        self.payload["result"] = {
            "theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM,
            "status": "checked",
        }
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.payload["result"] = {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM}
        self.payload["proof_frontiers"][0]["premises"] = []
        self._write()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError,
            "proof frontiers are stale",
        ):
            self._build()

    def test_writer_is_reproducible_and_module_name_is_checked(self) -> None:
        out = self.root / "out"
        plan = (
            write_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_bundle(
                out=out,
                candidate_pe=self.candidate,
                cdecl_epilogue_plan=self.cdecl,
            )
        )
        self.assertEqual(
            json.loads(
                (
                    out
                    / INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_PLAN_FILENAME
                ).read_text(encoding="utf-8")
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                out / INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_source(plan),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_source(
                plan,
                generated_cdecl_module="Injected\naxiom falseProof : False",
            )


if __name__ == "__main__":
    unittest.main()
