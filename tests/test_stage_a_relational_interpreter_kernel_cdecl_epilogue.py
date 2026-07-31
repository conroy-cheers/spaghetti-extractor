from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_cdecl_epilogue import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_PLAN_FILENAME,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM,
    RelationalInterpreterKernelCDeclEpilogueGenerationError,
    build_relational_interpreter_kernel_cdecl_epilogue_plan,
    relational_interpreter_kernel_cdecl_epilogue_source,
    write_relational_interpreter_kernel_cdecl_epilogue_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
    INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)
from spaghetti_extractor.util import sha256_file
from tests.pe_fixtures import pe32_image


class StageARelationalInterpreterKernelCDeclEpilogueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.step = self.root / "interpreter-kernel-step-operation-plan.json"
        self.run_plan = (
            self.root / "interpreter-kernel-run-operation-plan.json"
        )
        self.candidate.write_bytes(b"generic checked cdecl epilogue fixture" * 17)
        digest = sha256_file(self.candidate)
        size = self.candidate.stat().st_size
        self.step_payload = {
            "format": INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
            "acceptance_authority": False,
            "operation": "interpreterStep",
            "candidate": {"sha256": digest, "size": size},
            "checked_static_authority": {
                "function_index": 1,
                "function_symbol": "generatedKernelFunction0001",
                "entry_rva": 0x1000,
                "end_rva": 0x1100,
            },
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES
            ),
            "result": {
                "status": "upstream-status-is-not-proof",
                "theorem": INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
            },
            "failure_mode": "incomplete",
        }
        self._write_step()
        self.run_payload = {
            "format": INTERPRETER_KERNEL_RUN_OPERATION_FORMAT,
            "acceptance_authority": False,
            "operation": "runFunction",
            "candidate": {"sha256": digest, "size": size},
            "inputs": {
                "step_operation_plan": {
                    "path": self.step.name,
                    "sha256": sha256_file(self.step),
                }
            },
            "checked_static_authority": {
                "function_index": 2,
                "function_symbol": "generatedKernelFunction0002",
                "entry_rva": 0x2000,
                "end_rva": 0x2200,
            },
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES
            ),
            "result": {
                "status": "another-untrusted-upstream-status",
                "theorem": INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
            },
            "failure_mode": "incomplete",
        }
        self._write_run()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_step(self) -> None:
        self.step.write_text(json.dumps(self.step_payload), encoding="utf-8")

    def _write_run(self) -> None:
        self.run_plan.write_text(
            json.dumps(self.run_payload), encoding="utf-8"
        )

    def _build(
        self,
        *,
        step_epilogue_rva: int = 0x1080,
        step_return_rva: int = 0x10F0,
        step_epilogue_fuel: int = 4,
        run_epilogue_rva: int = 0x2100,
        run_return_rva: int = 0x21F0,
        run_epilogue_fuel: int = 8,
    ):
        return build_relational_interpreter_kernel_cdecl_epilogue_plan(
            candidate_pe=self.candidate,
            step_operation_plan=self.step,
            run_operation_plan=self.run_plan,
            step_epilogue_rva=step_epilogue_rva,
            step_return_rva=step_return_rva,
            step_epilogue_fuel=step_epilogue_fuel,
            run_epilogue_rva=run_epilogue_rva,
            run_return_rva=run_return_rva,
            run_epilogue_fuel=run_epilogue_fuel,
        )

    def test_plan_closes_shared_frontier_without_endpoint_or_status(self) -> None:
        payload = self._build().payload()

        self.assertEqual(payload["format"], INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["frontier"], INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES),
        )
        self.assertEqual(
            payload["result"], {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM}
        )
        self.assertEqual(
            [row["operation"] for row in payload["proof_frontiers"]],
            ["interpreterStep", "runFunction"],
        )
        self.assertNotIn("status", json.dumps(payload["result"]))
        self.assertIn(
            "return_endpoint", payload["forbidden_submitted_evidence"]
        )
        self.assertIn(
            "operation_status", payload["forbidden_submitted_evidence"]
        )

    def test_source_rechecks_static_data_and_exposes_typed_adapters(self) -> None:
        source = relational_interpreter_kernel_cdecl_epilogue_source(self._build())

        for fragment in (
            "KernelCDeclEpilogueInventory",
            "generatedInterpreterStepCDeclEpilogueChecked",
            "generatedRunFunctionCDeclEpilogueChecked",
            "CheckedCDeclEpilogueCertificate",
            "GeneratedInterpreterStepCDeclEpilogueCertificate",
            "GeneratedRunFunctionCDeclEpilogueCertificate",
            "generatedInterpreterStepCDeclEpilogueAdapter",
            "generatedRunFunctionCDeclEpilogueAdapter",
            "decide +kernel",
        ):
            self.assertIn(fragment, source)
        for forbidden in ("sorry", "axiom ", "unsafe ", "native_decide"):
            self.assertNotIn(forbidden, source)
        self.assertNotIn("operationStatus", source)
        self.assertNotIn("submittedEndpoint", source)

    def test_stale_candidate_fails_closed(self) -> None:
        self.candidate.write_bytes(b"changed candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueGenerationError,
            "candidate is stale",
        ):
            self._build()

    def test_run_plan_need_not_repeat_step_dependency(self) -> None:
        self.candidate.write_bytes(b"generic checked cdecl epilogue fixture" * 17)
        del self.run_payload["inputs"]["step_operation_plan"]
        self._write_run()
        self.assertEqual(self._build().run.operation, "runFunction")

    def test_incompatible_upstream_authority_fails_closed(self) -> None:
        self.step_payload["acceptance_authority"] = True
        self._write_step()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.step_payload["acceptance_authority"] = False
        self.step_payload["checked_static_authority"]["function_symbol"] = (
            "generatedKernelFunction0001\naxiom injected : False"
        )
        self._write_step()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueGenerationError,
            "function identity is stale",
        ):
            self._build()

        self.step_payload["checked_static_authority"]["function_symbol"] = (
            "generatedKernelFunction0001"
        )
        self.step_payload["remaining_proof_premises"] = []
        self._write_step()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueGenerationError,
            "stale or incompatible",
        ):
            self._build()

    def test_cutpoints_and_run_interface_fail_closed(self) -> None:
        for arguments in (
            {"step_epilogue_fuel": 0},
            {"step_return_rva": 0x1100},
            {"run_epilogue_rva": 0x21F1},
            {"run_epilogue_fuel": 7},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(
                    RelationalInterpreterKernelCDeclEpilogueGenerationError
                ):
                    self._build(**arguments)

    def test_terminal_epilogues_are_discovered_from_exact_function_ranges(
        self,
    ) -> None:
        step_code = b"\x90\x83\xc4\x04\x5d\x31\xc9\xc3"
        run_code = b"\x83\xc4\x08\x5b\x5e\x5f\x5d\x31\xd2\x31\xc9\xc3"
        self.candidate.write_bytes(pe32_image(step_code + run_code))
        digest = sha256_file(self.candidate)
        size = self.candidate.stat().st_size
        step_entry = 0x1000
        run_entry = step_entry + len(step_code)
        self.step_payload["candidate"] = {"sha256": digest, "size": size}
        self.step_payload["checked_static_authority"].update(
            {"entry_rva": step_entry, "end_rva": run_entry}
        )
        self._write_step()
        self.run_payload["candidate"] = {"sha256": digest, "size": size}
        self.run_payload["inputs"]["step_operation_plan"] = {
            "path": self.step.name,
            "sha256": sha256_file(self.step),
        }
        self.run_payload["checked_static_authority"].update(
            {
                "entry_rva": run_entry,
                "end_rva": run_entry + len(run_code),
            }
        )
        self._write_run()

        plan = build_relational_interpreter_kernel_cdecl_epilogue_plan(
            candidate_pe=self.candidate,
            step_operation_plan=self.step,
            run_operation_plan=self.run_plan,
            step_epilogue_fuel=4,
            run_epilogue_fuel=8,
        )

        self.assertEqual(plan.step.epilogue_rva, step_entry + 1)
        self.assertEqual(plan.step.return_rva, run_entry - 1)
        self.assertEqual(plan.run.epilogue_rva, run_entry)
        self.assertEqual(
            plan.run.return_rva, run_entry + len(run_code) - 1
        )

    def test_automatic_cutpoint_discovery_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueGenerationError,
            "supplied together",
        ):
            build_relational_interpreter_kernel_cdecl_epilogue_plan(
                candidate_pe=self.candidate,
                step_operation_plan=self.step,
                run_operation_plan=self.run_plan,
                step_epilogue_rva=0x1080,
                step_epilogue_fuel=4,
                run_epilogue_rva=0x2100,
                run_return_rva=0x21F0,
            )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueGenerationError,
            "not PE32",
        ):
            build_relational_interpreter_kernel_cdecl_epilogue_plan(
                candidate_pe=self.candidate,
                step_operation_plan=self.step,
                run_operation_plan=self.run_plan,
                step_epilogue_fuel=4,
                run_epilogue_fuel=8,
            )

    def test_writer_is_reproducible_and_module_names_are_checked(self) -> None:
        out = self.root / "out"
        plan = write_relational_interpreter_kernel_cdecl_epilogue_bundle(
            out=out,
            candidate_pe=self.candidate,
            step_operation_plan=self.step,
            run_operation_plan=self.run_plan,
            step_epilogue_rva=0x1080,
            step_return_rva=0x10F0,
            step_epilogue_fuel=4,
            run_epilogue_rva=0x2100,
            run_return_rva=0x21F0,
        )
        self.assertEqual(
            json.loads(
                (out / INTERPRETER_KERNEL_CDECL_EPILOGUE_PLAN_FILENAME).read_text(
                    encoding="utf-8"
                )
            ),
            plan.payload(),
        )
        self.assertEqual(
            (
                out / INTERPRETER_KERNEL_CDECL_EPILOGUE_LEAN_FILENAME
            ).read_text(encoding="ascii"),
            relational_interpreter_kernel_cdecl_epilogue_source(plan),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelCDeclEpilogueGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_cdecl_epilogue_source(
                plan, abi_module="Injected\naxiom falseProof : False"
            )


if __name__ == "__main__":
    unittest.main()
