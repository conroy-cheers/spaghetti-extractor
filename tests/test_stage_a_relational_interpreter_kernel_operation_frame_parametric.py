from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_operation_frame_parametric import (
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM,
    RelationalInterpreterKernelOperationFrameParametricGenerationError,
    build_relational_interpreter_kernel_operation_frame_parametric_plan,
    relational_interpreter_kernel_operation_frame_parametric_source,
    write_relational_interpreter_kernel_operation_frame_parametric_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelOperationFrameParametricTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.step = self.root / "interpreter-kernel-step-operation-plan.json"
        self.candidate.write_bytes(b"frame-parametric candidate" * 29)
        self._write_step()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_step(self, *, entry_rva: int = 0x2400) -> None:
        self.step.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_STEP_OPERATION_FORMAT,
                    "acceptance_authority": False,
                    "operation": "interpreterStep",
                    "candidate": {
                        "sha256": sha256_file(self.candidate),
                        "size": self.candidate.stat().st_size,
                    },
                    "checked_static_authority": {"entry_rva": entry_rva},
                    "remaining_proof_premises": list(
                        INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES
                    ),
                    "result": {
                        "theorem": INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
                    },
                    "failure_mode": "incomplete",
                }
            ),
            encoding="utf-8",
        )

    def _build(self):
        return (
            build_relational_interpreter_kernel_operation_frame_parametric_plan(
                candidate_pe=self.candidate,
                step_operation_plan=self.step,
            )
        )

    def test_plan_reports_only_the_two_smaller_typed_frontiers(self) -> None:
        payload = self._build().payload()
        self.assertEqual(
            INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT,
            "stage-a-relational-interpreter-kernel-operation-frame-parametric-"
            "plan-v2",
        )
        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT,
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES
            ),
        )
        self.assertEqual(len(payload["proof_frontiers"]), 2)
        self.assertEqual(
            payload["result"]["theorem"],
            INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM,
        )
        self.assertNotIn("status", payload["result"])

    def test_source_exposes_typed_certificate_without_status_authority(
        self,
    ) -> None:
        source = (
            relational_interpreter_kernel_operation_frame_parametric_source(
                self._build()
            )
        )
        for required in (
            "GeneratedInterpreterStepSelectedPathProducer",
            "GeneratedInterpreterStepSelectedPathRefinement",
            "ProducerSelectedStandaloneNativeWorldPath",
            "ProducerSelectedStandaloneNativeWorldDispatches",
            "NativeWorldFramePathRefinement",
            "generatedInterpreterStepFrameParametricCertificate",
            "KernelOperationFrameParametricCertificate",
        ):
            self.assertIn(required, source)
        self.assertNotIn("GeneratedStandaloneInterpreterStepOperation", source)
        self.assertNotIn("contextRefinement", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_stale_candidate_and_theorem_fail_closed(self) -> None:
        self.candidate.write_bytes(self.candidate.read_bytes() + b"x")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationFrameParametricGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.candidate.write_bytes(b"frame-parametric candidate" * 29)
        self._write_step()
        payload = json.loads(self.step.read_text(encoding="utf-8"))
        payload["result"]["theorem"] = "StageA.Unchecked.claim"
        self.step.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationFrameParametricGenerationError,
            "stale or incompatible",
        ):
            self._build()

    def test_input_status_cannot_replace_the_typed_premises(self) -> None:
        payload = json.loads(self.step.read_text(encoding="utf-8"))
        payload["result"]["status"] = "pass"
        self.step.write_text(json.dumps(payload), encoding="utf-8")

        generated = self._build().payload()
        self.assertEqual(
            generated["remaining_proof_premises"],
            list(
                INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES
            ),
        )
        self.assertNotIn("status", generated["result"])

    def test_writer_is_byte_reproducible_and_modules_fail_closed(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "candidate_pe": self.candidate,
            "step_operation_plan": self.step,
        }
        write_relational_interpreter_kernel_operation_frame_parametric_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_operation_frame_parametric_bundle(
            out=second, **kwargs
        )
        self.assertEqual(
            sorted(path.name for path in first.iterdir()),
            sorted(path.name for path in second.iterdir()),
        )
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())
        with self.assertRaisesRegex(
            RelationalInterpreterKernelOperationFrameParametricGenerationError,
            "ABI module",
        ):
            relational_interpreter_kernel_operation_frame_parametric_source(
                self._build(), abi_module="Bad.Module"
            )


if __name__ == "__main__":
    unittest.main()
