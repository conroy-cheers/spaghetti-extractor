from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_frame_executor import (
    INTERPRETER_KERNEL_FRAME_EXECUTOR_FORMAT,
    INTERPRETER_KERNEL_FRAME_EXECUTOR_REMAINING_PREMISES,
    INTERPRETER_KERNEL_FRAME_EXECUTOR_THEOREM,
    RelationalInterpreterKernelFrameExecutorGenerationError,
    build_relational_interpreter_kernel_frame_executor_plan,
    relational_interpreter_kernel_frame_executor_source,
    write_relational_interpreter_kernel_frame_executor_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_operation_frame_parametric import (
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES,
    INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelFrameExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.frame = (
            self.root / "interpreter-kernel-operation-frame-parametric-plan.json"
        )
        self.candidate.write_bytes(b"frame executor candidate" * 31)
        self._write_frame()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_frame(self, *, entry_rva: int = 0x2600) -> None:
        self.frame.write_text(
            json.dumps(
                {
                    "format": (
                        INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_FORMAT
                    ),
                    "acceptance_authority": False,
                    "operation": "interpreterStep",
                    "candidate": {
                        "sha256": sha256_file(self.candidate),
                        "size": self.candidate.stat().st_size,
                    },
                    "checked_static_authority": {"entry_rva": entry_rva},
                    "remaining_proof_premises": list(
                        INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_REMAINING_PREMISES
                    ),
                    "result": {
                        "theorem": (
                            INTERPRETER_KERNEL_OPERATION_FRAME_PARAMETRIC_THEOREM
                        )
                    },
                    "failure_mode": "incomplete",
                }
            ),
            encoding="utf-8",
        )

    def _build(self):
        return build_relational_interpreter_kernel_frame_executor_plan(
            candidate_pe=self.candidate,
            frame_parametric_plan=self.frame,
        )

    def test_plan_reports_exact_executor_frontiers_without_status(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            INTERPRETER_KERNEL_FRAME_EXECUTOR_FORMAT,
            "stage-a-relational-interpreter-kernel-frame-executor-plan-v2",
        )
        self.assertEqual(payload["format"], INTERPRETER_KERNEL_FRAME_EXECUTOR_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_FRAME_EXECUTOR_REMAINING_PREMISES),
        )
        self.assertEqual(len(payload["proof_frontiers"]), 3)
        self.assertEqual(
            payload["result"]["theorem"],
            INTERPRETER_KERNEL_FRAME_EXECUTOR_THEOREM,
        )
        self.assertNotIn("status", payload["result"])

    def test_source_builds_typed_executor_certificate(self) -> None:
        source = relational_interpreter_kernel_frame_executor_source(self._build())

        for required in (
            "GeneratedInterpreterStepFrameExecutorPathEvidence",
            "ProducerSelectedStandaloneNativeWorldPath",
            "GeneratedInterpreterStepSelectedPathProducer",
            "ImportedFrameEnvironmentContract",
            "NativeWorldFrameExecutorEnvironmentContract.ofDisabled",
            "NativeWorldFrameExecutorPathContract",
            "KernelOperationFrameExecutorCertificate",
            "toFrameParametric",
            "generatedInterpreterStepFrameExecutorCertificate",
        ):
            self.assertIn(required, source)
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterKernelOperationFrame"
            "Parametric",
            source,
        )
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterKernelStepNative",
            source,
        )
        self.assertNotIn("shiftedAction", source)
        self.assertIsNone(
            re.search(r"\bStandaloneNativeWorldPath\b", source)
        )
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_input_status_cannot_close_executor_premises(self) -> None:
        payload = json.loads(self.frame.read_text(encoding="utf-8"))
        payload["result"]["status"] = "pass"
        self.frame.write_text(json.dumps(payload), encoding="utf-8")

        generated = self._build().payload()
        self.assertEqual(
            generated["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_FRAME_EXECUTOR_REMAINING_PREMISES),
        )
        self.assertNotIn("status", generated["result"])

    def test_stale_candidate_and_theorem_fail_closed(self) -> None:
        self.candidate.write_bytes(self.candidate.read_bytes() + b"x")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelFrameExecutorGenerationError,
            "stale or incompatible",
        ):
            self._build()

        self.candidate.write_bytes(b"frame executor candidate" * 31)
        self._write_frame()
        payload = json.loads(self.frame.read_text(encoding="utf-8"))
        payload["result"]["theorem"] = "StageA.Unchecked.claim"
        self.frame.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelFrameExecutorGenerationError,
            "stale or incompatible",
        ):
            self._build()

    def test_v1_frame_plan_fails_closed(self) -> None:
        payload = json.loads(self.frame.read_text(encoding="utf-8"))
        payload["format"] = (
            "stage-a-relational-interpreter-kernel-operation-frame-parametric-"
            "plan-v1"
        )
        self.frame.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(
            RelationalInterpreterKernelFrameExecutorGenerationError,
            "unsupported format",
        ):
            self._build()

    def test_writer_is_reproducible_and_modules_fail_closed(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "candidate_pe": self.candidate,
            "frame_parametric_plan": self.frame,
        }
        write_relational_interpreter_kernel_frame_executor_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_frame_executor_bundle(
            out=second, **kwargs
        )
        self.assertEqual(
            sorted(path.name for path in first.iterdir()),
            sorted(path.name for path in second.iterdir()),
        )
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())

        with self.assertRaisesRegex(
            RelationalInterpreterKernelFrameExecutorGenerationError,
            "frame-parametric module",
        ):
            relational_interpreter_kernel_frame_executor_source(
                self._build(),
                frame_parametric_module="Bad.Module",
            )


if __name__ == "__main__":
    unittest.main()
