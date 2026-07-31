from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_lookup_native import (
    INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_native_world_bridge import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT,
    RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError,
    build_relational_interpreter_kernel_program_lookup_native_world_bridge_plan,
    relational_interpreter_kernel_program_lookup_native_world_bridge_source,
    write_relational_interpreter_kernel_program_lookup_native_world_bridge_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_operation import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_call import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
)
from spaghetti_extractor.util import sha256_file


class StageARelationalInterpreterKernelProgramLookupNativeWorldBridgeTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.native = self.root / "interpreter-kernel-lookup-native-plan.json"
        self.operation = (
            self.root / "interpreter-kernel-program-lookup-operation-plan.json"
        )
        self.call = (
            self.root / "interpreter-kernel-step-program-lookup-call-plan.json"
        )
        self.candidate.write_bytes(b"gnu hello exact candidate" * 97)
        self._write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _identity(self) -> dict[str, object]:
        return {
            "sha256": sha256_file(self.candidate),
            "size": self.candidate.stat().st_size,
        }

    def _write_inputs(
        self,
        *,
        entry_rva: int = 285217,
        call_site_rva: int = 285402,
        target_rva: int = 285217,
        continuation_rva: int = 285407,
    ) -> None:
        identity = self._identity()
        self.native.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT,
                    "candidate": identity,
                    "operation": "programLookup",
                }
            ),
            encoding="utf-8",
        )
        self.operation.write_text(
            json.dumps(
                {
                    "format": INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT,
                    "candidate": identity,
                    "operation": "programLookup",
                    "inputs": {
                        "lookup_native_plan": {
                            "sha256": sha256_file(self.native)
                        }
                    },
                    "checked_artifact_compatibility": {
                        "entry_rva": entry_rva
                    },
                }
            ),
            encoding="utf-8",
        )
        self.call.write_text(
            json.dumps(
                {
                    "format": (
                        INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT
                    ),
                    "candidate": identity,
                    "operation": "interpreterStep.programLookupCall",
                    "checked_static_authority": {
                        "call_site_rva": call_site_rva,
                        "target_rva": target_rva,
                        "continuation_rva": continuation_rva,
                    },
                }
            ),
            encoding="utf-8",
        )

    def _build(self):
        return (
            build_relational_interpreter_kernel_program_lookup_native_world_bridge_plan(
                candidate_pe=self.candidate,
                lookup_native_plan=self.native,
                lookup_operation_plan=self.operation,
                step_call_plan=self.call,
            )
        )

    def test_gnu_call_site_and_world_contract_are_exact(self) -> None:
        payload = self._build().payload()
        self.assertEqual(
            payload["format"],
            INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT,
        )
        self.assertEqual(
            payload["checked_static_authority"],
            {
                "entry_rva": 285217,
                "step_call_site_rva": 285402,
                "step_call_target_rva": 285217,
                "step_continuation_rva": 285407,
            },
        )
        self.assertEqual(
            payload["world_contract"],
            {
                "mode": "caller-parametric",
                "successor": "same-relational-world",
                "mixed_acceptance_launch_world_assumed": False,
            },
        )
        self.assertEqual(payload["remaining_proof_premises"], [])
        self.assertEqual(
            [row["id"] for row in payload["integration_frontiers"]],
            [
                "interpreter-step:program-lookup-caller-prefix",
                "mixed-acceptance:program-lookup-world-binding",
            ],
        )

    def test_source_is_world_parametric_and_has_no_launch_world_escape(
        self,
    ) -> None:
        source = (
            relational_interpreter_kernel_program_lookup_native_world_bridge_source(
                self._build()
            )
        )
        for required in (
            "import StageA.GeneratedRelationalInterpreterKernelProgramLookupOperation",
            "import StageA.GeneratedRelationalInterpreterKernelStepProgramLookupCall",
            "generatedProgramLookupStepCallExact",
            "generatedProgramLookupNativeWorldRefines",
            "generatedProgramLookupNativeWorldAtStepCall",
            "(environment : NativeWorldEnvironment) (world : RelationalWorld)",
            "NativeWorldKernelDispatches",
            "programLookupNativeLocalSemantics_programLookupRefinesUsingNativeWorld",
        ):
            self.assertIn(required, source)
        self.assertNotIn("generatedLaunchWorld", source)
        for marker in ("sorry", "axiom", "native_decide", "status"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_mismatched_target_continuation_and_candidate_fail_closed(
        self,
    ) -> None:
        self._write_inputs(target_rva=285218)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError,
            "does not target",
        ):
            self._build()
        self._write_inputs(continuation_rva=285408)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError,
            "does not target",
        ):
            self._build()
        self._write_inputs()
        self.candidate.write_bytes(self.candidate.read_bytes() + b"x")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError,
            "identity mismatch",
        ):
            self._build()

    def test_writer_is_reproducible(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "candidate_pe": self.candidate,
            "lookup_native_plan": self.native,
            "lookup_operation_plan": self.operation,
            "step_call_plan": self.call,
        }
        write_relational_interpreter_kernel_program_lookup_native_world_bridge_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_program_lookup_native_world_bridge_bundle(
            out=second, **kwargs
        )
        generated = (
            Path("StageA")
            / "GeneratedRelationalInterpreterKernelProgramLookupNativeWorldBridge.lean"
        )
        self.assertTrue((first / generated).is_file())
        self.assertEqual(
            sorted(path.relative_to(first) for path in first.rglob("*")),
            sorted(path.relative_to(second) for path in second.rglob("*")),
        )
        for path in first.rglob("*"):
            if path.is_file():
                self.assertEqual(
                    path.read_bytes(),
                    (second / path.relative_to(first)).read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
