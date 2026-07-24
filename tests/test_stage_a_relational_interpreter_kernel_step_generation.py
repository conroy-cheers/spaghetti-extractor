from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))
from spaghetti_extractor.relational.lean.interpreter_kernel_step import (
    INTERPRETER_KERNEL_STEP_FORMAT,
    INTERPRETER_KERNEL_STEP_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_PLAN_FILENAME,
    RelationalInterpreterKernelStepGenerationError,
    build_relational_interpreter_kernel_step_plan,
    relational_interpreter_kernel_step_source,
    write_relational_interpreter_kernel_step_bundle,
)


def _function() -> dict[str, object]:
    data = bytes.fromhex("55c3")
    return {
        "role": "interpreterStep",
        "rva_start": 0x1000,
        "rva_end": 0x1002,
        "size": 2,
        "sha256": hashlib.sha256(data).hexdigest(),
        "blocks": [
            {
                "entry_rva": 0x1000,
                "instructions": [
                    {"rva": 0x1000, "bytes": "55", "mnemonic": "push"},
                    {"rva": 0x1001, "bytes": "c3", "mnemonic": "ret"},
                ],
                "successors": [],
            }
        ],
        "loops": [],
        "x87_frames": [],
        "padding": [],
    }


def _payload() -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
        "candidate": {"pe_sha256": "a" * 64, "size": 8192},
        "kernel_functions": [_function()],
        "issues": [],
    }


class StageARelationalInterpreterKernelStepGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.kernel = self.root / "kernel.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, payload: dict[str, object] | None = None) -> None:
        self.kernel.write_text(json.dumps(payload or _payload()), encoding="utf-8")

    def test_reflects_complete_relative_machine_shape(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_step_plan(self.kernel)

        self.assertEqual(plan.function_entry_rva, 0x1000)
        self.assertEqual(plan.function_end_rva, 0x1002)
        self.assertEqual(plan.function_bytes, bytes.fromhex("55c3"))
        self.assertEqual(plan.instruction_count, 2)
        self.assertEqual(plan.return_offsets, (1,))
        self.assertEqual(plan.specialized_dependencies, ())
        payload = plan.payload()
        self.assertEqual(payload["format"], INTERPRETER_KERNEL_STEP_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["status"], "structurally_ready")

    def test_generated_source_exposes_goal_and_derived_refinement_only(self) -> None:
        self._write()
        source = relational_interpreter_kernel_step_source(
            build_relational_interpreter_kernel_step_plan(self.kernel)
        )

        for required in (
            "generatedInterpreterStepTemplate",
            "GeneratedInterpreterStepTemplateGoal",
            "GeneratedInterpreterStepMachineCertificateGoal",
            "parsePE32Tree generatedKernelCandidateBytes",
            "ExactDecodeInventory",
            "GeneratedInterpreterStepRefines",
            "certificate.refines",
        ):
            self.assertIn(required, source)
        self.assertNotRegex(source, r"\bsimulate\s*:")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_specialized_legacy_labels_become_explicit_dependencies(self) -> None:
        payload = _payload()
        payload["issues"] = [
            {
                "code": "unsupported_indirect_kernel_call",
                "function_role": "interpreterStep",
                "rva_start": 0x1000,
                "rva_end": 0x1001,
            },
            {
                "code": "unsupported_kernel_x87",
                "function_role": "helper 12",
                "rva_start": 0x2000,
                "rva_end": 0x2002,
            },
        ]
        self._write(payload)

        plan = build_relational_interpreter_kernel_step_plan(self.kernel)

        self.assertEqual(
            plan.specialized_dependencies,
            ("interpreter-kernel-indirect", "interpreter-kernel-x87"),
        )
        self.assertEqual(
            dict(plan.specialized_frontier_counts),
            {
                "unsupported_indirect_kernel_call": 1,
                "unsupported_kernel_x87": 1,
            },
        )
        self.assertEqual(plan.payload()["status"], "incomplete")

    def test_rejects_unknown_overlapping_issue_and_tampered_bytes(self) -> None:
        payload = _payload()
        payload["issues"] = [
            {
                "code": "unknown_machine_frontier",
                "function_role": "interpreterStep",
            }
        ]
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepGenerationError,
            "unsupported unresolved issue",
        ):
            build_relational_interpreter_kernel_step_plan(self.kernel)

        payload = _payload()
        function = copy.deepcopy(payload["kernel_functions"][0])
        function["blocks"][0]["instructions"][0]["bytes"] = "90"
        payload["kernel_functions"] = [function]
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepGenerationError, "disagree with its digest"
        ):
            build_relational_interpreter_kernel_step_plan(self.kernel)

    def test_writer_is_deterministic(self) -> None:
        self._write()
        first = self.root / "first"
        second = self.root / "second"
        write_relational_interpreter_kernel_step_bundle(
            kernel_plan=self.kernel, out=first
        )
        write_relational_interpreter_kernel_step_bundle(
            kernel_plan=self.kernel, out=second
        )
        for filename in (
            INTERPRETER_KERNEL_STEP_PLAN_FILENAME,
            INTERPRETER_KERNEL_STEP_LEAN_FILENAME,
        ):
            self.assertEqual(
                (first / filename).read_bytes(), (second / filename).read_bytes()
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_goal_compiles_against_kernel_module_interface(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_step_plan(self.kernel)
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelStep"
            )
            (stage_a / "GeneratedRelationalInterpreterKernel.lean").write_text(
                """import StageA.RelationalInterpreterKernelStep

namespace StageA.GeneratedRelational.InterpreterKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

def generatedKernelCandidateBytes : ByteTree := .leaf []

def generatedKernelFunction0000 : KernelFunction := {
  role := .interpreterStep
  hint := "fixture"
  span := { start := 4096, size := 2 }
  bytes := [85, 195]
  sha256 := "fixture"
  blocks := []
  x87Frames := []
  x87Commands := []
  padding := []
  loops := []
  frame := {
    required := false
    pushRva := 0
    setupRva := 0
    teardownRvas := []
    returnRvas := []
  }
}

def generatedCompiledKernelProgram : CompiledKernelProgram := {
  functions := [generatedKernelFunction0000]
}

end StageA.GeneratedRelational.InterpreterKernel
""",
                encoding="utf-8",
            )
            (stage_a / INTERPRETER_KERNEL_STEP_LEAN_FILENAME).write_text(
                relational_interpreter_kernel_step_source(plan),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="GeneratedRelationalInterpreterKernelStep"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    def test_latest_gnu_interpreter_step_is_reflected_exactly(self) -> None:
        kernel = (
            Path(__file__).parents[1]
            / "build/stage-b-gnu-hello-roundtrip/interpreter-kernel-v3/interpreter-kernel-plan.json"
        )
        if not kernel.exists():
            self.skipTest("latest GNU kernel plan is not present")

        plan = build_relational_interpreter_kernel_step_plan(kernel)

        self.assertEqual(plan.function_entry_rva, 414780)
        self.assertEqual(plan.function_end_rva, 418038)
        self.assertEqual(len(plan.function_bytes), 3258)
        self.assertEqual(len(plan.blocks), 143)
        self.assertEqual(plan.instruction_count, 930)
        self.assertEqual(len(plan.loops), 6)
        self.assertEqual(len(plan.call_offsets), 14)
        self.assertEqual(len(plan.indirect_call_offsets), 1)
        self.assertEqual(len(plan.return_offsets), 1)
        self.assertEqual(
            sum(
                1
                for block in plan.blocks
                if any(offset < 0 for offset in block.successor_offsets)
            ),
            11,
        )
        self.assertEqual(
            plan.function_sha256,
            "3b6708d34aeb8450ecd5d4bda7efc914e7d4e631884022df13ab4e649ace1e14",
        )
        self.assertEqual(
            plan.specialized_dependencies,
            ("interpreter-kernel-indirect", "interpreter-kernel-x87"),
        )
        self.assertEqual(
            dict(plan.specialized_frontier_counts),
            {
                "unsupported_indirect_kernel_call": 8,
                "unsupported_kernel_x87": 120,
            },
        )


if __name__ == "__main__":
    unittest.main()
