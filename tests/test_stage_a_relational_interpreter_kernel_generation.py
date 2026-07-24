from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

if "tests" not in sys.modules:
    tests_package = types.ModuleType("tests")
    tests_package.__path__ = [str(Path(__file__).parent)]
    sys.modules["tests"] = tests_package

from tests.test_stage_b_interpreter_native_build import _Packages

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    RelationalInterpreterKernelGenerationError,
    build_relational_interpreter_kernel_plan,
    relational_interpreter_kernel_source,
)
from spaghetti_extractor.stage_b_interpreter_native_build import (
    INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME,
    build_stage_b_interpreter_native_candidate,
)
from spaghetti_extractor.util import sha256_bytes


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"), "i686 MinGW compiler unavailable"
)
class StageARelationalInterpreterKernelGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.packages = _Packages(self.root / "inputs")
        self.output = self.root / "candidate"
        build_stage_b_interpreter_native_candidate(
            interpreter_package=self.packages.interpreter,
            native_engine_package=self.packages.engine,
            native_runtime_package=self.packages.runtime,
            load_image_contract=self.packages.contract,
            anchor_manifest=self.packages.anchors,
            out_dir=self.output,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _kwargs(self) -> dict[str, Path]:
        return {
            "candidate_pe": self.output / "candidate.exe",
            "linker_map": self.output / "payload.map",
            "interpreter_program_manifest": (
                self.packages.interpreter
                / "state-machine-interpreter-program.json"
            ),
            "engine_layout": self.output / "engine-layout.bin",
            "native_build_manifest": (
                self.output / INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME
            ),
        }

    def test_binds_exact_profile_bytes_and_reports_kernel_frontiers(self) -> None:
        plan = build_relational_interpreter_kernel_plan(**self._kwargs())
        payload = plan.payload()

        self.assertEqual(
            payload["compiler_profile"]["required_flags"],
            ["-O0", "-fno-inline", "-fno-omit-frame-pointer"],
        )
        manifest = json.loads(
            self._kwargs()["native_build_manifest"].read_text(encoding="utf-8")
        )
        for row in manifest["objects"]:
            self.assertIn("-O0", row["flags"])
            self.assertIn("-fno-inline", row["flags"])
            self.assertIn("-fno-omit-frame-pointer", row["flags"])
            self.assertNotIn("-Os", row["flags"])

        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["status"], "incomplete")
        self.assertGreaterEqual(len(plan.functions), 4)
        self.assertLess(len(plan.functions), 100)
        self.assertTrue(
            {"programLookup", "interpreterStep", "runFunction", "invokeCall"}
            <= {function.role for function in plan.functions}
        )
        invoke = next(
            function for function in plan.functions if function.role == "invokeCall"
        )
        self.assertEqual(
            invoke.end,
            max(invoke.return_rvas) + 1,
            "verified linker alignment after ret must not extend semantic code",
        )
        for function in plan.functions:
            self.assertEqual(sha256_bytes(function.data), function.payload()["sha256"])
        self.assertEqual(
            payload["kernel_binding_scope"]["classification"],
            "rooted-kernel-closure-byte-bound",
        )
        self.assertFalse(plan.unbound_executable_ranges)
        self.assertFalse(
            payload["kernel_binding_scope"]["structural_certificate_ready"]
        )
        self.assertEqual(payload["program"]["transfer_count"], 1)
        issue_codes = {issue.code for issue in plan.issues}
        self.assertIn("unsupported_indirect_kernel_call", issue_codes)
        self.assertNotIn("unsupported_kernel_x87", issue_codes)
        self.assertNotIn("unclassified_kernel_bytes", issue_codes)
        self.assertNotIn("unbound_direct_kernel_target", issue_codes)
        self.assertTrue(all(issue.rva_start is not None for issue in plan.issues))

        operation_obligations = [
            row
            for row in payload["proof_obligations"]
            if row["family"] == "compiled_kernel_operation_refinement"
        ]
        self.assertEqual(
            {row["function_role"] for row in operation_obligations},
            {"programLookup", "interpreterStep", "runFunction", "invokeCall"},
        )
        block_soundness = [
            row
            for row in payload["proof_obligations"]
            if row["family"] == "native_symbolic_execution_soundness"
        ]
        self.assertEqual(
            len(block_soundness), sum(len(function.blocks) for function in plan.functions)
        )
        self.assertTrue(
            all(row["status"] == "pending_lean_theorem" for row in block_soundness)
        )

        generated = relational_interpreter_kernel_source(plan)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", generated), marker)
        self.assertNotRegex(
            generated,
            r"\b(?:def|theorem|structure)\s+WholeProgramCertificate\b",
        )
        self.assertIn("GeneratedCompiledKernelRefinementGoal", generated)
        self.assertIn("GeneratedKernelBlockSoundnessGoal", generated)
        self.assertIn("generatedCompiledKernelProgram.checked", generated)
        self.assertIn("set_option maxHeartbeats 0", generated)
        self.assertIn("set_option maxRecDepth 1000000", generated)
        self.assertNotIn("NativeDispatchRefinement", generated)

    def test_rejects_missing_or_conflicting_proof_profile_flags(self) -> None:
        source = self._kwargs()["native_build_manifest"]
        manifest = json.loads(source.read_text(encoding="utf-8"))
        manifest["objects"][0]["flags"].remove("-fno-inline")
        missing = self.root / "missing-profile.json"
        missing.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelGenerationError,
            "violates the proof compiler profile",
        ):
            build_relational_interpreter_kernel_plan(
                **{**self._kwargs(), "native_build_manifest": missing}
            )

        manifest = json.loads(source.read_text(encoding="utf-8"))
        manifest["objects"][0]["flags"].append("-Os")
        conflicting = self.root / "conflicting-profile.json"
        conflicting.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelGenerationError,
            "violates the proof compiler profile",
        ):
            build_relational_interpreter_kernel_plan(
                **{**self._kwargs(), "native_build_manifest": conflicting}
            )

    def test_rejects_candidate_not_bound_by_native_build_manifest(self) -> None:
        candidate = bytearray(self._kwargs()["candidate_pe"].read_bytes())
        candidate[-1] ^= 1
        stale = self.root / "stale-candidate.exe"
        stale.write_bytes(candidate)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelGenerationError,
            "binds a different candidate PE",
        ):
            build_relational_interpreter_kernel_plan(
                **{**self._kwargs(), "candidate_pe": stale}
            )
