from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel_callback import (
    INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke import (
    InterpreterKernelInvokePlan,
    InvokeBlockPlan,
)
from spaghetti_extractor.relational.lean import interpreter_kernel_invoke_native
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_native import (
    INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT,
    INTERPRETER_KERNEL_INVOKE_NATIVE_LEAN_FILENAME,
    RelationalInterpreterKernelInvokeNativeGenerationError,
    build_relational_interpreter_kernel_invoke_native_plan,
    relational_interpreter_kernel_invoke_native_source,
)
from spaghetti_extractor.util import sha256_file


_INVOKE_ENTRY = 307_934
_RESOLVER_SITE = 308_058
_RESOLVER_CONTINUATION = 308_060
_CANDIDATE_BYTES = b"synthetic invoke native candidate"
_CANDIDATE_SHA256 = hashlib.sha256(_CANDIDATE_BYTES).hexdigest()
_CANDIDATE_SIZE = len(_CANDIDATE_BYTES)
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


def _invoke_plan(
    *,
    candidate_sha256: str = _CANDIDATE_SHA256,
    candidate_size: int = _CANDIDATE_SIZE,
) -> InterpreterKernelInvokePlan:
    return InterpreterKernelInvokePlan(
        kernel_plan_path=Path("interpreter-kernel-plan.json"),
        kernel_plan_sha256="1" * 64,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        function_index=2,
        function_entry_rva=_INVOKE_ENTRY,
        function_end_rva=_INVOKE_ENTRY + 202,
        function_sha256="2" * 64,
        function_bytes=b"\x90" * 202,
        blocks=(InvokeBlockPlan(0, (0,), ()),),
        run_function_rva=307_593,
        external_dispatch_rva=298_892,
        direct_call_offsets=(62, 157, 191),
        direct_call_targets=(307_593, 307_593, 298_892),
        resolver_call_offset=124,
        return_offset=201,
        overlapping_issue_codes=("unsupported_indirect_kernel_call",),
    )


def _callback_payload(
    *,
    sha256: str = _CANDIDATE_SHA256,
    size: int = _CANDIDATE_SIZE,
    site_rva: int = _RESOLVER_SITE,
    continuation_rva: int = _RESOLVER_CONTINUATION,
) -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT,
        "candidate": {"sha256": sha256, "size": size},
        "sites": [
            {
                "id": 5,
                "role": "runtime_resolve_code_target",
                "function_role": "invokeCall",
                "rva": site_rva,
                "continuation_rva": continuation_rva,
                "targets": [{"id": 0, "rva": 310_066}],
            }
        ],
    }


class StageARelationalInterpreterKernelInvokeNativeGenerationTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.kernel = self.root / "kernel.json"
        self.callback = self.root / "callback.json"
        self.candidate = self.root / "candidate.exe"
        self.candidate.write_bytes(_CANDIDATE_BYTES)
        self.kernel.write_text(
            json.dumps(
                {
                    "candidate": {
                        "pe_sha256": _CANDIDATE_SHA256,
                        "size": _CANDIDATE_SIZE,
                    }
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(
        self,
        payload: dict[str, object],
        *,
        invoke: InterpreterKernelInvokePlan | None = None,
        candidate_bytes: bytes = _CANDIDATE_BYTES,
    ):
        candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
        candidate_size = len(candidate_bytes)
        self.candidate.write_bytes(candidate_bytes)
        self.kernel.write_text(
            json.dumps(
                {
                    "candidate": {
                        "pe_sha256": candidate_sha256,
                        "size": candidate_size,
                    }
                }
            ),
            encoding="utf-8",
        )
        self.callback.write_text(json.dumps(payload), encoding="utf-8")
        with mock.patch.object(
            interpreter_kernel_invoke_native,
            "build_relational_interpreter_kernel_invoke_plan",
            return_value=invoke or _invoke_plan(),
        ) as build_invoke:
            result = build_relational_interpreter_kernel_invoke_native_plan(
                kernel_plan=self.kernel,
                callback_plan=self.callback,
                candidate_pe=self.candidate,
            )
        build_invoke.assert_called_once_with(
            self.kernel, candidate_pe=self.candidate
        )
        return result

    def test_fresh_inventory_binds_all_three_native_arms(self) -> None:
        plan = self._build(_callback_payload())
        payload = plan.payload()

        self.assertEqual(payload["format"], INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT)
        self.assertEqual(payload["status"], "semantic_proof_required")
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(plan.callback_site_index, 0)
        self.assertEqual(plan.callback_target_rvas, (310_066,))
        self.assertEqual(set(payload["arms"]), {"internal", "indirect", "external"})
        self.assertEqual(payload["issues"], [])
        self.assertNotIn("required_sha256", payload["candidate"])
        self.assertEqual(
            payload["forbidden_submitted_evidence"],
            ["whole_arm_path", "final_abi_response", "final_memory_frame"],
        )

    def test_accepts_any_exact_candidate_identity_shared_by_all_artifacts(self) -> None:
        candidate_bytes = b"a completely different exact candidate"
        candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
        candidate_size = len(candidate_bytes)
        plan = self._build(
            _callback_payload(sha256=candidate_sha256, size=candidate_size),
            invoke=_invoke_plan(
                candidate_sha256=candidate_sha256,
                candidate_size=candidate_size,
            ),
            candidate_bytes=candidate_bytes,
        )

        self.assertFalse(plan.issues)
        self.assertEqual(plan.candidate_sha256, candidate_sha256)
        self.assertEqual(plan.candidate_size, candidate_size)

    def test_candidate_bytes_and_kernel_plan_disagreement_reports_both(self) -> None:
        expected_sha256 = "d" * 64
        expected_size = _CANDIDATE_SIZE + 1
        self.kernel.write_text(
            json.dumps(
                {
                    "candidate": {
                        "pe_sha256": expected_sha256,
                        "size": expected_size,
                    }
                }
            ),
            encoding="utf-8",
        )
        self.callback.write_text(json.dumps(_callback_payload()), encoding="utf-8")

        with (
            mock.patch.object(
                interpreter_kernel_invoke_native,
                "build_relational_interpreter_kernel_invoke_plan",
            ) as build_invoke,
            self.assertRaisesRegex(
                RelationalInterpreterKernelInvokeNativeGenerationError,
                rf"sha256={_CANDIDATE_SHA256}, size={_CANDIDATE_SIZE}.*"
                rf"sha256={expected_sha256}, size={expected_size}",
            ),
        ):
            build_relational_interpreter_kernel_invoke_native_plan(
                kernel_plan=self.kernel,
                callback_plan=self.callback,
                candidate_pe=self.candidate,
            )
        build_invoke.assert_not_called()

    def test_disagreement_reports_supplied_candidate_and_resolver_artifacts(self) -> None:
        plan = self._build(
            _callback_payload(
                sha256="b" * 64,
                size=_CANDIDATE_SIZE + 512,
                site_rva=418_503,
                continuation_rva=418_505,
            )
        )
        issues = {issue.code: issue.payload() for issue in plan.issues}

        self.assertEqual(plan.payload()["status"], "incomplete")
        self.assertEqual(
            set(issues),
            {"callback_candidate_mismatch", "callback_resolver_site_mismatch"},
        )
        self.assertEqual(
            issues["callback_candidate_mismatch"]["expected"],
            {
                "source": "candidate_pe_and_kernel_invoke_plan",
                "sha256": _CANDIDATE_SHA256,
                "size": _CANDIDATE_SIZE,
            },
        )
        self.assertEqual(
            issues["callback_candidate_mismatch"]["observed"],
            {
                "source": "callback_plan",
                "sha256": "b" * 64,
                "size": _CANDIDATE_SIZE + 512,
            },
        )
        self.assertEqual(
            issues["callback_resolver_site_mismatch"]["expected"],
            {"rva": _RESOLVER_SITE, "continuation_rva": _RESOLVER_CONTINUATION},
        )
        self.assertEqual(
            issues["callback_resolver_site_mismatch"]["observed"],
            [{"rva": 418_503, "continuation_rva": 418_505}],
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeNativeGenerationError,
            "stale or incomplete callback evidence",
        ):
            relational_interpreter_kernel_invoke_native_source(plan)

    def test_generated_source_imports_data_and_exposes_semantic_goals(self) -> None:
        source = relational_interpreter_kernel_invoke_native_source(
            self._build(_callback_payload())
        )
        for required in (
            "import StageA.GeneratedInterpreterKernelDataBundle",
            "open StageA.GeneratedRelational.InterpreterKernelData",
            "GeneratedInvokeCallNativeStaticGoal",
            "generatedKernelCallbackInventory.checked",
            "callbackSiteAt? generatedKernelCallbackInventory",
            "GeneratedInvokeCallRunFunctionNativeGoal",
            "NativeWorldSubroutineDispatches",
            "GeneratedInvokeCallExternalNativeGoal",
            "GeneratedInvokeCallIndirectNativeGoal",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_source_compiles_against_explicit_modules(self) -> None:
        source = relational_interpreter_kernel_invoke_native_source(
            self._build(_callback_payload())
        )
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelInvokeNative"
            )
            (stage_a / "GeneratedRelationalInterpreterKernel.lean").write_text(
                """import StageA.RelationalInterpreterKernel
namespace StageA.GeneratedRelational.InterpreterKernel
open StageA.Relational.InterpreterKernel
def generatedKernelFunction0002 : KernelFunction := {
  role := .invokeCall
  hint := "fixture"
  span := { start := 0, size := 0 }
  bytes := []
  sha256 := ""
  blocks := []
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
  functions := [generatedKernelFunction0002]
}
end StageA.GeneratedRelational.InterpreterKernel
""",
                encoding="utf-8",
            )
            (
                stage_a / "GeneratedRelationalInterpreterKernelCallback.lean"
            ).write_text(
                """import StageA.RelationalInterpreterKernelCallback
namespace StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCallback
def generatedKernelCallback0000Target0000 : CallbackTargetEntry := {
  id := 0
  entry := { rva := 0, bytes := [195] }
}
def generatedKernelCallbackSite0000 : KernelIndirectCallbackSite := {
  id := 0
  instruction := { rva := 0, bytes := [255, 208] }
  continuationRva := 2
  targetOperand := .register .eax
  abi := {
    argumentCount := 0
    argumentOffsets := []
    callerStackDelta := 0
    preservedRegisters := [.ebx, .esi, .edi, .ebp]
    returnKind := .wordInEax
  }
  targets := { entries := [generatedKernelCallback0000Target0000] }
}
def generatedKernelCallbackInventory : KernelCallbackInventory := {
  sites := [generatedKernelCallbackSite0000]
}
end StageA.GeneratedRelational.InterpreterKernelCallback
""",
                encoding="utf-8",
            )
            (stage_a / "GeneratedInterpreterKernelDataBundle.lean").write_text(
                """import StageA.Formal
namespace StageA.GeneratedRelational.InterpreterKernelData
open StageA.Formal
def generatedInterpreterKernelCandidatePe : PE32 := {
  bytes := .leaf []
  peOffset := 0
  entrypointRva := 0
  imageBase := 0
  sectionAlignment := 0
  fileAlignment := 0
  sizeOfImage := 0
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := []
}
def generatedInterpreterKernelImports : List PEImport := []
end StageA.GeneratedRelational.InterpreterKernelData
""",
                encoding="utf-8",
            )
            (
                stage_a / "GeneratedRelationalInterpreterKernelInvoke.lean"
            ).write_text(
                """import StageA.RelationalInterpreterKernelInvoke
namespace StageA.GeneratedRelational.InterpreterKernelInvoke
open StageA.Relational.InterpreterKernelInvoke
def generatedInvokeCallTemplate : InvokeCallMachineTemplate := {
  entryRva := 0
  functionBytes := []
  externalDispatchRva := 0
}
end StageA.GeneratedRelational.InterpreterKernelInvoke
""",
                encoding="utf-8",
            )
            (stage_a / INTERPRETER_KERNEL_INVOKE_NATIVE_LEAN_FILENAME).write_text(
                source, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedRelationalInterpreterKernelInvokeNative"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


class StageARelationalInterpreterKernelInvokeNativeCurrentArtifactTests(
    unittest.TestCase
):
    root = Path(__file__).parents[1] / "build/stage-b-gnu-hello-roundtrip"
    candidate = Path(
        "/nix/store/qr6q0j24yzfjxzyhrbyxhb2al6npm394-"
        "stage-b-gnu-hello-roundtrip-candidate/candidate.exe"
    )

    def test_exact_v5_candidate_and_current_callback_inventory(self) -> None:
        kernel = self.root / "interpreter-kernel-v5/interpreter-kernel-plan.json"
        callback = (
            self.root
            / "interpreter-kernel-callback-v2/interpreter-kernel-callback-plan.json"
        )
        if not all(path.is_file() for path in (self.candidate, kernel, callback)):
            self.skipTest("GNU hello v5 native invoke artifacts unavailable")
        kernel_payload = json.loads(kernel.read_text(encoding="utf-8"))
        callback_payload = json.loads(callback.read_text(encoding="utf-8"))
        expected_candidate = kernel_payload["candidate"]
        self.assertEqual(
            sha256_file(self.candidate), expected_candidate["pe_sha256"]
        )
        self.assertEqual(self.candidate.stat().st_size, expected_candidate["size"])
        self.assertEqual(
            callback_payload["candidate"],
            {
                "sha256": expected_candidate["pe_sha256"],
                "size": expected_candidate["size"],
            },
        )

        plan = build_relational_interpreter_kernel_invoke_native_plan(
            kernel_plan=kernel,
            callback_plan=callback,
            candidate_pe=self.candidate,
        )

        self.assertFalse(plan.issues)
        self.assertEqual(plan.callback_site_index, 5)
        self.assertEqual(plan.callback_site_rva, _RESOLVER_SITE)
        self.assertEqual(plan.callback_continuation_rva, _RESOLVER_CONTINUATION)
        self.assertEqual(plan.callback_target_rvas, (310_066,))
        self.assertEqual(plan.invoke.external_dispatch_rva, 298_892)

    def test_disagreeing_inventory_reports_both_supplied_artifact_identities(self) -> None:
        kernel = self.root / "interpreter-kernel-v5/interpreter-kernel-plan.json"
        callback = (
            self.root
            / "interpreter-kernel-callback-v1/interpreter-kernel-callback-plan.json"
        )
        if not all(path.is_file() for path in (self.candidate, kernel, callback)):
            self.skipTest("GNU hello stale callback fixture unavailable")

        plan = build_relational_interpreter_kernel_invoke_native_plan(
            kernel_plan=kernel,
            callback_plan=callback,
            candidate_pe=self.candidate,
        )

        issues = {issue.code: issue for issue in plan.issues}
        kernel_payload = json.loads(kernel.read_text(encoding="utf-8"))
        callback_payload = json.loads(callback.read_text(encoding="utf-8"))
        self.assertIn("callback_candidate_mismatch", issues)
        self.assertIn("callback_resolver_site_mismatch", issues)
        self.assertEqual(
            issues["callback_candidate_mismatch"].expected,
            {
                "source": "candidate_pe_and_kernel_invoke_plan",
                "sha256": kernel_payload["candidate"]["pe_sha256"],
                "size": kernel_payload["candidate"]["size"],
            },
        )
        self.assertEqual(
            issues["callback_candidate_mismatch"].observed,
            {"source": "callback_plan", **callback_payload["candidate"]},
        )
        self.assertEqual(
            issues["callback_resolver_site_mismatch"].site_rva,
            plan.callback_site_rva,
        )


if __name__ == "__main__":
    unittest.main()
