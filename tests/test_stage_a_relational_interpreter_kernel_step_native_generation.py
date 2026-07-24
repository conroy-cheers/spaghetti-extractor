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
from spaghetti_extractor.relational.lean.interpreter_kernel_callback import (
    INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_native import (
    INTERPRETER_KERNEL_STEP_NATIVE_FORMAT,
    INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME,
    INTERPRETER_KERNEL_STEP_NATIVE_PLAN_FILENAME,
    RelationalInterpreterKernelStepNativeGenerationError,
    build_relational_interpreter_kernel_step_native_plan,
    relational_interpreter_kernel_step_native_source,
    write_relational_interpreter_kernel_step_native_bundle,
)
from spaghetti_extractor.util import sha256_file


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


def _call_bytes(rva: int, target: int) -> str:
    displacement = target - (rva + 5)
    return (b"\xe8" + displacement.to_bytes(4, "little", signed=True)).hex()


def _fixture(candidate: Path) -> tuple[dict[str, object], dict[str, object]]:
    lookup = 0x2000
    invoke = 0x3000
    callback_target = 0x4000
    blocks = [
        {
            "entry_rva": 0x1000,
            "instructions": [
                {
                    "rva": 0x1000,
                    "bytes": _call_bytes(0x1000, lookup),
                    "mnemonic": "call",
                }
            ],
            "successors": [lookup, 0x1005],
        },
        {
            "entry_rva": 0x1005,
            "instructions": [
                {
                    "rva": 0x1005,
                    "bytes": _call_bytes(0x1005, invoke),
                    "mnemonic": "call",
                }
            ],
            "successors": [invoke, 0x100A],
        },
        {
            "entry_rva": 0x100A,
            "instructions": [
                {"rva": 0x100A, "bytes": "ffd0", "mnemonic": "call"}
            ],
            "successors": [0x100C],
        },
        {
            "entry_rva": 0x100C,
            "instructions": [
                {"rva": 0x100C, "bytes": "c3", "mnemonic": "ret"}
            ],
            "successors": [],
        },
    ]
    image = b"".join(
        bytes.fromhex(instruction["bytes"])
        for block in blocks
        for instruction in block["instructions"]
    )
    identity = {"pe_sha256": sha256_file(candidate), "size": candidate.stat().st_size}
    kernel: dict[str, object] = {
        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
        "candidate": identity,
        "kernel_functions": [
            {
                "role": "interpreterStep",
                "rva_start": 0x1000,
                "rva_end": 0x100D,
                "size": len(image),
                "sha256": hashlib.sha256(image).hexdigest(),
                "blocks": blocks,
                "loops": [],
                "x87_frames": [],
                "x87_commands": [],
                "padding": [],
            },
            {"role": "programLookup", "rva_start": lookup},
            {"role": "invokeCall", "rva_start": invoke},
            {"role": "helper 16384", "rva_start": callback_target},
        ],
        "issues": [
            {
                "code": "unsupported_indirect_kernel_call",
                "function_role": "interpreterStep",
                "rva_start": 0x100A,
                "rva_end": 0x100C,
            }
        ],
    }
    callback: dict[str, object] = {
        "format": INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT,
        "candidate": {"sha256": identity["pe_sha256"], "size": identity["size"]},
        "sites": [
            {
                "id": 0,
                "rva": 0x100A,
                "continuation_rva": 0x100C,
                "function_role": "interpreterStep",
                "role": "runtime_callback",
                "targets": [{"id": 0, "rva": callback_target}],
            }
        ],
    }
    return kernel, callback


class StageARelationalInterpreterKernelStepNativeGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.candidate.write_bytes(b"exact-native-step-fixture")
        kernel, callback = _fixture(self.candidate)
        self.kernel = self.root / "kernel.json"
        self.callback = self.root / "callback.json"
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self.callback.write_text(json.dumps(callback), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self):
        return build_relational_interpreter_kernel_step_native_plan(
            kernel_plan=self.kernel,
            callback_plan=self.callback,
            candidate_pe=self.candidate,
        )

    def test_classifies_every_exact_cutpoint_and_call(self) -> None:
        plan = self._build()

        self.assertFalse(plan.issues)
        self.assertEqual(plan.program_lookup_call_offset, 0)
        self.assertEqual(plan.invoke_call_offset, 5)
        self.assertEqual(plan.callback_site_rvas, (0x100A,))
        self.assertEqual(plan.callback_target_rvas, (0x4000,))
        self.assertEqual(
            [cutpoint.effect for cutpoint in plan.cutpoints],
            [
                "program_lookup_call",
                "invoke_call",
                "indirect_callback_call",
                "return",
            ],
        )
        self.assertEqual(plan.cutpoints[2].allowed_rvas, (0x100C, 0x4000))
        payload = plan.payload()
        self.assertEqual(payload["format"], INTERPRETER_KERNEL_STEP_NATIVE_FORMAT)
        self.assertEqual(payload["status"], "local_semantics_required")
        self.assertFalse(payload["acceptance_authority"])

    def test_generated_source_contains_only_static_data_and_derived_theorem(self) -> None:
        source = relational_interpreter_kernel_step_native_source(self._build())

        for required in (
            "generatedInterpreterStepNativeCandidateSha256",
            "generatedInterpreterStepNativeTemplate",
            "generatedInterpreterKernelCandidateBytes",
            "GeneratedInterpreterStepNativeStaticGoal",
            "GeneratedInterpreterStepNativeCertificateGoal",
            "GeneratedInterpreterStepNativeConcreteCertificateGoal",
            "ConcreteKernelABI",
            "GeneratedInterpreterStepNativeRefines",
            "certificate.refines",
        ):
            self.assertIn(required, source)
        for forbidden in (
            r"\bstatus\b",
            r"\bsimulate\s*:",
            r"\bwholeOperationPath\b",
            r"\bwholeOperationFinalState\b",
        ):
            self.assertNotRegex(source, forbidden)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_fails_closed_on_stale_candidate_and_uncovered_callback(self) -> None:
        self.candidate.write_bytes(b"tampered")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepNativeGenerationError,
            "candidate PE identity disagrees",
        ):
            self._build()

        self.candidate.write_bytes(b"exact-native-step-fixture")
        callback = json.loads(self.callback.read_text(encoding="utf-8"))
        callback["sites"] = []
        self.callback.write_text(json.dumps(callback), encoding="utf-8")
        plan = self._build()
        self.assertIn("missing_step_callback_site", {issue.code for issue in plan.issues})
        with self.assertRaisesRegex(
            RelationalInterpreterKernelStepNativeGenerationError,
            "incomplete exact-native Step evidence",
        ):
            relational_interpreter_kernel_step_native_source(plan)

    def test_fails_closed_on_nonterminal_call_and_unresolved_direct_target(self) -> None:
        kernel = json.loads(self.kernel.read_text(encoding="utf-8"))
        function = copy.deepcopy(kernel["kernel_functions"][0])
        block = function["blocks"][0]
        block["instructions"].append(
            {"rva": 0x1005, "bytes": "90", "mnemonic": "nop"}
        )
        block["successors"] = [0x2000, 0x1006]
        function["blocks"][1]["entry_rva"] = 0x1006
        function["blocks"][1]["instructions"][0]["rva"] = 0x1006
        function["blocks"][1]["instructions"][0]["bytes"] = _call_bytes(
            0x1006, 0x3000
        )
        # This malformed fixture is rejected by the base exact template before
        # the native layer can accept a nonterminal call.
        kernel["kernel_functions"][0] = function
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        with self.assertRaises(RelationalInterpreterKernelStepNativeGenerationError):
            self._build()

    def test_writer_is_deterministic(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        for output in (first, second):
            write_relational_interpreter_kernel_step_native_bundle(
                kernel_plan=self.kernel,
                callback_plan=self.callback,
                candidate_pe=self.candidate,
                out=output,
            )
        for filename in (
            INTERPRETER_KERNEL_STEP_NATIVE_PLAN_FILENAME,
            INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME,
        ):
            self.assertEqual(
                (first / filename).read_bytes(), (second / filename).read_bytes()
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_module_elaborates_against_declared_interfaces(self) -> None:
        generated = relational_interpreter_kernel_step_native_source(
            self._build(),
            step_module="StageA.StepNativeStepFixture",
            kernel_module="StageA.StepNativeKernelFixture",
            callback_module="StageA.StepNativeCallbackFixture",
            data_module="StageA.StepNativeDataFixture",
        )
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        lean_root = self.root / "lean"
        stage_a = lean_root / "StageA"
        stage_a.mkdir(parents=True)
        _copy_module_closure(
            source_root, stage_a, "RelationalInterpreterKernelStepNative"
        )
        _copy_module_closure(
            source_root, stage_a, "RelationalInterpreterKernelData"
        )
        (stage_a / "StepNativeKernelFixture.lean").write_text(
            _LEAN_KERNEL_FIXTURE, encoding="utf-8"
        )
        (stage_a / "StepNativeStepFixture.lean").write_text(
            _LEAN_STEP_FIXTURE, encoding="utf-8"
        )
        (stage_a / "StepNativeCallbackFixture.lean").write_text(
            _LEAN_CALLBACK_FIXTURE, encoding="utf-8"
        )
        (stage_a / "StepNativeDataFixture.lean").write_text(
            _LEAN_DATA_FIXTURE, encoding="utf-8"
        )
        (stage_a / INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME).write_text(
            generated, encoding="utf-8"
        )

        result = _run_lean_relational(
            lean_root, bundle="GeneratedRelationalInterpreterKernelStepNative"
        )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


class StageARelationalInterpreterKernelStepNativeCurrentArtifactTests(
    unittest.TestCase
):
    root = Path(__file__).parents[1] / "build/stage-b-gnu-hello-roundtrip"
    candidate = Path(
        "/nix/store/qr6q0j24yzfjxzyhrbyxhb2al6npm394-"
        "stage-b-gnu-hello-roundtrip-candidate/candidate.exe"
    )

    def test_current_gnu_candidate_has_complete_native_step_inventory(self) -> None:
        kernel = self.root / "interpreter-kernel-v7/interpreter-kernel-plan.json"
        callback = (
            self.root
            / "interpreter-kernel-callback-v2/interpreter-kernel-callback-plan.json"
        )
        if not all(path.is_file() for path in (self.candidate, kernel, callback)):
            self.skipTest("current GNU exact-native Step artifacts unavailable")

        plan = build_relational_interpreter_kernel_step_native_plan(
            kernel_plan=kernel,
            callback_plan=callback,
            candidate_pe=self.candidate,
        )

        self.assertFalse(plan.issues)
        self.assertEqual(plan.candidate_sha256, sha256_file(self.candidate))
        self.assertEqual(plan.step.function_entry_rva, 304899)
        self.assertEqual(plan.step.function_sha256, "34723ff551e99275ee823c42029625d6012953ba89f1a20480cfda00762aa1c1")
        self.assertEqual(len(plan.cutpoints), 125)
        self.assertEqual(plan.step.instruction_count, 770)
        self.assertEqual(len(plan.direct_calls), 12)
        self.assertEqual(plan.callback_site_rvas, (307303,))
        self.assertEqual(plan.callback_target_rvas, (298318,))


_LEAN_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterKernelStepNative
namespace StageA.GeneratedRelational.InterpreterKernel
open StageA.Relational.InterpreterKernel
def generatedKernelFunction0000 : KernelFunction := {
  role := .interpreterStep
  hint := "fixture"
  span := { start := 4096, size := 13 }
  bytes := []
  sha256 := ""
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
"""

_LEAN_STEP_FIXTURE = r"""import StageA.RelationalInterpreterKernelStepNative
namespace StageA.GeneratedRelational.InterpreterKernelStep
open StageA.Relational.InterpreterKernelStep
def generatedInterpreterStepTemplate : InterpreterStepMachineTemplate := {
  entryRva := 4096
  functionBytes := []
  blocks := []
  loops := []
  callOffsets := []
  indirectCallOffsets := []
  returnOffsets := []
}
end StageA.GeneratedRelational.InterpreterKernelStep
"""

_LEAN_CALLBACK_FIXTURE = r"""import StageA.RelationalInterpreterKernelCallback
namespace StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCallback
def generatedKernelCallbackInventory : KernelCallbackInventory := { sites := [] }
end StageA.GeneratedRelational.InterpreterKernelCallback
"""

_LEAN_DATA_FIXTURE = r"""import StageA.RelationalInterpreterKernelData
namespace StageA.GeneratedRelational.InterpreterKernelData
open StageA.Formal
def generatedInterpreterKernelCandidateBytes : ByteTree := .leaf []
def generatedInterpreterKernelCandidatePe : PE32 := {
  bytes := generatedInterpreterKernelCandidateBytes
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
def generatedInterpreterKernelRelocations : List BaseRelocation := []
def generatedInterpreterKernelTableRva : Nat := 0
def generatedInterpreterKernelCountRva : Nat := 0
end StageA.GeneratedRelational.InterpreterKernelData
"""


if __name__ == "__main__":
    unittest.main()
