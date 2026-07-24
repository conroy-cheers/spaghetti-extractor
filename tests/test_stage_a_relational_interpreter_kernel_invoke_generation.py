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
from spaghetti_extractor.relational.lean.interpreter_kernel_invoke import (
    INTERPRETER_KERNEL_INVOKE_FORMAT,
    INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME,
    INTERPRETER_KERNEL_INVOKE_PLAN_FILENAME,
    RelationalInterpreterKernelInvokeGenerationError,
    _EXPECTED_LOCAL_CFG,
    _REVIEWED_NORMALIZED_BYTES,
    build_relational_interpreter_kernel_invoke_plan,
    relational_interpreter_kernel_invoke_source,
    write_relational_interpreter_kernel_invoke_bundle,
)


_START = 0x1000
_RUN = 0x2000
_EXTERNAL = 0x3000
_INSTRUCTION_OFFSETS = (
    0, 1, 3, 6, 10, 12, 17, 22, 25, 27, 30, 32, 35, 38, 41, 45,
    48, 52, 56, 59, 62, 67, 69, 72, 74, 77, 79, 83, 85, 88, 91, 93,
    95, 98, 101, 104, 107, 110, 114, 118, 121, 124, 126, 128, 130,
    133, 136, 140, 143, 147, 151, 154, 157, 162, 164, 167, 171, 174,
    178, 181, 185, 188, 191, 196, 197, 199, 201, 202,
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


def _rel32(source: int, target: int) -> bytes:
    displacement = (target - (source + 5)) & 0xFFFFFFFF
    return bytes([0xE8]) + displacement.to_bytes(4, "little")


def _function_bytes() -> bytes:
    result = bytearray(_REVIEWED_NORMALIZED_BYTES)
    result[62:67] = _rel32(_START + 62, _RUN)
    result[157:162] = _rel32(_START + 157, _RUN)
    result[191:196] = _rel32(_START + 191, _EXTERNAL)
    return bytes(result)


def _invoke_function() -> dict[str, object]:
    blob = _function_bytes()
    blocks: list[dict[str, object]] = []
    for index, (entry, local_successors) in enumerate(_EXPECTED_LOCAL_CFG):
        next_entry = (
            _EXPECTED_LOCAL_CFG[index + 1][0]
            if index + 1 < len(_EXPECTED_LOCAL_CFG)
            else len(blob)
        )
        offsets = [
            value
            for value in _INSTRUCTION_OFFSETS[:-1]
            if entry <= value < next_entry
        ]
        instructions = []
        for offset in offsets:
            end = _INSTRUCTION_OFFSETS[_INSTRUCTION_OFFSETS.index(offset) + 1]
            mnemonic = (
                "call"
                if offset in (62, 124, 157, 191)
                else "ret"
                if offset == 201
                else "op"
            )
            instructions.append(
                {
                    "rva": _START + offset,
                    "bytes": blob[offset:end].hex(),
                    "mnemonic": mnemonic,
                }
            )
        successors = [_START + value for value in local_successors]
        if entry == 32:
            successors.insert(0, _RUN)
        elif entry == 130:
            successors.insert(0, _RUN)
        elif entry == 164:
            successors.insert(0, _EXTERNAL)
        blocks.append(
            {
                "entry_rva": _START + entry,
                "instructions": instructions,
                "successors": successors,
            }
        )
    return {
        "role": "invokeCall",
        "rva_start": _START,
        "rva_end": _START + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": blocks,
        "loops": [],
        "x87_frames": [],
        "x87_commands": [],
        "padding": [],
        "frame": {
            "required": True,
            "push_rva": _START,
            "setup_rva": _START + 1,
            "teardown_rvas": [_START + 196],
            "return_rvas": [_START + 201],
        },
    }


def _payload() -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
        "candidate": {"pe_sha256": "a" * 64, "size": 0x8000},
        "kernel_functions": [
            {"role": "runFunction", "rva_start": _RUN},
            {"role": "helper 1", "rva_start": _EXTERNAL},
            _invoke_function(),
        ],
        "issues": [
            {
                "code": "unsupported_indirect_kernel_call",
                "function_role": "invokeCall",
                "rva_start": _START + 124,
                "rva_end": _START + 126,
            }
        ],
    }


class StageARelationalInterpreterKernelInvokeGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plan_path = self.root / "kernel.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, payload: dict[str, object] | None = None) -> None:
        self.plan_path.write_text(json.dumps(payload or _payload()), encoding="utf-8")

    def test_reflects_reviewed_three_arm_machine_template(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_invoke_plan(self.plan_path)

        self.assertEqual(plan.function_entry_rva, _START)
        self.assertEqual(plan.function_end_rva, _START + 202)
        self.assertEqual(len(plan.blocks), 14)
        self.assertEqual(plan.instruction_count, 67)
        self.assertEqual(plan.direct_call_offsets, (62, 157, 191))
        self.assertEqual(plan.direct_call_targets, (_RUN, _RUN, _EXTERNAL))
        self.assertEqual(plan.resolver_call_offset, 124)
        self.assertEqual(plan.return_offset, 201)
        payload = plan.payload()
        self.assertEqual(payload["format"], INTERPRETER_KERNEL_INVOKE_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["required_semantic_branches"],
            ["external", "internal", "indirect"],
        )

    def test_generated_source_exposes_static_and_semantic_goals(self) -> None:
        self._write()
        source = relational_interpreter_kernel_invoke_source(
            build_relational_interpreter_kernel_invoke_plan(self.plan_path)
        )

        for required in (
            "import StageA.GeneratedInterpreterKernelDataBundle",
            "generatedInvokeCallTemplate",
            "GeneratedInvokeCallTemplateGoal",
            "generatedKernelCallbackInventory",
            "ExactDecodeInventory",
            "GeneratedInvokeCallMachineCertificateGoal",
            "GeneratedInvokeCallRefines",
            "certificate.refines",
        ):
            self.assertIn(required, source)
        self.assertNotRegex(source, r"\bsimulate\s*:")
        self.assertNotRegex(source, r"\brefinement\s*:")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_source_compiles_with_explicit_data_module(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_invoke_plan(self.plan_path)
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelInvoke"
            )
            (stage_a / "GeneratedRelationalInterpreterKernel.lean").write_text(
                """import StageA.RelationalInterpreterKernelInvoke

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

def generatedKernelCallbackInventory : KernelCallbackInventory := { sites := [] }

end StageA.GeneratedRelational.InterpreterKernelCallback
""",
                encoding="utf-8",
            )
            (stage_a / "GeneratedInterpreterKernelDataBundle.lean").write_text(
                """import StageA.RelationalInterpreterKernel

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
            (stage_a / INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME).write_text(
                relational_interpreter_kernel_invoke_source(plan), encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="GeneratedRelationalInterpreterKernelInvoke"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    def test_rejects_opcode_cfg_target_and_frontier_tampering(self) -> None:
        payload = _payload()
        function = copy.deepcopy(payload["kernel_functions"][2])
        function["blocks"][0]["instructions"][0]["bytes"] = "90"
        payload["kernel_functions"][2] = function
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeGenerationError,
            "disagree with its digest",
        ):
            build_relational_interpreter_kernel_invoke_plan(self.plan_path)

        payload = _payload()
        payload["kernel_functions"][2]["blocks"][0]["successors"] = [_START + 12]
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeGenerationError, "local CFG"
        ):
            build_relational_interpreter_kernel_invoke_plan(self.plan_path)

        payload = _payload()
        payload["issues"][0]["code"] = "unknown_semantic_gap"
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelInvokeGenerationError,
            "unsupported overlapping issue",
        ):
            build_relational_interpreter_kernel_invoke_plan(self.plan_path)

    def test_writer_is_deterministic(self) -> None:
        self._write()
        first = self.root / "first"
        second = self.root / "second"
        write_relational_interpreter_kernel_invoke_bundle(
            kernel_plan=self.plan_path, out=first
        )
        write_relational_interpreter_kernel_invoke_bundle(
            kernel_plan=self.plan_path, out=second
        )
        for filename in (
            INTERPRETER_KERNEL_INVOKE_PLAN_FILENAME,
            INTERPRETER_KERNEL_INVOKE_LEAN_FILENAME,
        ):
            self.assertEqual(
                (first / filename).read_bytes(), (second / filename).read_bytes()
            )

    def test_latest_gnu_invoke_call_matches_reviewed_template(self) -> None:
        kernel = (
            Path(__file__).parents[1]
            / "build/stage-b-gnu-hello-roundtrip/interpreter-kernel-v5/interpreter-kernel-plan.json"
        )
        if not kernel.exists():
            self.skipTest("latest GNU kernel plan is not present")

        candidate = Path(
            "/nix/store/qr6q0j24yzfjxzyhrbyxhb2al6npm394-"
            "stage-b-gnu-hello-roundtrip-candidate/candidate.exe"
        )
        if not candidate.exists():
            self.skipTest("exact GNU candidate PE is not present")
        plan = build_relational_interpreter_kernel_invoke_plan(
            kernel, candidate_pe=candidate
        )

        self.assertEqual(plan.function_entry_rva, 307934)
        self.assertEqual(plan.function_end_rva, 308136)
        self.assertEqual(plan.function_sha256, "adc4dcc7e37205cddcf44b1bc13bf732392fe186a3a510b3526018027cedcc8d")
        self.assertEqual(plan.run_function_rva, 307593)
        self.assertEqual(plan.external_dispatch_rva, 298892)
        self.assertEqual(plan.direct_call_targets, (307593, 307593, 298892))
        self.assertEqual(plan.overlapping_issue_codes, ("unsupported_indirect_kernel_call",))


if __name__ == "__main__":
    unittest.main()
