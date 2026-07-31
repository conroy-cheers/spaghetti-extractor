from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run import (
    relational_interpreter_kernel_run_source,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_native import (
    INTERPRETER_KERNEL_RUN_NATIVE_FORMAT,
    INTERPRETER_KERNEL_RUN_NATIVE_LEAN_FILENAME,
    INTERPRETER_KERNEL_RUN_NATIVE_PLAN_FILENAME,
    RelationalInterpreterKernelRunNativeGenerationError,
    _BLOCK_INSTRUCTION_COUNTS,
    _BLOCK_OFFSETS,
    _LOOP_BODY_OFFSETS,
    _O0_PREFIX,
    _O0_SUFFIX,
    build_relational_interpreter_kernel_run_native_plan,
    relational_interpreter_kernel_run_native_source,
    write_relational_interpreter_kernel_run_native_bundle,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)
_START = 0x1000
_STEP = 0x2800


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


def _canonical_blob() -> bytes:
    return _O0_PREFIX + _rel32(_START + 91, _STEP)[1:] + _O0_SUFFIX


def _run_function() -> dict[str, object]:
    blob = _canonical_blob()
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoded = list(decoder.disasm(blob, _START))
    blocks: list[dict[str, object]] = []
    for index, offset in enumerate(_BLOCK_OFFSETS):
        stop = (
            _BLOCK_OFFSETS[index + 1] if index + 1 < len(_BLOCK_OFFSETS) else len(blob)
        )
        instructions = [
            {
                "rva": instruction.address,
                "bytes": bytes(instruction.bytes).hex(),
                "mnemonic": instruction.mnemonic,
            }
            for instruction in decoded
            if _START + offset <= instruction.address < _START + stop
        ]
        assert len(instructions) == _BLOCK_INSTRUCTION_COUNTS[index]
        blocks.append(
            {
                "entry_rva": _START + offset,
                "instructions": instructions,
                "successors": [_START + 58] if offset == 321 else [],
            }
        )
    return {
        "role": "runFunction",
        "rva_start": _START,
        "rva_end": _START + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": blocks,
        "loops": [
            {
                "header_rva": _START + 58,
                "latch_rva": _START + 321,
                "body_entries": [_START + value for value in _LOOP_BODY_OFFSETS],
            }
        ],
        "x87_frames": [],
        "x87_commands": [],
        "padding": [],
        "frame": {
            "required": True,
            "push_rva": _START,
            "setup_rva": _START + 1,
            "teardown_rvas": [_START + 335],
            "return_rvas": [_START + 340],
        },
    }


def _payload(candidate: bytes) -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
        "candidate": {
            "pe_sha256": hashlib.sha256(candidate).hexdigest(),
            "size": len(candidate),
        },
        "kernel_functions": [
            {"role": "interpreterStep", "rva_start": _STEP},
            _run_function(),
        ],
        "issues": [
            {
                "code": "unsupported_indirect_kernel_call",
                "function_role": "runFunction",
                "rva_start": _START + 180,
                "rva_end": _START + 182,
            }
        ],
    }


class StageARelationalInterpreterKernelRunNativeGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.kernel = self.root / "kernel.json"
        candidate = b"synthetic exact candidate" * 31
        self.candidate.write_bytes(candidate)
        self.kernel.write_text(json.dumps(_payload(candidate)), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self):
        return build_relational_interpreter_kernel_run_native_plan(
            kernel_plan=self.kernel, candidate_pe=self.candidate
        )

    def _compile_generated_interface(self, plan) -> dict[str, object]:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        lean_root = self.root / "generated-lean"
        stage_a = lean_root / "StageA"
        stage_a.mkdir(parents=True)
        _copy_module_closure(source_root, stage_a, "RelationalInterpreterKernelRun")
        (stage_a / "RunNativeDataFixture.lean").write_text(
            _LEAN_DATA_FIXTURE, encoding="utf-8"
        )
        kernel_fixture = _LEAN_KERNEL_FIXTURE.replace(
            "generatedKernelFunction0001",
            plan.run.generated_function_name,
        )
        (stage_a / "RunNativeKernelFixture.lean").write_text(
            kernel_fixture, encoding="utf-8"
        )
        (stage_a / "RunNativeCallbackFixture.lean").write_text(
            _LEAN_CALLBACK_FIXTURE, encoding="utf-8"
        )
        (stage_a / "RunNativeRunFixture.lean").write_text(
            relational_interpreter_kernel_run_source(
                plan.run,
                kernel_module="StageA.RunNativeKernelFixture",
                callback_module="StageA.RunNativeCallbackFixture",
                data_module="StageA.RunNativeDataFixture",
            ),
            encoding="utf-8",
        )
        generated = relational_interpreter_kernel_run_native_source(
            plan,
            run_module="StageA.RunNativeRunFixture",
            kernel_module="StageA.RunNativeKernelFixture",
            callback_module="StageA.RunNativeCallbackFixture",
            data_module="StageA.RunNativeDataFixture",
        )
        (stage_a / "GeneratedRelationalInterpreterKernelRunNative.lean").write_text(
            generated, encoding="utf-8"
        )
        (stage_a / "RunNativeGeneratedAudit.lean").write_text(
            """import StageA.GeneratedRelationalInterpreterKernelRunNative
open StageA.GeneratedRelational.InterpreterKernelRunNative
open StageA.GeneratedRelational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelRun
set_option maxRecDepth 100000 in
example : runFunctionLoopInventoryChecked generatedRunFunctionTemplate.loops = true := by
  decide
set_option maxRecDepth 100000 in
example : GeneratedRunFunctionNativeO0TemplateGoal := by
  change runFunctionNativeO0TemplateChecked generatedRunFunctionTemplate = true
  decide
#print axioms generatedRunFunctionNativeTemplateCertificate
""",
            encoding="utf-8",
        )
        return _run_lean_relational(lean_root, bundle="RunNativeGeneratedAudit")

    def test_plan_binds_canonical_template_and_local_chunks(self) -> None:
        plan = self._build()
        payload = plan.payload()

        self.assertEqual(payload["format"], INTERPRETER_KERNEL_RUN_NATIVE_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["template"]["bytes"], 341)
        self.assertEqual(payload["template"]["blocks"], 26)
        self.assertEqual(payload["template"]["instructions"], 102)
        self.assertEqual(payload["template"]["reviewed_profile"], "cdecl-o0-v1")
        self.assertEqual(payload["template"]["semantic_loop_header_offset"], 58)
        self.assertEqual(payload["template"]["backedge_latch_offsets"], [321])
        self.assertEqual(payload["template"]["masked_rel32_bytes"], [92, 93, 94, 95])
        self.assertEqual(payload["fixed_native_chunks"][0], {"id": "entry", "fuel": 18})
        self.assertIn(
            "RunFunctionNativeChunk.path",
            payload["constructed_lean_evidence"],
        )

    def test_rejects_byte_block_and_candidate_tampering(self) -> None:
        payload = _payload(self.candidate.read_bytes())
        function = payload["kernel_functions"][1]
        instruction = function["blocks"][0]["instructions"][1]
        instruction["bytes"] = "89e4"
        blob = b"".join(
            bytes.fromhex(item["bytes"])
            for block in function["blocks"]
            for item in block["instructions"]
        )
        function["sha256"] = hashlib.sha256(blob).hexdigest()
        self.kernel.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunNativeGenerationError,
            "reviewed O0 instruction template",
        ):
            self._build()

    def test_rejects_an_unreviewed_third_loop_record(self) -> None:
        payload = _payload(self.candidate.read_bytes())
        function = payload["kernel_functions"][1]
        function["loops"].extend(
            [
                dict(function["loops"][0]),
                dict(function["loops"][0]),
            ]
        )
        self.kernel.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunNativeGenerationError,
            "one or two checked backedge latches",
        ):
            self._build()

        payload = _payload(self.candidate.read_bytes())
        function = payload["kernel_functions"][1]
        function["blocks"][0]["instructions"].extend(
            function["blocks"][1]["instructions"]
        )
        del function["blocks"][1]
        self.kernel.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunNativeGenerationError,
            "block boundaries",
        ):
            self._build()

        candidate = self.candidate.read_bytes()
        self.kernel.write_text(json.dumps(_payload(candidate)), encoding="utf-8")
        self.candidate.write_bytes(candidate + b"tamper")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunNativeGenerationError,
            "different candidate PE",
        ):
            self._build()

    def test_generated_source_exposes_only_static_and_local_interfaces(self) -> None:
        source = relational_interpreter_kernel_run_native_source(self._build())
        for required in (
            "GeneratedRunFunctionNativeO0TemplateGoal",
            "generatedRunFunctionNativeTemplateCertificate",
            "GeneratedRunFunctionNativeLocalSemanticsGoal",
        ):
            self.assertIn(required, source)
        self.assertNotIn("GeneratedRunFunctionNativeMachineCertificateGoal", source)
        self.assertNotIn("GeneratedRunFunctionNativeRefinesUsing", source)
        for forbidden in (
            "whole_native_path",
            "caller_selected_final_state",
            "python_status_as_proof",
        ):
            self.assertNotIn(forbidden, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_writer_is_deterministic_and_validates_modules(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {"kernel_plan": self.kernel, "candidate_pe": self.candidate}
        write_relational_interpreter_kernel_run_native_bundle(out=first, **kwargs)
        write_relational_interpreter_kernel_run_native_bundle(out=second, **kwargs)
        for filename in (
            INTERPRETER_KERNEL_RUN_NATIVE_PLAN_FILENAME,
            INTERPRETER_KERNEL_RUN_NATIVE_LEAN_FILENAME,
        ):
            self.assertEqual(
                (first / filename).read_bytes(), (second / filename).read_bytes()
            )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunNativeGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_run_native_source(
                self._build(), run_module="Generated.Bad"
            )

    def test_current_round_trip_candidate_matches_output_state_template(self) -> None:
        kernel = Path(
            "/nix/store/5j5bqv7qyq9h8z2nprc61lvi17kql64n-"
            "stage-a-gnu-hello-roundtrip-compiled-kernel/"
            "interpreter-kernel-plan.json"
        )
        candidate = Path(
            "/nix/store/csx2ac6xi3kzaakrjxy7a8macilhb73l-"
            "stage-b-gnu-hello-roundtrip-candidate/candidate.exe"
        )
        if not kernel.is_file() or not candidate.is_file():
            self.skipTest("current round-trip artifacts are absent")

        plan = build_relational_interpreter_kernel_run_native_plan(
            kernel_plan=kernel, candidate_pe=candidate
        )

        payload = plan.payload()
        self.assertEqual(
            plan.candidate_sha256,
            ("657c3da82082f3898e7e3d38535b1303273fc310a246bdf7d870b9c0343b6d18"),
        )
        self.assertEqual(
            payload["template"]["reviewed_profile"], ("cdecl-o0-output-state-v2")
        )
        self.assertEqual(len(plan.run.function_bytes), 398)
        self.assertEqual(len(plan.run.blocks), 26)
        self.assertEqual(plan.run.instruction_count, 118)
        self.assertEqual(plan.run.direct_call_offsets, (97,))
        self.assertEqual(plan.run.indirect_call_offsets, (186,))
        self.assertEqual(plan.run.backedge_latch_offsets, (238, 378))
        self.assertEqual(payload["template"]["masked_rel32_bytes"], [98, 99, 100, 101])
        self.assertEqual(payload["fixed_native_chunks"][0], {"id": "entry", "fuel": 20})
        self.assertEqual(
            payload["fixed_native_chunks"][3],
            {"id": "resolver_prelude", "fuel": 21},
        )
        self.assertEqual(
            payload["fixed_native_chunks"][5]["fuel_by_status"],
            {
                "ok_returned": 22,
                "ok_external_jump": 25,
                "divide_error": 28,
                "memory_fault": 31,
                "external_fault": 34,
                "unimplemented": 34,
            },
        )
        self.assertNotIn(
            plan.candidate_sha256, relational_interpreter_kernel_run_native_source(plan)
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_native_core_compiles_with_only_approved_axioms(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        lean_root = self.root / "lean"
        stage_a = lean_root / "StageA"
        stage_a.mkdir(parents=True)
        _copy_module_closure(source_root, stage_a, "RelationalInterpreterKernelRun")

        result = _run_lean_relational(
            lean_root, bundle="RelationalInterpreterKernelRun"
        )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])
        self.assertIn("RunFunctionNativeChunk.path", result["stdout"])
        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_interface_compiles(self) -> None:
        plan = self._build()
        result = self._compile_generated_interface(plan)

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_current_output_state_template_compiles_and_decides(self) -> None:
        kernel = Path(
            "/nix/store/5j5bqv7qyq9h8z2nprc61lvi17kql64n-"
            "stage-a-gnu-hello-roundtrip-compiled-kernel/"
            "interpreter-kernel-plan.json"
        )
        candidate = Path(
            "/nix/store/csx2ac6xi3kzaakrjxy7a8macilhb73l-"
            "stage-b-gnu-hello-roundtrip-candidate/candidate.exe"
        )
        if not kernel.is_file() or not candidate.is_file():
            self.skipTest("current round-trip artifacts are absent")
        plan = build_relational_interpreter_kernel_run_native_plan(
            kernel_plan=kernel,
            candidate_pe=candidate,
        )

        result = self._compile_generated_interface(plan)

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])


_LEAN_DATA_FIXTURE = r"""import StageA.RelationalInterpreterKernelRun
namespace StageA.GeneratedRelational.InterpreterKernelData
open StageA.Formal
def generatedInterpreterKernelCandidatePe : PE32 := {
  bytes := ByteTree.ofBytes [0xc3]
  peOffset := 0
  entrypointRva := 0
  imageBase := 0x400000
  sectionAlignment := 1
  fileAlignment := 1
  sizeOfImage := 1
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
"""


_LEAN_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterKernelRun
import StageA.RunNativeDataFixture
namespace StageA.GeneratedRelational.InterpreterKernel
open StageA.Relational.InterpreterKernel
def generatedKernelFunction0001 : KernelFunction := {
  role := .runFunction
  hint := "fixture"
  span := { start := 4096, size := 1 }
  bytes := [0xc3]
  sha256 := "fixture"
  blocks := []
  x87Frames := []
  x87Commands := []
  padding := []
  loops := []
  frame := {
    required := true
    pushRva := 4096
    setupRva := 4096
    teardownRvas := []
    returnRvas := []
  }
}
def generatedCompiledKernelProgram : CompiledKernelProgram := {
  functions := [generatedKernelFunction0001]
}
end StageA.GeneratedRelational.InterpreterKernel
"""


_LEAN_CALLBACK_FIXTURE = r"""import StageA.RelationalInterpreterKernelRun
namespace StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCallback
def generatedKernelCallbackInventory : KernelCallbackInventory := { sites := [] }
end StageA.GeneratedRelational.InterpreterKernelCallback
"""


if __name__ == "__main__":
    unittest.main()
