from __future__ import annotations

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
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_lookup_native import (
    INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT,
    INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME,
    INTERPRETER_KERNEL_LOOKUP_NATIVE_PLAN_FILENAME,
    RelationalInterpreterKernelLookupNativeGenerationError,
    build_relational_interpreter_kernel_lookup_native_plan,
    relational_interpreter_kernel_lookup_native_source,
    write_relational_interpreter_kernel_lookup_native_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_summary import (
    _PROGRAM_LOOKUP_TEMPLATE_BLOCKS,
    _program_lookup_template_bytes,
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


def _function() -> dict[str, object]:
    start = 0x1000
    blob = _program_lookup_template_bytes(0x403020, 0x403000)
    offsets = sorted(
        offset
        for _, _, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        for offset in instructions
    )
    ends = {
        offset: offsets[index + 1] if index + 1 < len(offsets) else len(blob)
        for index, offset in enumerate(offsets)
    }
    return {
        "role": "programLookup",
        "rva_start": start,
        "rva_end": start + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": [
            {
                "entry_rva": start + entry,
                "successors": [start + successor for successor in successors],
                "instructions": [
                    {
                        "rva": start + offset,
                        "bytes": blob[offset : ends[offset]].hex(),
                    }
                    for offset in instructions
                ],
            }
            for entry, successors, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        ],
        "x87_frames": [],
    }


def _kernel_payload(candidate_sha256: str, candidate_size: int) -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
        "candidate": {
            "pe_sha256": candidate_sha256,
            "size": candidate_size,
        },
        "program": {"transfer_count": 7},
        "kernel_functions": [_function()],
        "issues": [],
    }


def _data_payload(candidate_sha256: str, candidate_size: int) -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_DATA_FORMAT,
        "candidate_sha256": candidate_sha256,
        "candidate_bytes": candidate_size,
        "table_rva": 0x3000,
        "count_rva": 0x3020,
        "counts": {"transfers": 7},
    }


class StageARelationalInterpreterKernelLookupNativeGenerationTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.kernel = self.root / "kernel.json"
        self.data = self.root / "data.json"
        candidate = b"exact candidate fixture" * 17
        self.candidate.write_bytes(candidate)
        digest = hashlib.sha256(candidate).hexdigest()
        self.kernel.write_text(
            json.dumps(_kernel_payload(digest, len(candidate))), encoding="utf-8"
        )
        self.data.write_text(
            json.dumps(_data_payload(digest, len(candidate))), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self):
        return build_relational_interpreter_kernel_lookup_native_plan(
            kernel_plan=self.kernel,
            data_inventory=self.data,
            candidate_pe=self.candidate,
        )

    def test_plan_binds_exact_candidate_and_fixed_chunks(self) -> None:
        plan = self._build()
        payload = plan.payload()

        self.assertEqual(payload["format"], INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["template"]["bytes"], 161)
        self.assertEqual(payload["template"]["blocks"], 10)
        self.assertEqual(payload["template"]["instructions"], 57)
        self.assertEqual(
            payload["fixed_native_chunks"],
            [
                {"id": "prologue", "fuel": 7},
                {"id": "lower_iteration", "fuel": 25},
                {"id": "upper_iteration", "fuel": 23},
                {"id": "finish", "fuel_min": 1, "fuel_max": 22},
                {"id": "epilogue", "fuel": 3},
            ],
        )
        self.assertEqual(
            payload["remaining_semantic_premises"],
            [],
        )
        self.assertIn(
            "programLookupNativeLocalSemantics",
            payload["constructed_lean_evidence"],
        )
        self.assertEqual(
            payload["remaining_static_premises"],
            [
                "programLookupNativeTemplateChecked",
                "ConcreteKernelABI.program_equals_generated_program",
            ],
        )
        self.assertNotIn("status", payload)

    def test_rejects_changed_candidate_and_changed_template(self) -> None:
        self.candidate.write_bytes(self.candidate.read_bytes() + b"tamper")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelLookupNativeGenerationError,
            "candidate PE identity",
        ):
            self._build()

        candidate = b"replacement candidate"
        digest = hashlib.sha256(candidate).hexdigest()
        self.candidate.write_bytes(candidate)
        kernel = _kernel_payload(digest, len(candidate))
        kernel["kernel_functions"][0]["blocks"][0]["instructions"][0][
            "bytes"
        ] = "54"
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self.data.write_text(
            json.dumps(_data_payload(digest, len(candidate))), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelLookupNativeGenerationError,
            "SHA-256 does not match|bytes do not match",
        ):
            self._build()

    def test_source_has_no_submitted_whole_path_or_final_state(self) -> None:
        source = relational_interpreter_kernel_lookup_native_source(self._build())
        for required in (
            "generatedProgramLookupNativeTemplateCertificate",
            "programLookupTemplateCertificateToNative",
            "GeneratedProgramLookupNativeTemplateCheckedGoal",
            "generatedProgramLookupNativeParametersExact",
            "generatedProgramLookupNativeLocalSemantics",
            "ProgramLookupNativeLocalSemantics",
            "programLookupNativeLocalSemantics",
            "generatedProgramLookupNativeConcreteABI",
            "ProgramLookupNativeConcreteABI",
            "GeneratedProgramLookupNativeRefinesUsing",
            "semantics.programLookupRefinesUsingNative",
            "NativeDispatches",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "whole_native_path",
            "caller_selected_final_state",
            "python_status_as_proof",
            "GeneratedProgramLookupNativeLocalSemanticsGoal",
            "(semantics :",
        ):
            self.assertNotIn(forbidden, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_writer_is_deterministic_and_validates_module_names(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "kernel_plan": self.kernel,
            "data_inventory": self.data,
            "candidate_pe": self.candidate,
        }
        write_relational_interpreter_kernel_lookup_native_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_lookup_native_bundle(
            out=second, **kwargs
        )
        self.assertEqual(
            (first / INTERPRETER_KERNEL_LOOKUP_NATIVE_PLAN_FILENAME).read_bytes(),
            (second / INTERPRETER_KERNEL_LOOKUP_NATIVE_PLAN_FILENAME).read_bytes(),
        )
        self.assertEqual(
            (first / INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME).read_bytes(),
            (second / INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME).read_bytes(),
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelLookupNativeGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_lookup_native_source(
                self._build(), kernel_module="Generated.Bad"
            )

    def test_current_round_trip_candidate_uses_same_generic_template(self) -> None:
        repository = Path(__file__).parents[1]
        kernel = repository / (
            "build/stage-b-gnu-hello-roundtrip/interpreter-kernel-v7/"
            "interpreter-kernel-plan.json"
        )
        data = repository / (
            "build/stage-b-gnu-hello-roundtrip/interpreter-kernel-data-v2/"
            "module-inventory.json"
        )
        candidate = Path(
            "/nix/store/qr6q0j24yzfjxzyhrbyxhb2al6npm394-"
            "stage-b-gnu-hello-roundtrip-candidate/candidate.exe"
        )
        if not kernel.is_file() or not data.is_file() or not candidate.is_file():
            self.skipTest("current round-trip artifacts are absent")

        plan = build_relational_interpreter_kernel_lookup_native_plan(
            kernel_plan=kernel,
            data_inventory=data,
            candidate_pe=candidate,
        )
        source = relational_interpreter_kernel_lookup_native_source(plan)

        self.assertEqual(
            plan.summary.function_end_rva - plan.summary.function_entry_rva,
            161,
        )
        self.assertEqual(plan.summary.block_count, 10)
        self.assertEqual(len(plan.summary.instruction_rvas), 57)
        self.assertLess(len(source.encode("ascii")), 32_768)
        self.assertNotIn(plan.candidate_sha256, source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_native_support_composition_compiles(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        native_source = (
            source_root / "RelationalInterpreterKernelLookupNative.lean"
        ).read_text(encoding="utf-8")
        executor_reductions = [
            line
            for line in native_source.splitlines()
            if "executeInstruction," in line
        ]
        self.assertTrue(executor_reductions)
        self.assertTrue(
            all(
                "executeInstructionWithContext" in line
                for line in executor_reductions
            )
        )
        lean_root = self.root / "native-support"
        stage_a = lean_root / "StageA"
        stage_a.mkdir(parents=True)
        _copy_module_closure(
            source_root, stage_a, "RelationalInterpreterKernelLookupNative"
        )

        result = _run_lean_relational(
            lean_root, bundle="RelationalInterpreterKernelLookupNative"
        )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_interface_and_native_composition_compile(self) -> None:
        generated = relational_interpreter_kernel_lookup_native_source(
            self._build(),
            kernel_module="StageA.LookupNativeKernelFixture",
            summary_module="StageA.LookupNativeSummaryFixture",
            data_module="StageA.LookupNativeDataFixture",
        )
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        lean_root = self.root / "lean"
        stage_a = lean_root / "StageA"
        stage_a.mkdir(parents=True)
        _copy_module_closure(
            source_root, stage_a, "RelationalInterpreterKernelLookupNative"
        )
        _copy_module_closure(
            source_root, stage_a, "RelationalInterpreterKernelLookupABI"
        )
        (stage_a / "LookupNativeKernelFixture.lean").write_text(
            _LEAN_KERNEL_FIXTURE, encoding="utf-8"
        )
        (stage_a / "LookupNativeDataFixture.lean").write_text(
            _LEAN_DATA_FIXTURE.replace(
                "__TEMPLATE_BYTES__",
                ", ".join(
                    str(value)
                    for value in _program_lookup_template_bytes(0x403020, 0x403000)
                ),
            ),
            encoding="utf-8",
        )
        (stage_a / "LookupNativeSummaryFixture.lean").write_text(
            "import StageA.RelationalInterpreterKernelSummary\n",
            encoding="utf-8",
        )
        (
            stage_a / "GeneratedRelationalInterpreterKernelLookupNative.lean"
        ).write_text(generated, encoding="utf-8")

        result = _run_lean_relational(
            lean_root, bundle="GeneratedRelationalInterpreterKernelLookupNative"
        )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])


_LEAN_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterKernel
namespace StageA.GeneratedRelational.InterpreterKernel
open StageA.Relational.InterpreterKernel
def generatedKernelFunction0000 : KernelFunction := {
  role := .programLookup
  hint := "fixture"
  span := { start := 0x1000, size := 161 }
  bytes := [0xc3]
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
  functions := [generatedKernelFunction0000]
}
end StageA.GeneratedRelational.InterpreterKernel
"""


_LEAN_DATA_FIXTURE = r"""import StageA.RelationalInterpreterKernelData
namespace StageA.GeneratedRelational.InterpreterKernelData
open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
def generatedInterpreterKernelCandidatePe : PE32 := {
  bytes := ByteTree.ofBytes [__TEMPLATE_BYTES__]
  peOffset := 0
  entrypointRva := 0x1000
  imageBase := 0x400000
  sectionAlignment := 0x1000
  fileAlignment := 1
  sizeOfImage := 0x4000
  sizeOfHeaders := 0
  importDirectoryRva := 0
  importDirectorySize := 0
  tlsDirectoryRva := 0
  tlsDirectorySize := 0
  relocationDirectoryRva := 0
  relocationDirectorySize := 0
  sections := [{
    virtualSize := 161
    virtualAddress := 0x1000
    rawSize := 161
    rawPointer := 0
    characteristics := 0x60000020
  }]
}
def generatedInterpreterKernelImports : List PEImport := []
def generatedInterpreterKernelRelocations : List BaseRelocation := []
def generatedInterpreterKernelTableRva : Nat := 0x3000
def generatedInterpreterKernelCountRva : Nat := 0x3020
def semanticInterpreterProgramRecords : List ProgramRecord := []
end StageA.GeneratedRelational.InterpreterKernelData
"""


if __name__ == "__main__":
    unittest.main()
