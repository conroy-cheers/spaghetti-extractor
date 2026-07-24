from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_summary import (
    INTERPRETER_KERNEL_SUMMARY_FORMAT,
    INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME,
    INTERPRETER_KERNEL_SUMMARY_PLAN_FILENAME,
    RelationalInterpreterKernelSummaryGenerationError,
    build_relational_interpreter_kernel_summary_plan,
    relational_interpreter_kernel_summary_source,
    write_relational_interpreter_kernel_summary_bundle,
    _PROGRAM_LOOKUP_TEMPLATE_BLOCKS,
    _program_lookup_template_bytes,
)


_CANDIDATE_SHA256 = "a" * 64
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


def _function(*, role: str = "programLookup") -> dict[str, object]:
    start = 0x1000
    blob = _program_lookup_template_bytes(0x403020, 0x403000)
    instruction_offsets = sorted(
        offset
        for _, _, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        for offset in instructions
    )
    instruction_ends = {
        offset: (
            instruction_offsets[index + 1]
            if index + 1 < len(instruction_offsets)
            else len(blob)
        )
        for index, offset in enumerate(instruction_offsets)
    }
    return {
        "role": role,
        "lookup_hint": "toolchain-specific-name-is-not-semantic",
        "rva_start": start,
        "rva_end": start + len(blob),
        "size": len(blob),
        "sha256": sha256(blob).hexdigest(),
        "blocks": [
            {
                "entry_rva": start + entry,
                "instructions": [
                    {
                        "rva": start + offset,
                        "bytes": blob[offset : instruction_ends[offset]].hex(),
                        "mnemonic": "reflected",
                    }
                    for offset in instructions
                ],
                "successors": [start + successor for successor in successors],
            }
            for entry, successors, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        ],
        "x87_frames": [],
        "padding": [],
        "loops": [],
        "frame": {
            "required": True,
            "push_rva": 0x1000,
            "setup_rva": 0x1001,
            "teardown_rvas": [],
            "return_rvas": [start + 160],
        },
    }


def _kernel_payload() -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
        "candidate": {"pe_sha256": _CANDIDATE_SHA256, "size": 8192},
        "program": {"transfer_count": 7},
        "kernel_functions": [_function()],
        "issues": [],
    }


def _data_payload() -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_DATA_FORMAT,
        "candidate_sha256": _CANDIDATE_SHA256,
        "candidate_bytes": 8192,
        "table_rva": 0x3000,
        "count_rva": 0x3020,
        "counts": {"transfers": 7},
    }


class StageARelationalInterpreterKernelSummaryGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.kernel_path = self.root / "kernel.json"
        self.data_path = self.root / "data.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(
        self,
        kernel: dict[str, object] | None = None,
        data: dict[str, object] | None = None,
    ) -> None:
        self.kernel_path.write_text(
            json.dumps(kernel or _kernel_payload()), encoding="utf-8"
        )
        self.data_path.write_text(
            json.dumps(data or _data_payload()), encoding="utf-8"
        )

    def test_cross_checks_exact_function_and_data_parameters(self) -> None:
        self._write()

        plan = build_relational_interpreter_kernel_summary_plan(
            self.kernel_path, self.data_path
        )

        self.assertEqual(plan.function_index, 0)
        self.assertEqual(plan.function_entry_rva, 0x1000)
        self.assertEqual(plan.function_end_rva, 0x10A1)
        self.assertEqual(len(plan.instruction_rvas), 57)
        self.assertEqual(plan.transfer_count, 7)
        self.assertEqual(plan.table_rva, 0x3000)
        self.assertEqual(plan.count_rva, 0x3020)
        self.assertEqual(plan.image_base, 0x400000)
        self.assertEqual(plan.table_absolute_address, 0x403000)
        self.assertEqual(plan.count_absolute_address, 0x403020)
        payload = plan.payload()
        self.assertEqual(payload["format"], INTERPRETER_KERNEL_SUMMARY_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["operation"], "programLookup")
        self.assertEqual(
            payload["data"]["relocations"], "parsed-from-candidate-pe"
        )
        self.assertIn(
            "reflected_template_execution", payload["required_proof_fields"]
        )
        self.assertIn(
            "exact_candidate_pe_parse", payload["required_proof_fields"]
        )
        self.assertIn(
            "rank_high_sub_low_strictly_decreases",
            payload["required_proof_fields"],
        )

    def test_generated_source_requires_summary_and_builds_real_refinement(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_summary_plan(
            self.kernel_path, self.data_path
        )

        source = relational_interpreter_kernel_summary_source(plan)

        self.assertIn("generatedProgramLookupTemplateParameters", source)
        self.assertIn("entryRva := 4096", source)
        self.assertIn("tableRva := 12288", source)
        self.assertIn("countRva := 12320", source)
        self.assertIn("GeneratedProgramLookupTemplateReflectionGoal", source)
        self.assertIn("GeneratedProgramLookupTemplateCheckedGoal", source)
        self.assertIn("generatedProgramLookupTemplateCertificate", source)
        self.assertIn("GeneratedProgramLookupKernelFunctionSummaryGoal", source)
        self.assertIn("Nonempty (KernelFunctionSummary", source)
        self.assertIn("GeneratedProgramLookupExecutionSummary", source)
        self.assertIn("ProgramLookupConcreteEntry", source)
        self.assertNotIn(
            "(entry : ProgramLookupLoadedEntry", source
        )
        self.assertIn(
            "GeneratedProgramLookupRefinesUsingReflectedTemplate", source
        )
        self.assertIn("KernelOperationRefinesUsing", source)
        self.assertIn("ProgramLookupTemplateDispatches", source)
        self.assertIn("summary.programLookupRefinesUsingTemplate", source)
        self.assertIn("generatedInterpreterKernelRelocations", source)
        self.assertIn("generatedInterpreterKernelTableRva", source)
        self.assertIn("generatedInterpreterKernelCountRva", source)
        self.assertNotIn("pending_lean_proof", source)
        self.assertNotIn("stage_b_program_lookup", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_writer_is_deterministic_and_emits_only_non_authoritative_goal(self) -> None:
        self._write()
        first = self.root / "first"
        second = self.root / "second"

        first_plan = write_relational_interpreter_kernel_summary_bundle(
            kernel_plan=self.kernel_path,
            data_inventory=self.data_path,
            out=first,
        )
        second_plan = write_relational_interpreter_kernel_summary_bundle(
            kernel_plan=self.kernel_path,
            data_inventory=self.data_path,
            out=second,
        )

        self.assertEqual(first_plan.payload(), second_plan.payload())
        self.assertEqual(
            (first / INTERPRETER_KERNEL_SUMMARY_PLAN_FILENAME).read_bytes(),
            (second / INTERPRETER_KERNEL_SUMMARY_PLAN_FILENAME).read_bytes(),
        )
        self.assertEqual(
            (first / INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME).read_bytes(),
            (second / INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME).read_bytes(),
        )

    def test_rejects_candidate_or_transfer_count_mismatch(self) -> None:
        data = _data_payload()
        data["candidate_sha256"] = "c" * 64
        self._write(data=data)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "different candidate PE bytes",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

        data = _data_payload()
        data["counts"] = {"transfers": 8}
        self._write(data=data)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "disagree on transfer count",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

    def test_rejects_ambiguous_or_structurally_unresolved_lookup(self) -> None:
        kernel = _kernel_payload()
        kernel["kernel_functions"] = [_function(), _function()]
        self._write(kernel=kernel)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "2 programLookup functions",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

        kernel = _kernel_payload()
        kernel["issues"] = [
            {
                "code": "unsupported_instruction_semantics",
                "function_role": "programLookup",
            }
        ]
        self._write(kernel=kernel)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "unresolved kernel issues",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

    def test_rejects_malformed_instruction_inventory_and_module_names(self) -> None:
        kernel = _kernel_payload()
        function = kernel["kernel_functions"][0]
        function["blocks"][0]["instructions"][0]["bytes"] = ""
        self._write(kernel=kernel)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "non-empty string",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

        self._write()
        plan = build_relational_interpreter_kernel_summary_plan(
            self.kernel_path, self.data_path
        )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_summary_source(
                plan, kernel_module="Generated.Bad"
            )

    def test_rejects_template_byte_cfg_and_operand_changes(self) -> None:
        kernel = _kernel_payload()
        function = kernel["kernel_functions"][0]
        function["blocks"][0]["instructions"][0]["bytes"] = "54"
        self._write(kernel=kernel)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "SHA-256 does not match",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

        kernel = _kernel_payload()
        function = kernel["kernel_functions"][0]
        function["blocks"][0]["instructions"][0]["bytes"] = "54"
        blob = b"".join(
            bytes.fromhex(instruction["bytes"])
            for block in function["blocks"]
            for instruction in block["instructions"]
        )
        function["sha256"] = sha256(blob).hexdigest()
        self._write(kernel=kernel)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "bytes do not match",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

        kernel = _kernel_payload()
        function = kernel["kernel_functions"][0]
        function["blocks"][1]["successors"].reverse()
        self._write(kernel=kernel)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "decoded CFG does not match",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

        data = _data_payload()
        data["table_rva"] = 0x3004
        self._write(data=data)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelSummaryGenerationError,
            "different PE image bases",
        ):
            build_relational_interpreter_kernel_summary_plan(
                self.kernel_path, self.data_path
            )

    def test_latest_gnu_v3_program_lookup_generates_checked_source(self) -> None:
        repository = Path(__file__).parents[1]
        kernel = repository / (
            "build/stage-b-gnu-hello-roundtrip/interpreter-kernel-v3/"
            "interpreter-kernel-plan.json"
        )
        data = repository / (
            "build/stage-b-gnu-hello-roundtrip/interpreter-kernel-data-v1/"
            "module-inventory.json"
        )
        if not kernel.is_file() or not data.is_file():
            self.skipTest("latest GNU interpreter-kernel artifacts are absent")

        plan = build_relational_interpreter_kernel_summary_plan(kernel, data)
        source = relational_interpreter_kernel_summary_source(plan)

        self.assertEqual(plan.candidate_sha256,
            "5e4592bdeddb876c5da8d8db50ef56b1f0628b907ea09bd1d57931c65513cc22")
        self.assertEqual(plan.function_index, 49)
        self.assertEqual(plan.function_entry_rva, 414619)
        self.assertEqual(plan.function_end_rva, 414780)
        self.assertEqual(plan.block_count, 10)
        self.assertEqual(len(plan.instruction_rvas), 57)
        self.assertEqual(plan.transfer_count, 5326)
        self.assertEqual(plan.table_rva, 9761312)
        self.assertEqual(plan.count_rva, 9974352)
        self.assertIn("entryRva := 414619", source)
        self.assertNotIn("304738", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_summary_goal_and_bridges_compile(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_summary_plan(
            self.kernel_path, self.data_path
        )
        generated = relational_interpreter_kernel_summary_source(
            plan,
            kernel_module="StageA.SummaryKernelFixture",
            data_module="StageA.SummaryDataFixture",
        )
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        lean_root = self.root / "lean"
        stage_a = lean_root / "StageA"
        stage_a.mkdir(parents=True)
        _copy_module_closure(
            source_root, stage_a, "RelationalInterpreterKernelSummary"
        )
        (stage_a / "SummaryKernelFixture.lean").write_text(
            _LEAN_KERNEL_FIXTURE, encoding="utf-8"
        )
        (stage_a / "SummaryDataFixture.lean").write_text(
            _LEAN_DATA_FIXTURE, encoding="utf-8"
        )
        (stage_a / "GeneratedRelationalInterpreterKernelSummary.lean").write_text(
            generated, encoding="utf-8"
        )

        result = _run_lean_relational(
            lean_root, bundle="GeneratedRelationalInterpreterKernelSummary"
        )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])


_LEAN_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterKernelSummary

namespace StageA.GeneratedRelational.InterpreterKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

def generatedKernelFunction0000 : KernelFunction := {
  role := .programLookup
  hint := "fixture"
  span := { start := 0, size := 1 }
  bytes := [0xc3]
  sha256 := "0000000000000000000000000000000000000000000000000000000000000000"
  blocks := []
  x87Frames := []
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


_LEAN_DATA_FIXTURE = r"""import StageA.RelationalInterpreterKernelSummary

namespace StageA.GeneratedRelational.InterpreterKernelData

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter

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
def generatedInterpreterKernelRelocations : List BaseRelocation := []
def generatedInterpreterKernelTableRva : Nat := 0
def generatedInterpreterKernelCountRva : Nat := 0
def semanticInterpreterProgramRecords : List ProgramRecord := []

end StageA.GeneratedRelational.InterpreterKernelData
"""


if __name__ == "__main__":
    unittest.main()
