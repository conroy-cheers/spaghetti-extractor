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
from spaghetti_extractor.relational.lean.interpreter_kernel_run import (
    INTERPRETER_KERNEL_RUN_FORMAT,
    INTERPRETER_KERNEL_RUN_LEAN_FILENAME,
    INTERPRETER_KERNEL_RUN_PLAN_FILENAME,
    RelationalInterpreterKernelRunGenerationError,
    build_relational_interpreter_kernel_run_plan,
    relational_interpreter_kernel_run_source,
    write_relational_interpreter_kernel_run_bundle,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_START = 0x1000
_STEP = 0x2000


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


def _run_function() -> dict[str, object]:
    call = _rel32(_START + 3, _STEP)
    instructions = (
        (0, b"\x55", "push"),
        (1, b"\x89\xe5", "mov"),
        (3, call, "call"),
        (8, b"\xff\xd0", "call"),
        (10, b"\xeb\xf7", "jmp"),
        (12, b"\xc9", "leave"),
        (13, b"\xc3", "ret"),
    )
    blob = b"".join(data for _, data, _ in instructions)
    by_offset = {offset: (data, mnemonic) for offset, data, mnemonic in instructions}

    def block(
        entry: int, offsets: tuple[int, ...], successors: list[int]
    ) -> dict[str, object]:
        return {
            "entry_rva": _START + entry,
            "instructions": [
                {
                    "rva": _START + offset,
                    "bytes": by_offset[offset][0].hex(),
                    "mnemonic": by_offset[offset][1],
                }
                for offset in offsets
            ],
            "successors": successors,
        }

    return {
        "role": "runFunction",
        "rva_start": _START,
        "rva_end": _START + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": [
            block(0, (0, 1), [_START + 3]),
            block(3, (3,), [_STEP, _START + 8]),
            block(8, (8,), [_START + 10]),
            block(10, (10,), [_START + 3]),
            block(12, (12, 13), []),
        ],
        "loops": [
            {
                "header_rva": _START + 3,
                "latch_rva": _START + 10,
                "body_entries": [_START + 3, _START + 8, _START + 10],
            }
        ],
        "x87_frames": [],
        "x87_commands": [],
        "padding": [],
        "frame": {
            "required": True,
            "push_rva": _START,
            "setup_rva": _START + 1,
            "teardown_rvas": [_START + 12],
            "return_rvas": [_START + 13],
        },
    }


def _two_latch_run_function() -> dict[str, object]:
    function = copy.deepcopy(_run_function())
    blocks = function["blocks"]
    blocks[3]["instructions"][0]["bytes"] = "75f7"
    blocks[3]["successors"] = [_START + 3, _START + 12]
    epilogue = blocks.pop()
    for instruction in epilogue["instructions"]:
        instruction["rva"] += 2
    epilogue["entry_rva"] += 2
    blocks.append(
        {
            "entry_rva": _START + 12,
            "instructions": [
                {
                    "rva": _START + 12,
                    "bytes": "ebf5",
                    "mnemonic": "jmp",
                }
            ],
            "successors": [_START + 3],
        }
    )
    blocks.append(epilogue)
    function["loops"].append(
        {
            "header_rva": _START + 3,
            "latch_rva": _START + 12,
            "body_entries": [
                _START + 3,
                _START + 8,
                _START + 10,
                _START + 12,
            ],
        }
    )
    function["rva_end"] += 2
    function["size"] += 2
    function["frame"]["teardown_rvas"] = [_START + 14]
    function["frame"]["return_rvas"] = [_START + 15]
    blob = b"".join(
        bytes.fromhex(instruction["bytes"])
        for block in blocks
        for instruction in block["instructions"]
    )
    function["sha256"] = hashlib.sha256(blob).hexdigest()
    return function


def _payload() -> dict[str, object]:
    return {
        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
        "candidate": {"pe_sha256": "a" * 64, "size": 0x8000},
        "kernel_functions": [
            {"role": "interpreterStep", "rva_start": _STEP},
            _run_function(),
        ],
        "issues": [
            {
                "code": "unsupported_indirect_kernel_call",
                "function_role": "runFunction",
                "rva_start": _START + 8,
                "rva_end": _START + 10,
            }
        ],
    }


class StageARelationalInterpreterKernelRunGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.plan_path = self.root / "kernel.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, payload: dict[str, object] | None = None) -> None:
        self.plan_path.write_text(json.dumps(payload or _payload()), encoding="utf-8")

    def test_reflects_complete_loop_call_and_return_shape(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_run_plan(self.plan_path)

        self.assertEqual(plan.function_entry_rva, _START)
        self.assertEqual(plan.function_end_rva, _START + 14)
        self.assertEqual(plan.instruction_count, 7)
        self.assertEqual(plan.direct_call_offsets, (3,))
        self.assertEqual(plan.direct_call_targets, (_STEP,))
        self.assertEqual(plan.indirect_call_offsets, (8,))
        self.assertEqual(plan.return_offsets, (13,))
        self.assertEqual(plan.loops[0].body_offsets, (3, 8, 10))
        self.assertEqual(plan.semantic_loop_header_offset, 3)
        self.assertEqual(plan.backedge_latch_offsets, (10,))
        self.assertEqual(
            plan.specialized_dependencies, ("interpreter-kernel-indirect",)
        )
        payload = plan.payload()
        self.assertEqual(payload["format"], INTERPRETER_KERNEL_RUN_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["status"], "semantic_proof_required")
        self.assertEqual(
            payload["loop_inventory"]["latch_offsets"],
            [10],
        )

    def test_reflects_one_semantic_header_with_two_exact_latches(self) -> None:
        payload = _payload()
        payload["kernel_functions"][1] = _two_latch_run_function()
        self._write(payload)

        plan = build_relational_interpreter_kernel_run_plan(self.plan_path)

        self.assertEqual(plan.function_end_rva, _START + 16)
        self.assertEqual(plan.semantic_loop_header_offset, 3)
        self.assertEqual(plan.backedge_latch_offsets, (10, 12))
        self.assertEqual(
            [loop.body_offsets for loop in plan.loops],
            [(3, 8, 10), (3, 8, 10, 12)],
        )
        self.assertEqual(
            plan.payload()["function"]["semantic_loop_headers"],
            1,
        )
        self.assertEqual(plan.payload()["function"]["backedge_latches"], 2)

    def test_rejects_unbounded_or_inexact_loop_inventory(self) -> None:
        payload = _payload()
        function = payload["kernel_functions"][1]
        function["loops"].extend(
            [
                copy.deepcopy(function["loops"][0]),
                copy.deepcopy(function["loops"][0]),
            ]
        )
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunGenerationError,
            "one or two checked backedge latches",
        ):
            build_relational_interpreter_kernel_run_plan(self.plan_path)

        payload = _payload()
        function = payload["kernel_functions"][1]
        function["loops"][0]["latch_rva"] = _START + 8
        function["loops"][0]["body_entries"] = [_START + 3, _START + 8]
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunGenerationError,
            "does not exactly match its CFG backedges",
        ):
            build_relational_interpreter_kernel_run_plan(self.plan_path)

    def test_generated_source_exposes_static_and_phase_goals_only(self) -> None:
        self._write()
        source = relational_interpreter_kernel_run_source(
            build_relational_interpreter_kernel_run_plan(self.plan_path),
            data_module="StageA.GeneratedRelationalInterpreterKernelRunFixtureData",
        )

        for required in (
            "generatedRunFunctionTemplate",
            "GeneratedRunFunctionTemplateGoal",
            "generatedKernelCallbackInventory",
            "ExactDecodeInventory",
            "GeneratedRunFunctionMachineCertificateGoal",
            "GeneratedRunFunctionRefines",
            "certificate.refines",
            "StageA.GeneratedRelational.InterpreterKernelData",
        ):
            self.assertIn(required, source)
        self.assertNotRegex(source, r"\bsimulate\s*:")
        self.assertNotRegex(source, r"\brefinement\s*:")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_tampered_bytes_target_frontier_and_candidate(self) -> None:
        payload = _payload()
        function = copy.deepcopy(payload["kernel_functions"][1])
        function["blocks"][0]["instructions"][0]["bytes"] = "90"
        payload["kernel_functions"][1] = function
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunGenerationError,
            "disagree with its digest",
        ):
            build_relational_interpreter_kernel_run_plan(self.plan_path)

        payload = _payload()
        function = payload["kernel_functions"][1]
        tampered = _rel32(_START + 3, _STEP + 4)
        function["blocks"][1]["instructions"][0]["bytes"] = tampered.hex()
        blob = b"".join(
            bytes.fromhex(instruction["bytes"])
            for block in function["blocks"]
            for instruction in block["instructions"]
        )
        function["sha256"] = hashlib.sha256(blob).hexdigest()
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunGenerationError,
            "interpreterStep call",
        ):
            build_relational_interpreter_kernel_run_plan(self.plan_path)

        payload = _payload()
        payload["issues"] = []
        self._write(payload)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunGenerationError,
            "frontier inventory is incomplete",
        ):
            build_relational_interpreter_kernel_run_plan(self.plan_path)

        self._write()
        candidate = self.root / "candidate.exe"
        candidate.write_bytes(b"not-the-bound-candidate")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelRunGenerationError,
            "different candidate PE",
        ):
            build_relational_interpreter_kernel_run_plan(
                self.plan_path, candidate_pe=candidate
            )

    def test_x87_is_an_explicit_fail_closed_dependency(self) -> None:
        payload = _payload()
        payload["kernel_functions"][1]["x87_commands"] = [
            {"rva": _START + 8, "bytes": "d9e8", "mnemonic": "fld1"}
        ]
        self._write(payload)

        plan = build_relational_interpreter_kernel_run_plan(self.plan_path)

        self.assertEqual(
            plan.specialized_dependencies,
            ("interpreter-kernel-indirect", "interpreter-kernel-x87"),
        )
        self.assertEqual(plan.payload()["status"], "incomplete")

    def test_writer_is_deterministic(self) -> None:
        self._write()
        first = self.root / "first"
        second = self.root / "second"
        write_relational_interpreter_kernel_run_bundle(
            kernel_plan=self.plan_path,
            out=first,
            data_module="StageA.GeneratedRelationalInterpreterKernelRunFixtureData",
        )
        write_relational_interpreter_kernel_run_bundle(
            kernel_plan=self.plan_path,
            out=second,
            data_module="StageA.GeneratedRelationalInterpreterKernelRunFixtureData",
        )
        for filename in (
            INTERPRETER_KERNEL_RUN_PLAN_FILENAME,
            INTERPRETER_KERNEL_RUN_LEAN_FILENAME,
        ):
            self.assertEqual(
                (first / filename).read_bytes(), (second / filename).read_bytes()
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_goal_compiles_without_the_huge_kernel_module(self) -> None:
        self._write()
        plan = build_relational_interpreter_kernel_run_plan(self.plan_path)
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalInterpreterKernelRun")
            (stage_a / "GeneratedRelationalInterpreterKernel.lean").write_text(
                """import StageA.RelationalInterpreterKernelRun

namespace StageA.GeneratedRelational.InterpreterKernel

open StageA.Relational.InterpreterKernel

def generatedKernelFunction0001 : KernelFunction := {
  role := .runFunction
  hint := "fixture"
  span := { start := 4096, size := 14 }
  bytes := []
  sha256 := "fixture"
  blocks := []
  x87Frames := []
  x87Commands := []
  padding := []
  loops := []
  frame := {
    required := true
    pushRva := 4096
    setupRva := 4097
    teardownRvas := [4108]
    returnRvas := [4109]
  }
}

def generatedCompiledKernelProgram : CompiledKernelProgram := {
  functions := [generatedKernelFunction0001]
}

end StageA.GeneratedRelational.InterpreterKernel
""",
                encoding="utf-8",
            )
            (stage_a / "GeneratedRelationalInterpreterKernelCallback.lean").write_text(
                """import StageA.RelationalInterpreterKernelRun

namespace StageA.GeneratedRelational.InterpreterKernelCallback

open StageA.Relational.InterpreterKernelCallback

def generatedKernelCallbackInventory : KernelCallbackInventory := { sites := [] }

end StageA.GeneratedRelational.InterpreterKernelCallback
""",
                encoding="utf-8",
            )
            (
                stage_a / "GeneratedRelationalInterpreterKernelRunFixtureData.lean"
            ).write_text(
                """import StageA.RelationalInterpreterKernelRun

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
""",
                encoding="utf-8",
            )
            (stage_a / INTERPRETER_KERNEL_RUN_LEAN_FILENAME).write_text(
                relational_interpreter_kernel_run_source(
                    plan,
                    data_module=(
                        "StageA.GeneratedRelationalInterpreterKernelRunFixtureData"
                    ),
                ),
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="GeneratedRelationalInterpreterKernelRun"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'sorry'", result["stderr"])

    def test_current_exact_candidate_has_two_checked_latches(self) -> None:
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
            self.skipTest("exact GNU candidate PE is not present")

        plan = build_relational_interpreter_kernel_run_plan(
            kernel, candidate_pe=candidate
        )

        self.assertEqual(plan.function_index, 39)
        self.assertEqual(
            plan.candidate_sha256,
            "657c3da82082f3898e7e3d38535b1303273fc310a246bdf7d870b9c0343b6d18",
        )
        self.assertEqual(plan.function_entry_rva, 310608)
        self.assertEqual(plan.function_end_rva, 311006)
        self.assertEqual(
            plan.function_sha256,
            "47a5818fbc2ea6a6d640a5a7c839bccc6acef6f9ad168baacb0745eab012da81",
        )
        self.assertEqual(len(plan.blocks), 26)
        self.assertEqual(plan.instruction_count, 118)
        self.assertEqual(plan.direct_call_offsets, (97,))
        self.assertEqual(plan.direct_call_targets, (307914,))
        self.assertEqual(plan.indirect_call_offsets, (186,))
        self.assertEqual(plan.return_offsets, (397,))
        self.assertEqual(plan.semantic_loop_header_offset, 64)
        self.assertEqual(plan.backedge_latch_offsets, (238, 378))
        self.assertEqual(
            plan.overlapping_issue_codes,
            ("unsupported_indirect_kernel_call",),
        )


if __name__ == "__main__":
    unittest.main()
