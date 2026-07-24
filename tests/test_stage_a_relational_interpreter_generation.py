from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter import (
    RelationalInterpreterGenerationError,
    relational_interpreter_program_source,
    relational_interpreter_source,
)
from spaghetti_extractor.stage_b_interpreter_backend import (
    _Action,
    _Node,
    compile_stage_b_interpreter_program,
)


_SHA_A = "a" * 64
_SHA_B = "b" * 64


def _register_inputs() -> dict[str, dict[str, object]]:
    return {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }


def _flag_inputs() -> dict[str, dict[str, object]]:
    return {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }


def _row() -> dict[str, Any]:
    address = {"op": "const", "value": 0x2000, "width": 32}
    zero = {"op": "const", "value": 0, "width": 32}
    one = {"op": "const", "value": 1, "width": 32}
    response = {
        "op": "call_response",
        "call_index": 1,
        "register": "eax",
    }
    response_flag = {
        "op": "call_flag",
        "call_index": 1,
        "flag": "zf",
    }
    return {
        "id": "semantic-transfer:generic-fixture",
        "contract_sha256": _SHA_A,
        "instruction_bytes_sha256": _SHA_B,
        "original": {"rva_start": 0x1000, "rva_end": 0x1014, "size": 0x14},
        "ordered_events": [
            {
                "family": "memory",
                "kind": "read",
                "width": 4,
                "address": address,
            },
            {
                "family": "memory",
                "kind": "write",
                "width": 4,
                "address": address,
                "value": one,
            },
            {
                "family": "fault",
                "kind": "divide_error",
                "condition": {"op": "false"},
            },
            {
                "family": "external",
                "kind": "rep_movsd",
                "source": address,
                "destination": {
                    "op": "const",
                    "value": 0x3000,
                    "width": 32,
                },
                "count": one,
                "direction_flag": {"op": "false"},
            },
            {
                "family": "external",
                "kind": "external_call",
                "instruction_rva": 0x1008,
                "return_rva": 0x100D,
                "dll": "example.dll",
                "symbol": "Operation",
                "ordinal": None,
                "register_inputs": _register_inputs(),
                "flag_inputs": _flag_inputs(),
                "arguments": [one],
                "stack_inputs": [{"offset": 0, "width": 4, "value": one}],
            },
        ],
        "register_writes": [{"register": "eax", "value": response}],
        "flag_writes": [{"flag": "zf", "value": response_flag}],
        "fpu_state": None,
        "outcome": {
            "kind": "branch",
            "condition": {"op": "eq", "args": [response, zero]},
            "true_target_rva": 0x1010,
            "false_target_rva": 0x1014,
        },
    }


def _write_machine(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


class StageARelationalInterpreterGenerationTests(unittest.TestCase):
    def test_emits_records_exports_and_checked_macro_steps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [_row()])
            source = relational_interpreter_source(machine)

        for required in (
            "import StageA.RelationalInterpreter",
            "def semanticInterpreterProgramRecord0 : ProgramRecord",
            "def semanticInterpreterTransfer0 : SemanticTransfer",
            "def semanticInterpreterExport0 : ExportedSemanticTransfer",
            f'contractSha256 := "{_SHA_A}"',
            f'instructionBytesSha256 := "{_SHA_B}"',
            "semanticInterpreterProgramRecord0Decoded",
            "semanticInterpreterProgramRecord0TransferChecked",
            "semanticInterpreterProgramRecord0MacroStep",
            "semanticInterpreterProgramSourceRvasUnique",
            "semanticInterpreterProgramChecked",
            ".memoryWrite",
            ".divideIf",
            ".repMovsd",
            ".call 0",
            ".setRegister .eax",
            ".setFlag .zf",
            ".branch",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertNotIn("Acceptance", source)

    def test_generation_rejects_unsupported_or_malformed_programs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [_row()])
            transfer = compile_stage_b_interpreter_program(machine)[0]

        x87 = replace(
            transfer,
            x87_nodes=(_Node("fpu_reg", aux=0),),
        )
        unsupported_action = replace(
            transfer,
            actions=(_Action("eval_x87", (0,)),) + transfer.actions,
        )
        unevaluated = replace(
            transfer,
            actions=(_Action("set_reg", (0,), 0),) + transfer.actions,
        )
        response_index = next(
            index
            for index, node in enumerate(transfer.nodes)
            if node.op == "call_response"
        )
        stale_nodes = list(transfer.nodes)
        stale_nodes[response_index] = replace(
            stale_nodes[response_index], immediate=99
        )
        stale_call_output = replace(transfer, nodes=tuple(stale_nodes))

        cases = (
            (x87, "x87 value operations"),
            (unsupported_action, "unsupported Lean action"),
            (unevaluated, "unevaluated word node"),
            (stale_call_output, "stale call output"),
        )
        for malformed, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    RelationalInterpreterGenerationError, message
                ):
                    relational_interpreter_program_source([malformed])

    def test_generation_validates_outcomes_without_eagerly_indexing_other_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            row = _row()
            row["outcome"] = {"kind": "fallthrough", "target_rva": 0x1014}
            _write_machine(machine, [row])
            transfer = compile_stage_b_interpreter_program(machine)[0]

        source = relational_interpreter_program_source([transfer])
        self.assertIn(".fallthrough", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_generated_program_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row()])
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in ("X87", "Formal", "RelationalInterpreter"):
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "GeneratedRelationalInterpreter.lean").write_text(
                relational_interpreter_source(machine),
                encoding="utf-8",
            )
            (stage_a / "RelationalInterpreterGenerationKernel.lean").write_text(
                """import StageA.GeneratedRelationalInterpreter

namespace StageA.RelationalInterpreterGenerationKernel

open StageA.Relational.Interpreter StageA.GeneratedRelational

example : semanticInterpreterProgramRecord0.checked = true :=
  semanticInterpreterProgramRecord0Checked

example : semanticInterpreterProgramRecord0.decode =
    some semanticInterpreterExport0.transfer :=
  semanticInterpreterProgramRecord0Decoded

example (environment : StageA.Relational.Interpreter.Environment)
    (state : InterpreterMachine) :
    semanticInterpreterProgramRecord0.interpret environment state =
      semanticInterpreterExport0.transfer.execute environment state :=
  semanticInterpreterProgramRecord0MacroStep environment state

#print axioms semanticInterpreterProgramRecord0Decoded
#print axioms semanticInterpreterProgramRecord0MacroStep
#print axioms semanticInterpreterProgramChecked

end StageA.RelationalInterpreterGenerationKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterGenerationKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
