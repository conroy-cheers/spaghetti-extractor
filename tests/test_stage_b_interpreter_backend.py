from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_interpreter_backend import (
    STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT,
    StageBInterpreterError,
    compile_stage_b_interpreter_program,
    write_stage_b_interpreter_package,
)


_SHA_A = "a" * 64
_SHA_B = "b" * 64


def _row(*, expression: dict[str, object] | None = None) -> dict[str, object]:
    value = expression or {
        "op": "add32",
        "args": [
            {"op": "reg", "name": "eax", "width": 32},
            {"op": "const", "value": 1, "width": 32},
        ],
    }
    return {
        "id": "semantic-transfer:fixture",
        "contract_sha256": _SHA_A,
        "instruction_bytes_sha256": _SHA_B,
        "original": {"rva_start": 0x1000, "rva_end": 0x1003, "size": 3},
        "ordered_events": [],
        "register_writes": [{"register": "eax", "value": value}],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {"kind": "fallthrough", "target_rva": 0x1003},
    }


def _write_machine(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


class StageBInterpreterBackendTests(unittest.TestCase):
    def test_undefined_nodes_emit_complete_non_authoritative_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            row = _row(
                expression={
                    "op": "undefined_bv",
                    "width": 32,
                    "id": "fixture:undefined:eax",
                    "reason": "fixture",
                }
            )
            _write_machine(machine, [row])

            write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )
            program = json.loads(
                (root / "package/state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            metadata = program["definedness_use"]
            self.assertEqual(
                metadata["format"], STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT
            )
            self.assertEqual(metadata["status"], "complete")
            self.assertFalse(metadata["proof_authority"])
            self.assertEqual(program["counts"]["undefined_nodes"], 1)
            self.assertEqual(metadata["undefined_node_count"], 1)
            self.assertEqual(len(metadata["slots"]), 1)
            self.assertEqual(metadata["slots"][0]["classification"], "unknown")
            self.assertIsNone(metadata["slots"][0]["witness_policy"])
            self.assertEqual(
                metadata["slots"][0]["uses"],
                [{
                    "transfer_id": "semantic-transfer:fixture",
                    "node_index": 0,
                    "op": "undefined_bv",
                }],
            )

    def test_value_indexed_undefined_node_retains_exact_input_expression(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            row = _row(
                expression={
                    "op": "undefined_bv",
                    "width": 32,
                    "id": "fixture:bsr:eax",
                    "reason": "bsr-zero-source",
                    "defined_value": {
                        "op": "reg",
                        "name": "eax",
                        "width": 32,
                    },
                }
            )
            _write_machine(machine, [row])

            transfer = compile_stage_b_interpreter_program(machine)[0]
            undefined_index, undefined = next(
                (index, node)
                for index, node in enumerate(transfer.nodes)
                if node.op == "undefined_bv"
            )
            self.assertEqual(undefined.op, "undefined_bv")
            self.assertEqual(len(undefined.args), 1)
            value = transfer.nodes[undefined.args[0]]
            self.assertEqual((value.op, value.aux, value.immediate), ("reg", 0, 0))

            write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )
            program = json.loads(
                (root / "package/state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            use = program["definedness_use"]["slots"][0]["uses"][0]
            self.assertEqual(use["node_index"], undefined_index)
            self.assertEqual(use["defined_value_node"], undefined.args[0])

    def test_external_call_stack_inputs_lower_to_fixed_program_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            row = _row()
            registers = {
                name: {"op": "reg", "name": name, "width": 32}
                for name in (
                    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
                )
            }
            flags = {
                name: {"op": "flag", "name": name}
                for name in ("cf", "zf", "sf", "of", "pf", "df")
            }
            event = {
                "family": "external",
                "kind": "external_call",
                "instruction_rva": 0x1000,
                "return_rva": 0x1005,
                "dll": "kernel32.dll",
                "symbol": "ExitProcess",
                "ordinal": None,
                "arguments": [{"op": "const", "value": 0, "width": 32}],
                "register_inputs": registers,
                "flag_inputs": flags,
                "stack_inputs": [
                    {
                        "offset": 0,
                        "width": 4,
                        "value": {"op": "const", "value": 0, "width": 32},
                    }
                ],
            }
            row["ordered_events"] = [event]
            row["outcome"] = {"kind": "fallthrough", "target_rva": 0x1005}
            _write_machine(machine, [row])

            transfer = compile_stage_b_interpreter_program(machine)[0]

            self.assertEqual(len(transfer.calls), 1)
            self.assertEqual(len(transfer.calls[0].stack_inputs), 1)
            self.assertEqual(transfer.calls[0].stack_inputs[0][:2], (0, 4))
            package = write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )
            self.assertEqual(package["status"], "ready")
            self.assertIn(
                "{ 0U, 4U, ",
                (root / "package/state-machine-program.c").read_text(
                    encoding="utf-8"
                ),
            )

    def test_repeated_ordered_reads_emit_distinct_actions_and_latest_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            address = {"op": "reg", "name": "esp", "width": 32}
            loaded = {"op": "load", "width": 4, "address": address}
            row = _row(expression=loaded)
            row["ordered_events"] = [
                {"family": "memory", "kind": "read", "width": 4, "address": address},
                {"family": "memory", "kind": "read", "width": 4, "address": address},
            ]
            _write_machine(machine, [row])

            transfer = compile_stage_b_interpreter_program(machine)[0]
            read_nodes = [
                action.args[0]
                for action in transfer.actions
                if action.op == "eval_word"
                and transfer.nodes[action.args[0]].op == "load"
            ]
            set_eax = next(
                action
                for action in transfer.actions
                if action.op == "set_reg" and action.aux == 0
            )

            self.assertEqual(len(read_nodes), 2)
            self.assertNotEqual(read_nodes[0], read_nodes[1])
            self.assertEqual(set_eax.args, (read_nodes[1],))

    def test_repeated_read_invalidates_only_its_dependent_expressions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            first_address = {"op": "reg", "name": "esp", "width": 32}
            second_address = {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 4, "width": 32},
                    first_address,
                ],
            }
            first_load = {"op": "load", "width": 4, "address": first_address}
            second_load = {"op": "load", "width": 4, "address": second_address}
            row = _row(
                expression={"op": "add32", "args": [first_load, second_load]}
            )
            row["ordered_events"] = [
                {
                    "family": "memory",
                    "kind": "read",
                    "width": 4,
                    "address": first_address,
                },
                {
                    "family": "memory",
                    "kind": "read",
                    "width": 4,
                    "address": second_address,
                },
                {
                    "family": "memory",
                    "kind": "write",
                    "width": 4,
                    "address": second_address,
                    "value": {"op": "const", "value": 7, "width": 32},
                },
                {
                    "family": "memory",
                    "kind": "read",
                    "width": 4,
                    "address": first_address,
                },
            ]
            _write_machine(machine, [row])

            transfer = compile_stage_b_interpreter_program(machine)[0]
            read_nodes = [
                action.args[0]
                for action in transfer.actions
                if action.op == "eval_word"
                and transfer.nodes[action.args[0]].op == "load"
            ]
            set_eax = next(
                action
                for action in transfer.actions
                if action.op == "set_reg" and action.aux == 0
            )
            result_node = transfer.nodes[set_eax.args[0]]
            effect_schedule = [
                "read"
                if action.op == "eval_word"
                and transfer.nodes[action.args[0]].op == "load"
                else "write"
                for action in transfer.actions
                if (
                    action.op == "memory_write"
                    or (
                        action.op == "eval_word"
                        and transfer.nodes[action.args[0]].op == "load"
                    )
                )
            ]

            self.assertEqual(len(read_nodes), 3)
            self.assertEqual(effect_schedule, ["read", "read", "write", "read"])
            self.assertEqual(result_node.op, "add32")
            self.assertEqual(result_node.args, (read_nodes[2], read_nodes[1]))

    def test_deterministic_package_compiles_as_freestanding_pe32_objects(self) -> None:
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if compiler is None:
            self.skipTest("i686 MinGW compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row()])
            first = root / "first"
            second = root / "second"
            package = write_stage_b_interpreter_package(
                state_machine=machine, out=first
            )
            write_stage_b_interpreter_package(state_machine=machine, out=second)

            self.assertEqual(package["status"], "ready")
            self.assertEqual(package["counts"]["transfers"], 1)
            names = (
                "state-machine-runtime.h",
                "state-machine-interpreter.h",
                "state-machine-interpreter-internal.h",
                "state-machine-interpreter.c",
                "state-machine-program.c",
                "state-machine-interpreter-program.json",
                "state-machine-interpreter-package.json",
            )
            for name in names:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            self.assertNotIn(
                "long double",
                (first / "state-machine-interpreter.c").read_text(encoding="ascii"),
            )
            for source in ("state-machine-interpreter.c", "state-machine-program.c"):
                subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        "-Os",
                        "-ffreestanding",
                        "-fno-builtin",
                        "-I",
                        str(first),
                        "-c",
                        str(first / source),
                        "-o",
                        str(first / (source + ".o")),
                    ],
                    check=True,
                    text=True,
                    capture_output=True,
                )

    def test_run_function_encodes_every_terminal_state_at_the_entry_rva(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row()])
            write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )

            source = (root / "package/state-machine-interpreter.c").read_text(
                encoding="ascii"
            )
            run = source.split(
                "stage_b_call_status stage_b_run_function(", 1
            )[1].split("stage_b_call_status stage_b_invoke_call(", 1)[0]
            self.assertIn("uint32_t entry_rva = rva;", run)
            self.assertEqual(run.count("*out = s;"), 2)
            self.assertEqual(run.count("out->original_rva = entry_rva;"), 2)
            self.assertLess(
                run.index("*out = s;", run.index("stage_b_step_result r")),
                run.index("if (r.kind == STAGE_B_RETURN"),
            )

    def test_unsupported_operation_fails_before_emission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [_row(expression={"op": "target_specific_magic"})])
            with self.assertRaisesRegex(StageBInterpreterError, "unsupported semantic op"):
                compile_stage_b_interpreter_program(machine)

    def test_duplicate_rva_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            second = dict(_row())
            second["id"] = "semantic-transfer:other"
            _write_machine(machine, [_row(), second])
            with self.assertRaisesRegex(StageBInterpreterError, "duplicate transfer RVA"):
                compile_stage_b_interpreter_program(machine)

    def test_symbolic_x87_state_requires_checked_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            row = _row()
            row["fpu_state"] = {
                "model": "symbolic_x87_stack_v1",
                "stack": [{"op": "fpu_reg", "args": [index]} for index in range(8)],
                "control": {"op": "fpu_control", "args": []},
                "status": {"op": "fpu_status", "args": []},
            }
            _write_machine(machine, [row])
            with self.assertRaisesRegex(
                StageBInterpreterError, "exact checked replay schedule"
            ) as raised:
                compile_stage_b_interpreter_program(machine)
            self.assertEqual(raised.exception.code, "x87_checked_replay_required")
            self.assertIn("instruction-ordered effect schedule", raised.exception.next_action)


if __name__ == "__main__":
    unittest.main()
