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
    compile_stage_b_interpreter_machine_ir,
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


def _machine_ir_pre_call_tail_unit() -> dict[str, object]:
    registers = {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    empty_effects = {
        "register_writes": [],
        "defined_flag_writes": [],
        "undefined_flag_writes": [],
        "ordered_events": [],
    }
    records = [
        {
            "rva_start": 0x1000,
            "rva_end": 0x1001,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "effects": {
                **empty_effects,
                "register_writes": [{
                    "register": "esp",
                    "value": {
                        "op": "add32",
                        "args": [registers["esp"], {"op": "const", "value": 28, "width": 32}],
                    },
                }],
                "control": {"kind": "fallthrough", "target_rva": 0x1001},
            },
        },
        {
            "rva_start": 0x1001,
            "rva_end": 0x1002,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "effects": {
                **empty_effects,
                "ordered_events": [{
                    "family": "external",
                    "kind": "external_call",
                    "instruction_rva": 0x1001,
                    "return_rva": 0x1002,
                    "dll": "msvcrt.dll",
                    "symbol": "_unlock",
                    "ordinal": None,
                    "register_inputs": registers,
                    "flag_inputs": flags,
                    "arguments": [],
                    "stack_inputs": [],
                }],
                "control": {
                    "kind": "external_jump",
                    "dll": "msvcrt.dll",
                    "symbol": "_unlock",
                    "ordinal": None,
                },
            },
        },
    ]
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "semantic-transfer:pre-call-tail",
        "status": "qualified",
        "reachable": True,
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
            "contract_sha256": _SHA_A,
            "instruction_bytes_sha256": _SHA_B,
        },
        "instructions": [],
        "x87_micro_ops": [],
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {
                "kind": "external_jump",
                "dll": "msvcrt.dll",
                "symbol": "_unlock",
                "ordinal": None,
            },
            "stack_delta": None,
            "counts": {},
            "fpu_state": None,
            "instruction_effect_schedule": {
                "format": "stage-a-instruction-ordered-effect-schedule-v1",
                "status": "complete",
                "proof_authority": False,
                "ordering": "strict_contiguous_rva_order",
                "rva_start": 0x1000,
                "rva_end": 0x1002,
                "records": records,
                "blockers": [],
                "counts": {
                    "instructions": 2,
                    "x87_singletons": 0,
                    "ordinary_instructions": 2,
                    "blockers": 0,
                },
            },
        },
    }


def _machine_ir_load_compare_branch_unit() -> dict[str, object]:
    empty_effects = {
        "register_writes": [],
        "defined_flag_writes": [],
        "undefined_flag_writes": [],
        "ordered_events": [],
    }
    address = {"op": "const", "value": 0x430328, "width": 32}
    eax = {"op": "reg", "name": "eax", "width": 32}
    one = {"op": "const", "value": 1, "width": 32}
    difference = {"op": "sub32", "args": [eax, one]}
    zero = {"op": "const", "value": 0, "width": 32}
    records = [
        {
            "rva_start": 0x1063,
            "rva_end": 0x1068,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "effects": {
                **empty_effects,
                "register_writes": [{
                    "register": "eax",
                    "value": {"op": "load", "width": 4, "address": address},
                }],
                "ordered_events": [{
                    "family": "memory",
                    "kind": "read",
                    "width": 4,
                    "address": address,
                }],
                "control": {"kind": "fallthrough", "target_rva": 0x1068},
            },
        },
        {
            "rva_start": 0x1068,
            "rva_end": 0x106B,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "effects": {
                **empty_effects,
                "defined_flag_writes": [{
                    "flag": "zf",
                    "value": {"op": "eq", "args": [difference, zero]},
                }],
                "control": {"kind": "fallthrough", "target_rva": 0x106B},
            },
        },
        {
            "rva_start": 0x106B,
            "rva_end": 0x1071,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "effects": {
                **empty_effects,
                "control": {
                    "kind": "branch",
                    "condition": {"op": "flag", "name": "zf"},
                    "true_target_rva": 0x13F2,
                    "false_target_rva": 0x1071,
                },
            },
        },
    ]
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "semantic-transfer:load-compare-branch",
        "status": "qualified",
        "reachable": True,
        "source": {
            "original": {"rva_start": 0x1063, "rva_end": 0x1071, "size": 14},
            "contract_sha256": _SHA_A,
            "instruction_bytes_sha256": _SHA_B,
        },
        "instructions": [],
        "x87_micro_ops": [],
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {
                "kind": "branch",
                "condition": {"op": "flag", "name": "zf"},
                "true_target_rva": 0x13F2,
                "false_target_rva": 0x1071,
            },
            "stack_delta": None,
            "counts": {},
            "fpu_state": None,
            "instruction_effect_schedule": {
                "format": "stage-a-instruction-ordered-effect-schedule-v1",
                "status": "complete",
                "proof_authority": False,
                "ordering": "strict_contiguous_rva_order",
                "rva_start": 0x1063,
                "rva_end": 0x1071,
                "records": records,
                "blockers": [],
                "counts": {
                    "instructions": 3,
                    "x87_singletons": 0,
                    "ordinary_instructions": 3,
                    "blockers": 0,
                },
            },
        },
    }


class StageBInterpreterBackendTests(unittest.TestCase):
    def test_machine_ir_applies_pre_call_effects_before_external_tail_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "machine-ir.jsonl"
            _write_machine(machine, [_machine_ir_pre_call_tail_unit()])

            transfer = compile_stage_b_interpreter_machine_ir(machine)[0]
            set_esp = next(
                index
                for index, action in enumerate(transfer.actions)
                if action.op == "set_reg" and action.aux == 7
            )
            call = next(
                index for index, action in enumerate(transfer.actions)
                if action.op == "call"
            )

            self.assertLess(set_esp, call)
            self.assertFalse(any(
                action.op == "set_reg" and action.aux == 7
                for action in transfer.actions[call + 1:]
            ))

    def test_machine_ir_terminal_branch_reads_final_instruction_state(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            _write_machine(machine, [_machine_ir_load_compare_branch_unit()])

            transfer = compile_stage_b_interpreter_machine_ir(machine)[0]
            branch = next(action for action in transfer.actions if action.op == "outcome_branch")
            condition = transfer.nodes[branch.args[0]]
            self.assertEqual(condition.op, "flag")
            self.assertEqual(condition.immediate, 1)

            package_dir = root / "package"
            package = write_stage_b_interpreter_package(
                machine_ir=machine, out=package_dir
            )
            self.assertEqual(package["status"], "ready")
            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

typedef struct fixture_context { uint32_t value; } fixture_context;

static uint32_t read_word(
    void *raw, uint32_t address, uint32_t width, uint32_t *fault) {
  fixture_context *context = (fixture_context *)raw;
  if (address != 0x430328U || width != 4U) { *fault = 1U; return 0U; }
  return context->value;
}

static void write_word(
    void *raw, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {
  (void)raw; (void)address; (void)width; (void)value; *fault = 1U;
}

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

int main(void) {
  fixture_context context = {0U};
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;

  state.zf = 1U;
  result = stage_b_interpreter_step(&runtime, &state, 0x1063U);
  if (result.kind != STAGE_B_BRANCH || result.target_rva != 0x1071U) return 1;

  context.value = 1U;
  state.zf = 0U;
  result = stage_b_interpreter_step(&runtime, &state, 0x1063U);
  if (result.kind != STAGE_B_BRANCH || result.target_rva != 0x13f2U) return 2;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "load-compare-branch"
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Werror",
                    "-I",
                    str(package_dir),
                    str(package_dir / "state-machine-interpreter.c"),
                    str(package_dir / "state-machine-program.c"),
                    str(harness),
                    "-o",
                    str(executable),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_interpreter_stack_capacity_matches_checked_program_maximum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_row()])

            write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )
            program = json.loads(
                (root / "package/state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            maximum = program["counts"]["max_word_nodes_per_transfer"]
            source = (
                root / "package/state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            self.assertGreater(maximum, 0)
            self.assertIn(
                f"#define STAGE_B_MAX_WORD_NODES {maximum}U",
                source,
            )
            self.assertNotIn("#define STAGE_B_MAX_WORD_NODES 1024U", source)

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

    def test_rep_stosd_lowers_to_stable_action_26_and_executes_ordered_fill(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            row = _row()
            row["ordered_events"] = [{
                "family": "external",
                "kind": "rep_stosd",
                "index": 0,
                "instruction_rva": 0x1000,
                "destination": {"op": "reg", "name": "edi", "width": 32},
                "value": {"op": "reg", "name": "eax", "width": 32},
                "count": {"op": "reg", "name": "ecx", "width": 32},
                "direction_flag": {"op": "flag", "name": "df"},
                "effect_model": "symbolic_string_fill_v1",
            }]
            row["register_writes"] = []
            _write_machine(machine, [row])

            transfer = compile_stage_b_interpreter_program(machine)[0]
            fill = next(action for action in transfer.actions if action.op == "rep_stosd")
            self.assertEqual(len(fill.args), 4)

            package_dir = root / "package"
            package = write_stage_b_interpreter_package(
                state_machine=machine, out=package_dir
            )
            self.assertEqual(package["status"], "ready")
            program = json.loads(
                (package_dir / "state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn("rep_stosd", program["capability"]["action_ops"])
            program_source = (
                package_dir / "state-machine-program.c"
            ).read_text(encoding="ascii")
            self.assertRegex(program_source, r"\{\s*26U,\s*4U,\s*0U,")

            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

typedef struct fill_context {
  uint32_t addresses[3];
  uint32_t values[3];
  uint32_t count;
} fill_context;

static uint32_t read_word(
    void *context, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)context; (void)address; (void)width; *fault = 1U; return 0U;
}

static void write_word(
    void *raw, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {
  fill_context *context = (fill_context *)raw;
  if (width != 4U || context->count >= 3U) { *fault = 1U; return; }
  context->addresses[context->count] = address;
  context->values[context->count] = value;
  ++context->count;
}

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

int main(void) {
  fill_context context = {{0U,0U,0U},{0U,0U,0U},0U};
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;
  state.eax = 0x11223344U;
  state.ecx = 3U;
  state.edi = 0x100cU;
  state.df = 1U;
  result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != STAGE_B_FALLTHROUGH) return 1;
  if (context.count != 3U) return 2;
  if (context.addresses[0] != 0x100cU ||
      context.addresses[1] != 0x1008U ||
      context.addresses[2] != 0x1004U) return 3;
  if (context.values[0] != 0x11223344U ||
      context.values[1] != 0x11223344U ||
      context.values[2] != 0x11223344U) return 4;
  if (state.edi != 0x1000U || state.ecx != 0U) return 5;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "rep-stosd"
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Werror",
                    "-I",
                    str(package_dir),
                    str(package_dir / "state-machine-interpreter.c"),
                    str(package_dir / "state-machine-program.c"),
                    str(harness),
                    "-o",
                    str(executable),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_rep_stosd_event_validation_fails_closed(self) -> None:
        base = {
            "family": "external",
            "kind": "rep_stosd",
            "index": 0,
            "instruction_rva": 0x1000,
            "destination": {"op": "reg", "name": "edi", "width": 32},
            "value": {"op": "reg", "name": "eax", "width": 32},
            "count": {"op": "reg", "name": "ecx", "width": 32},
            "direction_flag": {"op": "flag", "name": "df"},
            "effect_model": "symbolic_string_fill_v1",
        }
        cases = (
            ({"effect_model": "unchecked"}, "symbolic_string_fill_v1"),
            ({"index": 1}, "event index"),
            ({"source": {"op": "reg", "name": "esi", "width": 32}}, "source address"),
        )
        for mutation, message in cases:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    machine = Path(temporary) / "state-machine.jsonl"
                    row = _row()
                    row["ordered_events"] = [{**base, **mutation}]
                    _write_machine(machine, [row])
                    with self.assertRaisesRegex(StageBInterpreterError, message) as raised:
                        compile_stage_b_interpreter_program(machine)
                    self.assertEqual(
                        raised.exception.code, "malformed_rep_stosd_event"
                    )

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

    def test_run_function_preserves_nested_failure_rva(self) -> None:
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
                "static stage_b_call_status stage_b_run_function_checked(", 1
            )[1].split("stage_b_call_status stage_b_run_function(", 1)[0]
            self.assertNotIn("uint32_t entry_rva = rva;", run)
            self.assertEqual(run.count("*out = s;"), 2)
            self.assertEqual(run.count("out->original_rva = rva;"), 1)
            self.assertIn(
                "out->original_rva = r.target_rva != 0U ? r.target_rva : rva;",
                run,
            )
            self.assertIn("*state=call_output;return(stage_b_step_result)", source)
            self.assertIn("call_output.original_rva,0U", source)
            self.assertLess(
                run.index("*out = s;", run.index("stage_b_step_result r")),
                run.index("if (r.kind == STAGE_B_RETURN"),
            )
            self.assertIn("r.value != expected_return_rva", run)
            self.assertIn("out->esi = expected_return_rva;", run)
            self.assertIn("out->edi = r.value;", run)
            self.assertIn("call_input.esp -= 4U;", source)
            self.assertIn("event->return_rva, &memory_fault", source)
            self.assertIn("output->esp < input->esp", source)
            self.assertIn("output->esi = input->esp;", source)
            self.assertIn("output->edi = output->esp;", source)
            self.assertIn("->fs_base;", source)

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
