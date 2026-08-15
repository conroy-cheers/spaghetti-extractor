from __future__ import annotations

from tests.unit.candidate.interpreter._support import *


class InterpreterExecutionModelTests(unittest.TestCase):
    def test_machine_ir_applies_pre_call_effects_before_external_tail_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "machine-ir.jsonl"
            _write_machine(machine, [_machine_ir_pre_call_tail_unit()])

            transfer = compile_spx_interpreter_machine_ir(machine)[0]
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
            self.assertEqual(len(transfer.calls[0].stack_inputs), 1)
            self.assertEqual(transfer.calls[0].stack_inputs[0][:2], (0, 4))
            self.assertFalse(any(
                action.op == "set_reg" and action.aux == 7
                for action in transfer.actions[call + 1:]
            ))

    def test_machine_ir_call_stack_inputs_read_memory_after_register_reuse(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            _write_machine(
                machine,
                [_machine_ir_stack_call_after_register_reuse_unit()],
            )
            package_dir = root / "package"
            write_spx_interpreter_package(machine_ir=machine, out=package_dir)
            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

typedef struct fixture_context {
  uint32_t word_12, word_16, observed;
} fixture_context;

static uint32_t read_word(
    void *raw, uint32_t address, uint32_t width, uint32_t *fault) {
  fixture_context *context = (fixture_context *)raw;
  if (width != 4U) { *fault = 1U; return 0U; }
  if (address == 0x1040U) return 0xbbbbbbbbU;
  if (address == 0x0ff0U) return context->word_12;
  if (address == 0x0ff4U) return context->word_16;
  *fault = 1U;
  return 0U;
}

static void write_word(
    void *raw, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {
  fixture_context *context = (fixture_context *)raw;
  if (width != 4U) { *fault = 1U; return; }
  if (address == 0x0ff0U) { context->word_12 = value; return; }
  if (address == 0x0ff4U) { context->word_16 = value; return; }
  *fault = 1U;
}

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {
  fixture_context *context = (fixture_context *)runtime->context;
  if (event->stack_input_count != 2U) return SPX_CALL_UNIMPLEMENTED;
  if (event->stack_inputs[0].offset != 12U ||
      event->stack_inputs[0].value != 0xaaaaaaaaU ||
      event->stack_inputs[1].offset != 16U ||
      event->stack_inputs[1].value != 0xbbbbbbbbU)
    return SPX_CALL_UNIMPLEMENTED;
  context->observed = 1U;
  *output = *input;
  return SPX_CALL_OK;
}

int main(void) {
  fixture_context context = {0U, 0U, 0U};
  spx_runtime runtime = {0};
  spx_machine_state state = {0};
  spx_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;
  state.esp = 0x1000U;
  state.edx = 0xaaaaaaaaU;
  result = spx_interpreter_step(&runtime, &state, 0x1000U);
  if (context.observed != 1U) return 1;
  if (context.word_12 != 0xaaaaaaaaU ||
      context.word_16 != 0xbbbbbbbbU) return 2;
  if (result.kind == SPX_MEMORY_FAULT ||
      result.kind == SPX_UNIMPLEMENTED) return 3;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "stack-call-after-register-reuse"
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

    def test_machine_ir_terminal_branch_reads_final_instruction_state(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            _write_machine(machine, [_machine_ir_load_compare_branch_unit()])

            transfer = compile_spx_interpreter_machine_ir(machine)[0]
            branch = next(action for action in transfer.actions if action.op == "outcome_branch")
            condition = transfer.nodes[branch.args[0]]
            self.assertEqual(condition.op, "flag")
            self.assertEqual(condition.immediate, 1)

            package_dir = root / "package"
            package = write_spx_interpreter_package(
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

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return SPX_CALL_UNIMPLEMENTED;
}

int main(void) {
  fixture_context context = {0U};
  spx_runtime runtime = {0};
  spx_machine_state state = {0};
  spx_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;

  state.zf = 1U;
  result = spx_interpreter_step(&runtime, &state, 0x1063U);
  if (result.kind != SPX_BRANCH || result.target_rva != 0x1071U) return 1;

  context.value = 1U;
  state.zf = 0U;
  result = spx_interpreter_step(&runtime, &state, 0x1063U);
  if (result.kind != SPX_BRANCH || result.target_rva != 0x13f2U) return 2;
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

            write_spx_interpreter_package(
                machine_ir=machine, out=root / "package"
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
                f"#define SPX_MAX_WORD_NODES {maximum}U",
                source,
            )
            self.assertNotIn("#define SPX_MAX_WORD_NODES 1024U", source)

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

            transfer = compile_spx_interpreter_program(machine)[0]

            self.assertEqual(len(transfer.calls), 1)
            self.assertEqual(len(transfer.calls[0].stack_inputs), 1)
            self.assertEqual(transfer.calls[0].stack_inputs[0][:2], (0, 4))
            package = write_spx_interpreter_package(
                machine_ir=machine, out=root / "package"
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

            transfer = compile_spx_interpreter_program(machine)[0]
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

            transfer = compile_spx_interpreter_program(machine)[0]
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


if __name__ == "__main__":
    unittest.main()
