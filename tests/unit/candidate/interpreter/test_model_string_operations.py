from __future__ import annotations

from tests.unit.candidate.interpreter._support import *


class InterpreterStringOperationModelTests(unittest.TestCase):
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

            transfer = compile_spx_interpreter_program(machine)[0]
            fill = next(action for action in transfer.actions if action.op == "rep_stosd")
            self.assertEqual(len(fill.args), 4)

            package_dir = root / "package"
            package = write_spx_interpreter_package(
                machine_ir=machine, out=package_dir
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

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return SPX_CALL_UNIMPLEMENTED;
}

int main(void) {
  fill_context context = {{0U,0U,0U},{0U,0U,0U},0U};
  spx_runtime runtime = {0};
  spx_machine_state state = {0};
  spx_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;
  state.eax = 0x11223344U;
  state.ecx = 3U;
  state.edi = 0x100cU;
  state.df = 1U;
  result = spx_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != SPX_FALLTHROUGH) return 1;
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

    def test_width_generic_string_events_lower_with_explicit_width(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            row = _row()
            row["ordered_events"] = [
                {
                    "family": "external",
                    "kind": "rep_movs",
                    "index": 0,
                    "instruction_rva": 0x1000,
                    "element_width": 1,
                    "address_size": 32,
                    "destination": {"op": "reg", "name": "edi", "width": 32},
                    "source": {"op": "reg", "name": "esi", "width": 32},
                    "count": {"op": "reg", "name": "ecx", "width": 32},
                    "direction_flag": {"op": "flag", "name": "df"},
                    "effect_model": "symbolic_string_copy_v2",
                    "restart_semantics": "element_committed_v1",
                },
                {
                    "family": "external",
                    "kind": "rep_stos",
                    "index": 1,
                    "instruction_rva": 0x1002,
                    "element_width": 2,
                    "address_size": 32,
                    "destination": {"op": "reg", "name": "edi", "width": 32},
                    "value": {"op": "reg", "name": "eax", "width": 32},
                    "count": {"op": "reg", "name": "ecx", "width": 32},
                    "direction_flag": {"op": "flag", "name": "df"},
                    "effect_model": "symbolic_string_fill_v2",
                    "restart_semantics": "element_committed_v1",
                },
            ]
            row["register_writes"] = []
            _write_machine(machine, [row])

            transfer = compile_spx_interpreter_program(machine)[0]

            copy = next(action for action in transfer.actions if action.op == "rep_movs")
            fill = next(action for action in transfer.actions if action.op == "rep_stos")
            self.assertEqual((copy.aux, fill.aux), (1, 2))
            self.assertEqual((len(copy.args), len(fill.args)), (4, 4))

    def test_rep_scas_opcode_runtime_and_owned_outputs(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            row = _row()
            row["ordered_events"] = [_rep_scas_event()]
            row["register_writes"] = [
                {"register": "edi", "value": {"op": "const", "value": 0xBAD0, "width": 32}},
                {"register": "ecx", "value": {"op": "const", "value": 0xBAD1, "width": 32}},
                {"register": "eax", "value": {"op": "const", "value": 0xDEADBEEF, "width": 32}},
            ]
            row["flag_writes"] = [
                {"flag": name, "value": {"op": "false"}}
                for name in ("cf", "pf", "af", "zf", "sf", "of")
            ] + [{"flag": "df", "value": {"op": "false"}}]
            _write_machine(machine, [row])

            transfer = compile_spx_interpreter_program(machine)[0]
            scan = next(action for action in transfer.actions if action.op == "rep_scas")
            self.assertEqual((len(scan.args), scan.aux), (4, 1))
            self.assertEqual(
                [(transfer.nodes[index].op, transfer.nodes[index].aux) for index in scan.args],
                [("reg", 0), ("reg", 5), ("reg", 2), ("flag", 5)],
            )
            self.assertFalse(any(
                action.op == "set_reg" and action.aux in {2, 5}
                for action in transfer.actions
            ))
            self.assertEqual(
                [
                    action.aux
                    for action in transfer.actions
                    if action.op == "set_flag"
                ],
                [5],
            )

            package_dir = root / "package"
            package = write_spx_interpreter_package(
                machine_ir=machine,
                out=package_dir,
            )
            self.assertEqual(package["status"], "ready")
            program = json.loads(
                (package_dir / "state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn("rep_scas", program["capability"]["action_ops"])
            program_source = (
                package_dir / "state-machine-program.c"
            ).read_text(encoding="ascii")
            self.assertRegex(program_source, r"\{\s*29U,\s*4U,\s*1U,")

            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

typedef struct scan_context {
  uint32_t base, fault_address, reads;
  uint8_t bytes[4];
} scan_context;

static uint32_t read_byte(
    void *raw, uint32_t address, uint32_t width, uint32_t *fault) {
  scan_context *context = (scan_context *)raw;
  ++context->reads;
  if (width != 1U || address == context->fault_address ||
      address < context->base || address >= context->base + 4U) {
    *fault = 1U;
    return 0U;
  }
  return context->bytes[address - context->base];
}

static void write_unused(
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

static void initial_flags(spx_machine_state *state) {
  state->cf = 1U; state->zf = 0U; state->sf = 1U;
  state->of = 1U; state->pf = 0U; state->eflags = 1U << 4;
}

static int flags_are(
    const spx_machine_state *state, uint32_t cf, uint32_t zf,
    uint32_t sf, uint32_t of, uint32_t pf, uint32_t af) {
  return state->cf == cf && state->zf == zf && state->sf == sf &&
      state->of == of && state->pf == pf &&
      ((state->eflags >> 4) & 1U) == af;
}

static spx_step_result run(
    scan_context *context, spx_machine_state *state) {
  spx_runtime runtime = {0};
  runtime.context = context; runtime.read = read_byte; runtime.write = write_unused;
  return spx_interpreter_step(&runtime, state, 0x1000U);
}

int main(void) {
  const uint32_t base = 0x3000U;
  scan_context context = {base, 0xffffffffU, 0U, {0U,0U,0U,0U}};
  spx_machine_state state = {0};
  spx_step_result result;

  state.eax = 0x41U; state.edi = base; state.ecx = 0U; initial_flags(&state);
  result = run(&context, &state);
  if (result.kind != SPX_FALLTHROUGH || context.reads != 0U) return 1;
  if (state.edi != base || state.ecx != 0U ||
      !flags_are(&state, 1U,0U,1U,1U,0U,1U)) return 2;
  if (state.eax != 0xdeadbeefU || state.df != 0U) return 3;

  context = (scan_context){base, 0xffffffffU, 0U, {0U,0x41U,0x10U,0U}};
  state = (spx_machine_state){0};
  state.eax = 0x41U; state.edi = base + 2U; state.ecx = 2U; state.df = 1U;
  result = run(&context, &state);
  if (result.kind != SPX_FALLTHROUGH || context.reads != 2U) return 4;
  if (state.edi != base || state.ecx != 0U ||
      !flags_are(&state, 0U,1U,0U,0U,1U,0U) || state.df != 0U) return 5;

  context = (scan_context){base, 0xffffffffU, 0U, {1U,2U,0U,0U}};
  state = (spx_machine_state){0};
  state.eax = 0U; state.edi = base; state.ecx = 2U;
  result = run(&context, &state);
  if (result.kind != SPX_FALLTHROUGH || state.edi != base + 2U ||
      state.ecx != 0U || !flags_are(&state, 1U,0U,1U,0U,0U,1U)) return 6;

  context = (scan_context){base, base + 1U, 0U, {0x42U,0U,0U,0U}};
  state = (spx_machine_state){0};
  state.eax = 0x41U; state.edi = base; state.ecx = 3U;
  result = run(&context, &state);
  if (result.kind != SPX_MEMORY_FAULT || result.target_rva != 0x1000U ||
      context.reads != 2U) return 7;
  if (state.edi != base + 1U || state.ecx != 2U ||
      !flags_are(&state, 1U,0U,1U,0U,1U,1U)) return 8;
  if (state.eax != 0x41U) return 9;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "rep-scas-interpreter"
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

    def test_rep_movs_preserves_completed_iteration_state_on_fault(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            row = _row()
            row["ordered_events"] = [{
                "family": "external",
                "kind": "rep_movs",
                "index": 0,
                "instruction_rva": 0x1000,
                "element_width": 1,
                "address_size": 32,
                "destination": {"op": "reg", "name": "edi", "width": 32},
                "source": {"op": "reg", "name": "esi", "width": 32},
                "count": {"op": "reg", "name": "ecx", "width": 32},
                "direction_flag": {"op": "flag", "name": "df"},
                "effect_model": "symbolic_string_copy_v2",
                "restart_semantics": "element_committed_v1",
            }]
            row["register_writes"] = []
            _write_machine(machine, [row])
            package_dir = root / "package"
            write_spx_interpreter_package(machine_ir=machine, out=package_dir)

            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

typedef struct copy_context { uint32_t writes; } copy_context;

static uint32_t read_word(
    void *raw, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)raw;
  if (width != 1U || address < 0x2000U || address > 0x2002U) {
    *fault = 1U;
    return 0U;
  }
  return address & 0xffU;
}

static void write_word(
    void *raw, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {
  copy_context *context = (copy_context *)raw;
  if (width != 1U || context->writes != 0U || address != 0x3000U ||
      value != 0U) {
    *fault = 1U;
    return;
  }
  ++context->writes;
}

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return SPX_CALL_UNIMPLEMENTED;
}

int main(void) {
  copy_context context = {0U};
  spx_runtime runtime = {0};
  spx_machine_state state = {0};
  spx_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;
  state.esi = 0x2000U;
  state.edi = 0x3000U;
  state.ecx = 3U;
  result = spx_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != SPX_MEMORY_FAULT) return 1;
  if (context.writes != 1U) return 2;
  if (state.esi != 0x2001U || state.edi != 0x3001U || state.ecx != 2U)
    return 3;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "rep-movs-fault"
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


if __name__ == "__main__":
    unittest.main()
