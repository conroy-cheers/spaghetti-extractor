from __future__ import annotations

from spaghetti_extractor.machine_ir.fallback_capability import (
    FallbackCapabilityAnalysis,
    FallbackCapabilityAnalysisError,
)
from tests.unit.candidate.interpreter._support import *


class InterpreterFailurePolicyTests(unittest.TestCase):
    def test_capability_analysis_reports_incomplete_rows_without_emitting_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            valid = _machine_ir_pre_call_tail_unit()
            valid["reachability"] = "reachable"
            potential = json.loads(json.dumps(valid))
            potential["id"] = "semantic-transfer:potential-data"
            potential["status"] = "incomplete"
            potential["reachable"] = False
            potential["reachability"] = "potential"
            potential["source"]["original"] = {
                "rva_start": 0x2000,
                "rva_end": 0x2002,
                "size": 2,
            }
            schedule = potential["semantics"]["instruction_effect_schedule"]
            schedule["rva_start"] = 0x2000
            schedule["rva_end"] = 0x2002
            schedule["records"][0]["rva_start"] = 0x2000
            schedule["records"][0]["rva_end"] = 0x2001
            schedule["records"][0]["instruction_class"] = "unsupported_instruction"
            schedule["records"][1]["rva_start"] = 0x2001
            schedule["records"][1]["rva_end"] = 0x2002
            _write_machine(machine, [valid, potential])

            strict = write_stage_b_interpreter_package(
                machine_ir=machine,
                out=root / "strict",
            )
            self.assertEqual(strict["status"], "incomplete")
            self.assertEqual(strict["counts"]["blocked_transfers"], 1)
            self.assertEqual(strict["counts"]["deferred_transfers"], 0)

            report_path = root / "capability.json"
            capability = write_fallback_capability_analysis(
                machine_ir=machine,
                out=report_path,
            )
            self.assertEqual(capability["status"], "incomplete")
            self.assertEqual(capability["counts"]["required_units"], 2)
            self.assertEqual(capability["counts"]["lowerable_units"], 1)
            self.assertEqual(
                capability["unlowerable_unit_ids"],
                ["semantic-transfer:potential-data"],
            )
            self.assertFalse(capability["trust"]["candidate_executable"])
            self.assertEqual(list(root.glob("capability*")), [report_path])

    def test_capability_analysis_digest_covers_generated_source_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            _write_machine(machine, [_machine_ir_pre_call_tail_unit()])
            report_path = root / "capability.json"
            report = write_fallback_capability_analysis(
                machine_ir=machine,
                out=report_path,
            )

            checked = FallbackCapabilityAnalysis.from_payload(report)
            self.assertTrue(checked.complete)
            self.assertEqual(checked.required_units, 1)
            self.assertEqual(
                set(checked.lowering.to_payload()),
                {
                    "program_source_sha256",
                    "interpreter_source_sha256",
                    "runtime_header_sha256",
                    "interpreter_header_sha256",
                    "interpreter_internal_header_sha256",
                },
            )
            report["lowering"]["program_source_sha256"] = "f" * 64
            with self.assertRaisesRegex(
                FallbackCapabilityAnalysisError,
                "capability SHA-256 is stale",
            ):
                FallbackCapabilityAnalysis.from_payload(report)

    def test_machine_ir_never_defers_reachable_incomplete_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            reachable = _machine_ir_pre_call_tail_unit()
            reachable["status"] = "incomplete"
            reachable["reachability"] = "reachable"
            _write_machine(machine, [reachable])

            package = write_stage_b_interpreter_package(
                machine_ir=machine,
                out=root / "package",
            )
            self.assertEqual(package["status"], "incomplete")
            self.assertEqual(package["counts"]["blocked_transfers"], 1)
            self.assertEqual(package["counts"]["deferred_transfers"], 0)

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

    def test_inactive_conditional_arm_does_not_consume_undefined_value(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            undefined = {
                "op": "undefined_bv",
                "width": 32,
                "id": "fixture:inactive-undefined",
                "reason": "inactive conditional arm",
            }
            _write_machine(machine, [_row(expression={
                "op": "ite",
                "args": [
                    {"op": "false"},
                    undefined,
                    {"op": "const", "value": 7, "width": 32},
                ],
            })])
            package_dir = root / "package"
            write_stage_b_interpreter_package(
                state_machine=machine, out=package_dir
            )
            transfer = compile_stage_b_interpreter_program(machine)[0]
            undefined_index = next(
                index
                for index, node in enumerate(transfer.nodes)
                if node.op == "undefined_bv"
            )
            self.assertNotIn(
                undefined_index,
                {
                    action.args[0]
                    for action in transfer.actions
                    if action.op == "eval_word"
                },
            )
            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

static uint32_t undefined_calls;

static uint32_t undefined_value(
    void *context, uint32_t slot, const stage_b_machine_state *input,
    uint32_t defined_value) {
  (void)context; (void)slot; (void)input; (void)defined_value;
  ++undefined_calls;
  return 0U;
}

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

int main(void) {
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  runtime.undefined_value = undefined_value;
  result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind == STAGE_B_UNIMPLEMENTED) return 1;
  if (state.eax != 7U) return 2;
  if (undefined_calls != 0U) return 3;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "inactive-undefined"
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

    def test_false_divide_fault_guard_continues_to_register_updates(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            operands = [
                {"op": "reg", "name": "edx", "width": 32},
                {"op": "reg", "name": "eax", "width": 32},
                {"op": "reg", "name": "esi", "width": 32},
            ]
            valid = {"op": "udiv_valid32", "args": operands}
            row = _row(expression={
                "op": "ite",
                "args": [
                    valid,
                    {"op": "udiv_quot32", "args": operands},
                    {
                        "op": "undefined_bv",
                        "width": 32,
                        "id": "fixture:divide-fault-eax",
                        "reason": "divide fault",
                    },
                ],
            })
            row["ordered_events"] = [{
                "family": "fault",
                "kind": "divide_error",
                "condition": {"op": "not", "args": [valid]},
            }]
            _write_machine(machine, [row])
            package_dir = root / "package"
            write_stage_b_interpreter_package(
                state_machine=machine, out=package_dir
            )
            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

static uint32_t undefined_calls;

static uint32_t undefined_value(
    void *context, uint32_t slot, const stage_b_machine_state *input,
    uint32_t defined_value) {
  (void)context; (void)slot; (void)input; (void)defined_value;
  ++undefined_calls;
  return 0U;
}

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

int main(void) {
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  runtime.undefined_value = undefined_value;
  state.eax = 20000U;
  state.edx = 0U;
  state.esi = 4096U;
  result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != STAGE_B_FALLTHROUGH) return 1;
  if (result.target_rva != 0x1003U) return 2;
  if (state.eax != 4U) return 3;
  if (undefined_calls != 0U) return 4;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "false-divide-fault"
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

    def test_blocked_transfer_definedness_slots_do_not_abort_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            compiled = _row(
                expression={
                    "op": "undefined_bv",
                    "width": 32,
                    "id": "fixture:compiled:undefined:eax",
                    "reason": "fixture",
                }
            )
            blocked = _row(
                expression={
                    "op": "undefined_bv",
                    "width": 32,
                    "id": "fixture:blocked:undefined:eax",
                    "reason": "fixture",
                },
            )
            blocked["id"] = "semantic-transfer:blocked"
            blocked["contract_sha256"] = "c" * 64
            blocked["instruction_bytes_sha256"] = "d" * 64
            blocked["original"] = {
                "rva_start": 0x2000,
                "rva_end": 0x2003,
                "size": 3,
            }
            blocked["outcome"] = {"kind": "unsupported"}
            _write_machine(machine, [compiled, blocked])

            package = write_stage_b_interpreter_package(
                state_machine=machine,
                out=root / "package",
            )

            self.assertEqual(package["status"], "incomplete")
            self.assertEqual(package["counts"]["transfers"], 1)
            self.assertEqual(package["counts"]["blocked_transfers"], 1)
            program = json.loads(
                (root / "package/state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            metadata = program["definedness_use"]
            self.assertEqual(metadata["evidence_slot_count"], 2)
            self.assertEqual(metadata["unused_evidence_slot_count"], 1)
            self.assertEqual(metadata["undefined_node_count"], 1)
            self.assertEqual(len(metadata["slots"]), 1)
            self.assertEqual(
                metadata["slots"][0]["uses"][0]["transfer_id"],
                "semantic-transfer:fixture",
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


if __name__ == "__main__":
    unittest.main()
