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


def _rep_scas_event() -> dict[str, object]:
    return {
        "family": "external",
        "kind": "rep_scas",
        "index": 0,
        "instruction_rva": 0x1000,
        "element_width": 1,
        "address_size": 32,
        "destination": {"op": "reg", "name": "edi", "width": 32},
        "accumulator": {"op": "reg", "name": "eax", "width": 32},
        "count": {"op": "reg", "name": "ecx", "width": 32},
        "direction_flag": {"op": "flag", "name": "df"},
        "repeat_condition": "while_not_equal_v1",
        "comparison_model": "subtraction_flags_v1",
        "segment_model": "flat_es_zero_v1",
        "effect_model": "symbolic_string_scan_v1",
        "restart_semantics": "element_committed_v1",
        "fault_model": "read_before_commit_v1",
        "owned_register_outputs": ["edi", "ecx"],
        "owned_flag_outputs": ["cf", "pf", "af", "zf", "sf", "of"],
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
            "external_events": [
                {
                    "kind": "external_call",
                    "return_rva": 0x1002,
                    "dll": "msvcrt.dll",
                    "symbol": "_unlock",
                    "ordinal": None,
                    "register_inputs": registers,
                    "flag_inputs": flags,
                    "arguments": [],
                    "stack_inputs": [
                        {
                            "offset": 0,
                            "width": 4,
                            "value": {
                                "op": "const",
                                "value": 17,
                                "width": 32,
                            },
                        }
                    ],
                }
            ],
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


def _machine_ir_stack_call_after_register_reuse_unit() -> dict[str, object]:
    registers = {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }

    def address(offset: int) -> dict[str, object]:
        return {
            "op": "add32",
            "args": [
                registers["esp"],
                {"op": "const", "value": offset, "width": 32},
            ],
        }

    def load(offset: int) -> dict[str, object]:
        return {"op": "load", "width": 4, "address": address(offset)}

    frame_esp = {
        "op": "sub32",
        "args": [
            registers["esp"],
            {"op": "const", "value": 28, "width": 32},
        ],
    }

    def aggregate_load(offset: int) -> dict[str, object]:
        return {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    frame_esp,
                    {"op": "const", "value": offset, "width": 32},
                ],
            },
        }

    empty_effects = {
        "register_writes": [],
        "defined_flag_writes": [],
        "undefined_flag_writes": [],
        "ordered_events": [],
    }
    stack_inputs = [
        {"offset": offset, "width": 4, "value": aggregate_load(offset)}
        for offset in (12, 16)
    ]
    call = {
        "kind": "external_call",
        "instruction_rva": 0x100F,
        "return_rva": 0x1015,
        "dll": "fixture.dll",
        "symbol": "Consume",
        "ordinal": None,
        "register_inputs": registers,
        "flag_inputs": flags,
        "arguments": [],
        "stack_inputs": stack_inputs,
    }
    records = [
        {
            "rva_start": 0x1000,
            "rva_end": 0x1003,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "effects": {
                **empty_effects,
                "register_writes": [{"register": "esp", "value": frame_esp}],
                "control": {"kind": "fallthrough", "target_rva": 0x1003},
            },
        },
        {
            "rva_start": 0x1003,
            "rva_end": 0x1007,
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
                    "family": "memory",
                    "kind": "write",
                    "width": 4,
                    "address": address(12),
                    "value": registers["edx"],
                }],
                "control": {"kind": "fallthrough", "target_rva": 0x1007},
            },
        },
        {
            "rva_start": 0x1007,
            "rva_end": 0x100B,
            "instruction_class": "ordinary_symbolic_instruction",
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "proof_authority": False,
                "checked_decoder": "StageA.Formal.decodeInstructionExact",
                "checked_executor": "StageA.Formal.executeInstruction",
            },
            "effects": {
                **empty_effects,
                "register_writes": [{"register": "edx", "value": load(92)}],
                "ordered_events": [{
                    "family": "memory",
                    "kind": "read",
                    "width": 4,
                    "address": address(92),
                }],
                "control": {"kind": "fallthrough", "target_rva": 0x100B},
            },
        },
        {
            "rva_start": 0x100B,
            "rva_end": 0x100F,
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
                    "family": "memory",
                    "kind": "write",
                    "width": 4,
                    "address": address(16),
                    "value": registers["edx"],
                }],
                "control": {"kind": "fallthrough", "target_rva": 0x100F},
            },
        },
        {
            "rva_start": 0x100F,
            "rva_end": 0x1015,
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
                    **call,
                    "stack_inputs": [],
                }],
                "control": {
                    "kind": "external_jump",
                    "dll": "fixture.dll",
                    "symbol": "Consume",
                    "ordinal": None,
                },
            },
        },
    ]
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "semantic-transfer:stack-call-after-register-reuse",
        "status": "qualified",
        "reachable": True,
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1015, "size": 21},
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
            "external_events": [call],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {
                "kind": "external_jump",
                "dll": "fixture.dll",
                "symbol": "Consume",
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
                "rva_end": 0x1015,
                "records": records,
                "blockers": [],
                "counts": {
                    "instructions": 5,
                    "x87_singletons": 0,
                    "ordinary_instructions": 5,
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
            write_stage_b_interpreter_package(machine_ir=machine, out=package_dir)
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

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  fixture_context *context = (fixture_context *)runtime->context;
  if (event->stack_input_count != 2U) return STAGE_B_CALL_UNIMPLEMENTED;
  if (event->stack_inputs[0].offset != 12U ||
      event->stack_inputs[0].value != 0xaaaaaaaaU ||
      event->stack_inputs[1].offset != 16U ||
      event->stack_inputs[1].value != 0xbbbbbbbbU)
    return STAGE_B_CALL_UNIMPLEMENTED;
  context->observed = 1U;
  *output = *input;
  return STAGE_B_CALL_OK;
}

int main(void) {
  fixture_context context = {0U, 0U, 0U};
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;
  state.esp = 0x1000U;
  state.edx = 0xaaaaaaaaU;
  result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (context.observed != 1U) return 1;
  if (context.word_12 != 0xaaaaaaaaU ||
      context.word_16 != 0xbbbbbbbbU) return 2;
  if (result.kind == STAGE_B_MEMORY_FAULT ||
      result.kind == STAGE_B_UNIMPLEMENTED) return 3;
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

            transfer = compile_stage_b_interpreter_program(machine)[0]

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

            transfer = compile_stage_b_interpreter_program(machine)[0]
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
            package = write_stage_b_interpreter_package(
                state_machine=machine,
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

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

static void initial_flags(stage_b_machine_state *state) {
  state->cf = 1U; state->zf = 0U; state->sf = 1U;
  state->of = 1U; state->pf = 0U; state->eflags = 1U << 4;
}

static int flags_are(
    const stage_b_machine_state *state, uint32_t cf, uint32_t zf,
    uint32_t sf, uint32_t of, uint32_t pf, uint32_t af) {
  return state->cf == cf && state->zf == zf && state->sf == sf &&
      state->of == of && state->pf == pf &&
      ((state->eflags >> 4) & 1U) == af;
}

static stage_b_step_result run(
    scan_context *context, stage_b_machine_state *state) {
  stage_b_runtime runtime = {0};
  runtime.context = context; runtime.read = read_byte; runtime.write = write_unused;
  return stage_b_interpreter_step(&runtime, state, 0x1000U);
}

int main(void) {
  const uint32_t base = 0x3000U;
  scan_context context = {base, 0xffffffffU, 0U, {0U,0U,0U,0U}};
  stage_b_machine_state state = {0};
  stage_b_step_result result;

  state.eax = 0x41U; state.edi = base; state.ecx = 0U; initial_flags(&state);
  result = run(&context, &state);
  if (result.kind != STAGE_B_FALLTHROUGH || context.reads != 0U) return 1;
  if (state.edi != base || state.ecx != 0U ||
      !flags_are(&state, 1U,0U,1U,1U,0U,1U)) return 2;
  if (state.eax != 0xdeadbeefU || state.df != 0U) return 3;

  context = (scan_context){base, 0xffffffffU, 0U, {0U,0x41U,0x10U,0U}};
  state = (stage_b_machine_state){0};
  state.eax = 0x41U; state.edi = base + 2U; state.ecx = 2U; state.df = 1U;
  result = run(&context, &state);
  if (result.kind != STAGE_B_FALLTHROUGH || context.reads != 2U) return 4;
  if (state.edi != base || state.ecx != 0U ||
      !flags_are(&state, 0U,1U,0U,0U,1U,0U) || state.df != 0U) return 5;

  context = (scan_context){base, 0xffffffffU, 0U, {1U,2U,0U,0U}};
  state = (stage_b_machine_state){0};
  state.eax = 0U; state.edi = base; state.ecx = 2U;
  result = run(&context, &state);
  if (result.kind != STAGE_B_FALLTHROUGH || state.edi != base + 2U ||
      state.ecx != 0U || !flags_are(&state, 1U,0U,1U,0U,0U,1U)) return 6;

  context = (scan_context){base, base + 1U, 0U, {0x42U,0U,0U,0U}};
  state = (stage_b_machine_state){0};
  state.eax = 0x41U; state.edi = base; state.ecx = 3U;
  result = run(&context, &state);
  if (result.kind != STAGE_B_MEMORY_FAULT || result.target_rva != 0x1000U ||
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

    def test_rep_scas_event_validation_fails_closed(self) -> None:
        cases = (
            ({"element_width": 2}, "byte element width"),
            ({"address_size": 16}, "32-bit address size"),
            ({"repeat_condition": "unchecked"}, "while_not_equal_v1"),
            ({"comparison_model": "unchecked"}, "subtraction_flags_v1"),
            ({"segment_model": "unchecked"}, "flat_es_zero_v1"),
            ({"effect_model": "unchecked"}, "symbolic_string_scan_v1"),
            ({"restart_semantics": "unchecked"}, "element_committed_v1"),
            ({"fault_model": "unchecked"}, "read_before_commit_v1"),
            ({"owned_register_outputs": ["edi"]}, "owned-output inventory"),
        )
        for (mutation, message) in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                machine = Path(temporary) / "state-machine.jsonl"
                row = _row()
                row["ordered_events"] = [{**_rep_scas_event(), **mutation}]
                _write_machine(machine, [row])
                with self.assertRaisesRegex(StageBInterpreterError, message) as raised:
                    compile_stage_b_interpreter_program(machine)
                self.assertEqual(raised.exception.code, "malformed_rep_scas_event")

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
            write_stage_b_interpreter_package(state_machine=machine, out=package_dir)

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

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

int main(void) {
  copy_context context = {0U};
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  runtime.context = &context;
  runtime.read = read_word;
  runtime.write = write_word;
  state.esi = 0x2000U;
  state.edi = 0x3000U;
  state.ecx = 3U;
  result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != STAGE_B_MEMORY_FAULT) return 1;
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
            interpreter_header = (
                first / "state-machine-interpreter.h"
            ).read_text(encoding="ascii")
            interpreter_source = (
                first / "state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            self.assertIn("uint32_t fallback_on_unimplemented;", interpreter_header)
            self.assertIn(
                "result.kind==STAGE_B_UNIMPLEMENTED&&override->fallback_on_unimplemented",
                interpreter_source,
            )
            self.assertIn("t=stage_b_program_lookup(source_rva);", interpreter_source)
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
