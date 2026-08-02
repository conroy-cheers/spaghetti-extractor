from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from spaghetti_extractor.stage_b_interpreter_backend import (
    StageBInterpreterError,
    compile_stage_b_interpreter_machine_ir,
    compile_stage_b_interpreter_program,
    write_stage_b_interpreter_package,
)
from spaghetti_extractor.stage_b_typed_x87 import (
    typed_x87_operation_from_micro_op,
    typed_x87_operation_from_payload,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_bytes


_CONTRACT_SHA = "a" * 64
_MISSING_PHYSICAL_FIELDS = [
    "tags",
    "pending_exception",
    "last_opcode",
    "instruction_pointer",
    "code_selector",
    "data_pointer",
    "data_selector",
]
_REQUIRED_PHYSICAL_FIELDS = [
    "stack",
    "tags",
    "control",
    "status",
    "pending_exception",
    "last_opcode",
    "instruction_pointer",
    "code_selector",
    "data_pointer",
    "data_selector",
]


def _replay_row(
    *,
    identity: str = "semantic-transfer:x87-replay",
    rva_start: int = 0x1000,
    encoded: bytes = bytes.fromhex("d9e8"),
) -> dict[str, object]:
    rva_end = rva_start + len(encoded)
    digest = sha256_bytes(encoded)
    replay_instruction = {
        "rva": rva_start,
        "size": len(encoded),
        "bytes": encoded.hex(),
    }
    instruction = {
        **replay_instruction,
        "mnemonic": "fld1",
        "op_str": "",
    }
    return {
        "id": identity,
        "status": "incomplete",
        "contract_sha256": _CONTRACT_SHA,
        "instruction_bytes_sha256": digest,
        "original": {
            "rva_start": rva_start,
            "rva_end": rva_end,
            "size": len(encoded),
        },
        "instructions": [dict(instruction)],
        "ordered_events": [],
        "register_writes": [],
        "flag_writes": [],
        "fpu_state": {
            "model": "native_exact_x87_command_replay_obligation_v1",
            "status": "required",
            "authoritative_state_type": "StageA.X87.PhysicalState",
            "required_fields": list(_REQUIRED_PHYSICAL_FIELDS),
            "missing_or_invalid_fields": list(_MISSING_PHYSICAL_FIELDS),
            "logical_state_guidance": {
                "stack": [
                    {"op": "fpu_reg", "args": [index]} for index in range(8)
                ],
                "control": {"op": "fpu_control", "args": []},
                "status": {"op": "fpu_status", "args": []},
            },
            "replay": {
                "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
                "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
                "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
                "architecture": "x86",
                "bitness": 32,
                "image_base": 0x400000,
                "rva_start": rva_start,
                "rva_end": rva_end,
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [dict(replay_instruction)],
            },
        },
        "outcome": {"kind": "fallthrough", "target_rva": rva_end},
    }


def _write_machine(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _machine_ir_x87_unit(*, mnemonic: str = "fld1", operands: list[object] | None = None) -> dict[str, object]:
    digest = sha256_bytes(bytes.fromhex("d9e8"))
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "semantic-transfer:x87-replay",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
            "contract_sha256": _CONTRACT_SHA,
            "instruction_bytes_sha256": digest,
        },
        "x87_micro_ops": [{
            "format": "stage-a-x87-micro-op-v1",
            "id": "semantic-transfer:x87-replay:x87:00001000",
            "unit_id": "semantic-transfer:x87-replay",
            "rva_start": 0x1000,
            "rva_end": 0x1002,
            "size": 2,
            "instruction_sha256": digest,
            "transfer_instruction_sha256": digest,
            "mnemonic": mnemonic,
            "operands": [] if operands is None else operands,
            "implicit_registers_read": [],
            "implicit_registers_written": [],
            "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
            "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
            "physical_state_effect": "defined_by_checked_typed_x87_executor",
        }],
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "fallthrough", "target_rva": 0x1002},
            "stack_delta": 0,
            "counts": {},
            "fpu_state": {
                "typed_replay": {
                    "image_base": 0x400000,
                    "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
                    "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
                }
            },
            "instruction_effect_schedule": None,
        },
    }


def _machine_ir_mixed_unit() -> dict[str, object]:
    unit = _machine_ir_x87_unit()
    transfer_digest = sha256_bytes(bytes.fromhex("d9e840"))
    unit["source"]["original"] = {
        "rva_start": 0x1000,
        "rva_end": 0x1003,
        "size": 3,
    }
    unit["source"]["instruction_bytes_sha256"] = transfer_digest
    unit["x87_micro_ops"][0]["transfer_instruction_sha256"] = transfer_digest
    x87_effects = {
        "ordered_events": [],
        "register_writes": [],
        "defined_flag_writes": [],
        "undefined_flag_writes": [],
        "control": {"kind": "fallthrough", "target_rva": 0x1002},
    }
    ordinary_effects = {
        "ordered_events": [],
        "register_writes": [{
            "register": "eax",
            "value": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "eax", "width": 32},
                    {"op": "const", "value": 1, "width": 32},
                ],
            },
        }],
        "defined_flag_writes": [],
        "undefined_flag_writes": [],
        "control": {"kind": "fallthrough", "target_rva": 0x1003},
    }
    unit["semantics"]["outcome"] = {
        "kind": "fallthrough",
        "target_rva": 0x1003,
    }
    unit["semantics"]["instruction_effect_schedule"] = {
        "format": "stage-a-instruction-ordered-effect-schedule-v1",
        "status": "complete",
        "proof_authority": False,
        "ordering": "strict_contiguous_rva_order",
        "rva_start": 0x1000,
        "rva_end": 0x1003,
        "source_schedule_sha256": "f" * 64,
        "records": [
            {
                "index": 0,
                "rva_start": 0x1000,
                "rva_end": 0x1002,
                "instruction_class": "x87_singleton_checked_replay",
                "classification": {
                    "status": "proposal_requires_lean_exact_byte_replay",
                    "proof_authority": False,
                    "checked_decoder": "StageA.Relational.X87.decodeSingletonCommand",
                    "checked_executor": "StageA.Relational.X87.executeSingletonCommand",
                },
                "effects": x87_effects,
            },
            {
                "index": 1,
                "rva_start": 0x1002,
                "rva_end": 0x1003,
                "instruction_class": "ordinary_symbolic_instruction",
                "classification": {
                    "status": "proposal_requires_lean_exact_byte_replay",
                    "proof_authority": False,
                    "checked_decoder": "StageA.Formal.decodeInstructionExact",
                    "checked_executor": "StageA.Formal.executeInstruction",
                },
                "effects": ordinary_effects,
            },
        ],
        "blockers": [],
        "counts": {
            "instructions": 2,
            "x87_singletons": 1,
            "ordinary_instructions": 1,
            "blockers": 0,
        },
    }
    return unit


def _machine_ir_adc_carry_unit() -> dict[str, object]:
    unit = _machine_ir_x87_unit()
    unit["id"] = "semantic-transfer:adc-carry"
    unit["source"]["original"] = {
        "rva_start": 0x2000, "rva_end": 0x2002, "size": 2,
    }
    unit["x87_micro_ops"] = []
    unit["semantics"]["fpu_state"] = None
    unit["semantics"]["flag_writes"] = [{
        "flag": "cf",
        "value": {
            "op": "adc_carry",
            "args": [
                {"op": "const", "value": 32, "width": 32},
                {"op": "reg", "name": "eax", "width": 32},
                {"op": "reg", "name": "ebx", "width": 32},
                {"op": "flag", "name": "cf"},
                {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "eax", "width": 32},
                        {"op": "reg", "name": "ebx", "width": 32},
                        {"op": "flag", "name": "cf"},
                    ],
                },
            ],
        },
    }, {
        "flag": "of",
        "value": {
            "op": "adc_overflow",
            "args": [
                {"op": "const", "value": 32, "width": 32},
                {"op": "reg", "name": "eax", "width": 32},
                {"op": "reg", "name": "ebx", "width": 32},
                {"op": "flag", "name": "cf"},
                {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "eax", "width": 32},
                        {"op": "reg", "name": "ebx", "width": 32},
                        {"op": "flag", "name": "cf"},
                    ],
                },
            ],
        },
    }]
    unit["semantics"]["outcome"] = {
        "kind": "fallthrough", "target_rva": 0x2002,
    }
    return unit


def _json_sha256(value: object) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _scheduled_mixed_row() -> dict[str, object]:
    """One checked x87 command followed by an ordinary post-state update."""

    row = _replay_row(encoded=bytes.fromhex("d9e840"))
    transfer_digest = sha256_bytes(bytes.fromhex("d9e840"))
    row["instructions"] = [
        {"rva": 0x1000, "size": 2, "bytes": "d9e8", "mnemonic": "fld1", "op_str": ""},
        {"rva": 0x1002, "size": 1, "bytes": "40", "mnemonic": "inc", "op_str": "eax"},
    ]
    fpu = row["fpu_state"]
    assert isinstance(fpu, dict)
    replay = fpu["replay"]
    assert isinstance(replay, dict)
    replay["instructions"] = [
        {"rva": 0x1000, "size": 2, "bytes": "d9e8"},
        {"rva": 0x1002, "size": 1, "bytes": "40"},
    ]

    def effects(
        target: int, *, register_writes: list[dict[str, object]] | None = None
    ) -> dict[str, object]:
        writes = register_writes or []
        return {
            "register_writes": writes,
            "defined_flag_writes": [],
            "undefined_flags": [],
            "undefined_flag_writes": [],
            "memory_events": [],
            "faults": [],
            "control": {"kind": "fallthrough", "target_rva": target},
            "call_effects": [],
            "ordered_events": [],
            "counts": {
                "register_writes": len(writes),
                "defined_flag_writes": 0,
                "undefined_flags": 0,
                "undefined_flag_writes": 0,
                "memory_events": 0,
                "faults": 0,
                "call_effects": 0,
                "ordered_events": 0,
            },
        }

    records: list[dict[str, object]] = []
    for index, start, encoded, mnemonic, is_x87, instruction_effects in (
        (0, 0x1000, bytes.fromhex("d9e8"), "fld1", True, effects(0x1002)),
        (
            1,
            0x1002,
            bytes.fromhex("40"),
            "inc",
            False,
            effects(
                0x1003,
                register_writes=[
                    {
                        "register": "eax",
                        "value": {
                            "op": "add32",
                            "args": [
                                {"op": "reg", "name": "eax", "width": 32},
                                {"op": "const", "value": 1, "width": 32},
                            ],
                        },
                    }
                ],
            ),
        ),
    ):
        stop = start + len(encoded)
        decoder = (
            "StageA.Relational.X87.decodeSingletonCommand"
            if is_x87
            else "StageA.Formal.decodeInstructionExact"
        )
        executor = (
            "StageA.Relational.X87.executeSingletonCommand"
            if is_x87
            else "StageA.Formal.executeInstruction"
        )
        record: dict[str, object] = {
            "index": index,
            "rva_start": start,
            "rva_end": stop,
            "bytes": encoded.hex(),
            "bytes_sha256": sha256_bytes(encoded),
            "transfer_bytes_sha256": transfer_digest,
            "instruction_class": (
                "x87_singleton_checked_replay"
                if is_x87
                else "ordinary_symbolic_instruction"
            ),
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "source": "normalized_symbolic_equivalence_v1",
                "proof_authority": False,
                "mnemonic_guidance": mnemonic,
                "operand_guidance": "",
                "checked_decoder": decoder,
                "checked_executor": executor,
            },
            "symbolic_pre_state_sha256": "1" * 64,
            "symbolic_post_state_sha256": "2" * 64,
            "effects": instruction_effects,
        }
        if is_x87:
            record["x87_singleton_replay"] = {
                "rva_start": start,
                "rva_end": stop,
                "bytes": encoded.hex(),
                "bytes_sha256": sha256_bytes(encoded),
                "checked_decoder": decoder,
                "checked_executor": executor,
                "physical_state_effect": (
                    "produced_by_checked_executor_not_inferred_by_exporter"
                ),
            }
        record["record_sha256"] = _json_sha256(record)
        records.append(record)

    schedule: dict[str, object] = {
        "format": "stage-a-instruction-ordered-effect-schedule-v1",
        "status": "complete",
        "proof_authority": False,
        "ordering": "strict_contiguous_rva_order",
        "rva_start": 0x1000,
        "rva_end": 0x1003,
        "transfer_bytes_sha256": transfer_digest,
        "records": records,
        "blockers": [],
        "counts": {
            "instructions": 2,
            "x87_singletons": 1,
            "ordinary_instructions": 1,
            "blockers": 0,
        },
    }
    schedule["schedule_sha256"] = _json_sha256(schedule)
    replay["instruction_effect_schedule"] = schedule
    row["instruction_effect_schedule"] = schedule
    return row


class StageBInterpreterX87ReplayTests(unittest.TestCase):
    def test_typed_operation_payload_round_trips_canonically(self) -> None:
        operation = typed_x87_operation_from_micro_op(
            _machine_ir_x87_unit()["x87_micro_ops"][0], image_base=0x400000
        )

        self.assertEqual(
            typed_x87_operation_from_payload(
                operation.payload(), image_base=0x400000
            ),
            operation,
        )

    def test_typed_operation_payload_rejects_identity_corruption(self) -> None:
        operation = typed_x87_operation_from_micro_op(
            _machine_ir_x87_unit()["x87_micro_ops"][0], image_base=0x400000
        ).payload()
        operation["identity"] = "0" * 64

        with self.assertRaisesRegex(StageAInputError, "canonical representation"):
            typed_x87_operation_from_payload(operation, image_base=0x400000)

    def test_typed_micro_op_rejects_malformed_address_registers(self) -> None:
        unit = _machine_ir_x87_unit(
            mnemonic="fld",
            operands=[{
                "kind": "memory",
                "width_bits": 32,
                "segment": None,
                "base": 7,
                "index": None,
                "scale": 1,
                "displacement": 0,
            }],
        )

        with self.assertRaisesRegex(StageAInputError, "memory base is malformed"):
            typed_x87_operation_from_micro_op(
                unit["x87_micro_ops"][0], image_base=0x400000
            )

    def test_byte_free_machine_ir_generates_same_typed_interpreter_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            _write_machine(machine_ir, [_machine_ir_x87_unit()])

            transfer = compile_stage_b_interpreter_machine_ir(machine_ir)[0]
            self.assertEqual(transfer.x87_operations[0].operation.mnemonic, "fld1")
            package = write_stage_b_interpreter_package(
                machine_ir=machine_ir, out=root / "package"
            )
            self.assertEqual(package["status"], "ready", package["blockers"])
            self.assertEqual(package["input_mode"], "sanitized_machine_ir_v2")
            for path in (root / "package").iterdir():
                if path.suffix not in {".c", ".h", ".json", ".jsonl"}:
                    continue
                generated = path.read_text(encoding="utf-8")
                self.assertNotIn("d9e8", generated)
                self.assertNotIn("instruction_bytes", generated)
                self.assertNotIn(".byte", generated)

    def test_malformed_byte_free_x87_form_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine_ir = Path(temporary) / "machine-ir.jsonl"
            _write_machine(
                machine_ir,
                [_machine_ir_x87_unit(
                    mnemonic="fld1",
                    operands=[{
                        "kind": "immediate", "value": 1,
                        "width_bits": 32, "access": "read",
                    }],
                )],
            )
            with self.assertRaises(StageBInterpreterError) as raised:
                compile_stage_b_interpreter_machine_ir(machine_ir)
            self.assertEqual(raised.exception.code, "unsupported_typed_x87_operation")

    def test_byte_free_micro_op_must_bind_its_unit_and_checker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine_ir = Path(temporary) / "machine-ir.jsonl"
            unit = _machine_ir_x87_unit()
            unit["x87_micro_ops"][0]["unit_id"] = "semantic-transfer:other"
            _write_machine(machine_ir, [unit])
            with self.assertRaises(StageBInterpreterError) as raised:
                compile_stage_b_interpreter_machine_ir(machine_ir)
            self.assertEqual(raised.exception.code, "malformed_typed_x87_operation")

    def test_byte_free_machine_ir_rejects_raw_opcode_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine_ir = Path(temporary) / "machine-ir.jsonl"
            unit = _machine_ir_x87_unit()
            unit["x87_micro_ops"][0]["bytes"] = "d9e8"
            _write_machine(machine_ir, [unit])
            with self.assertRaises(StageBInterpreterError) as raised:
                compile_stage_b_interpreter_machine_ir(machine_ir)
            self.assertEqual(raised.exception.code, "malformed_machine_ir_input")

    def test_byte_free_machine_ir_composes_x87_and_ordinary_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            _write_machine(machine_ir, [_machine_ir_mixed_unit()])

            transfer = compile_stage_b_interpreter_machine_ir(machine_ir)[0]
            self.assertEqual(
                [action.op for action in transfer.actions],
                [
                    "typed_x87", "eval_word", "eval_word", "eval_word",
                    "set_reg", "sync_eflags", "outcome_fallthrough",
                ],
            )
            package = write_stage_b_interpreter_package(
                machine_ir=machine_ir, out=root / "package"
            )
            self.assertEqual(package["status"], "ready", package["blockers"])

    def test_byte_free_machine_ir_supports_adc_carry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            _write_machine(machine_ir, [_machine_ir_adc_carry_unit()])

            transfer = compile_stage_b_interpreter_machine_ir(machine_ir)[0]
            node_ops = [node.op for node in transfer.nodes]
            self.assertIn("adc_carry", node_ops)
            self.assertIn("adc_overflow", node_ops)
            package = write_stage_b_interpreter_package(
                machine_ir=machine_ir, out=root / "package"
            )
            self.assertEqual(package["status"], "ready", package["blockers"])
            source = (
                root / "package/state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            self.assertIn("if (op == 71U)", source)
            self.assertIn("if (op == 72U)", source)
            compiler = shutil.which("cc")
            if compiler is None:
                return
            harness = root / "adc-harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"
stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}
static int check(uint32_t left, uint32_t right, uint32_t carry,
                 uint32_t expected_cf, uint32_t expected_of) {
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  state.eax = left; state.ebx = right; state.cf = carry;
  result = stage_b_interpreter_step(&runtime, &state, 0x2000U);
  if (result.kind != STAGE_B_FALLTHROUGH || result.target_rva != 0x2002U)
    return 10;
  if (state.cf != expected_cf) return 20;
  if (state.of != expected_of) return 30;
  return 0;
}
int main(void) {
  int result;
  if ((result = check(0xffffffffU, 0U, 1U, 1U, 0U)) != 0) return result + 1;
  if ((result = check(0x7fffffffU, 0U, 1U, 0U, 1U)) != 0) return result + 2;
  if ((result = check(0x80000000U, 0xffffffffU, 1U, 1U, 0U)) != 0) return result + 3;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "adc-harness"
            subprocess.run(
                [
                    compiler, "-std=c11", "-I", str(root / "package"),
                    str(root / "package/state-machine-interpreter.c"),
                    str(root / "package/state-machine-program.c"),
                    str(harness), "-o", str(executable),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run(
                [str(executable)], check=True, text=True, capture_output=True
            )

    def test_linked_regional_override_precedes_lookup_and_fails_closed(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("native C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            package_dir = root / "package"
            unit = _machine_ir_x87_unit()
            unit["x87_micro_ops"] = []
            unit["semantics"]["fpu_state"] = None
            _write_machine(machine_ir, [unit])
            write_stage_b_interpreter_package(
                machine_ir=machine_ir, out=package_dir
            )
            source = (
                package_dir / "state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            self.assertLess(
                source.index("override=stage_b_region_override_lookup(source_rva)"),
                source.index("t=stage_b_program_lookup(source_rva)"),
            )
            harness = root / "override-harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

static stage_b_step_result valid_override(
    stage_b_runtime *runtime, stage_b_machine_state *state) {
  (void)runtime;
  state->eax = 0x12345678U;
  return (stage_b_step_result){STAGE_B_JUMP, 0x2000U, 0U};
}

static stage_b_step_result malformed_override(
    stage_b_runtime *runtime, stage_b_machine_state *state) {
  (void)runtime;
  state->eax = 0xffffffffU;
  return (stage_b_step_result){(stage_b_control_kind)99U, 7U, 9U};
}

static const stage_b_region_override overrides[] = {
  {0x1000U, valid_override, "valid", "fixture"},
  {0x3000U, malformed_override, "malformed", "fixture"},
};

const stage_b_region_override *stage_b_region_override_lookup(uint32_t rva) {
  if (rva == 0x1000U) return &overrides[0];
  if (rva == 0x3000U) return &overrides[1];
  return (const stage_b_region_override *)0;
}

int main(void) {
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != STAGE_B_JUMP || result.target_rva != 0x2000U) return 1;
  if (state.eax != 0x12345678U) return 2;
  state.eax = 0x55U;
  result = stage_b_interpreter_step(&runtime, &state, 0x3000U);
  if (result.kind != STAGE_B_UNIMPLEMENTED || result.target_rva != 0x3000U) return 3;
  return state.eax == 0x55U ? 0 : 4;
}
''',
                encoding="ascii",
            )
            executable = root / "override-harness"
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
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
            subprocess.run(
                [str(executable)], check=True, text=True, capture_output=True
            )

    def test_exact_singleton_lowers_to_sanitized_typed_native_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_replay_row()])

            transfer = compile_stage_b_interpreter_program(machine)[0]
            operation = transfer.x87_operations[0]

            self.assertEqual([action.op for action in transfer.actions], [
                "typed_x87",
                "outcome_fallthrough",
            ])
            self.assertEqual(transfer.nodes, ())
            self.assertEqual(transfer.x87_nodes, ())
            self.assertEqual(operation.operation.mnemonic, "fld1")
            self.assertEqual(operation.operation.operand.kind, "none")
            self.assertEqual(operation.rva_start, 0x1000)
            self.assertEqual(operation.rva_end, 0x1002)
            self.assertEqual(operation.contract_sha256, _CONTRACT_SHA)
            with self.assertRaises(FrozenInstanceError):
                operation.rva_start = 0x2000  # type: ignore[misc]

            package = write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )
            program = json.loads(
                (root / "package/state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            operation_record = program["transfers"][0]["x87_operations"][0]
            self.assertEqual(package["status"], "ready")
            self.assertEqual(
                operation_record["operation"]["mnemonic"], "fld1"
            )
            self.assertEqual(
                operation_record["operation"]["operand"], {"kind": "none"}
            )
            self.assertTrue(set(_REQUIRED_PHYSICAL_FIELDS).isdisjoint(operation_record))
            runtime_header = (
                root / "package/state-machine-runtime.h"
            ).read_text(encoding="ascii")
            program_source = (
                root / "package/state-machine-program.c"
            ).read_text(encoding="ascii")
            interpreter_source = (
                root / "package/state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            self.assertIn("stage_b_typed_x87_handler", runtime_header)
            self.assertIn("execute_typed_x87_operation", runtime_header)
            self.assertIn("static const stage_b_typed_x87_operation", program_source)
            self.assertNotIn("0xd9U,0xe8U", program_source)
            self.assertIn("{ 25U, 1U, 0U, {0U,0U,0U,0U,0U} }", program_source)
            self.assertEqual(
                program["transfers"][0]["instruction_bytes_sha256"],
                sha256_bytes(bytes.fromhex("d9e8")),
            )
            self.assertNotIn("instruction_bytes", json.dumps(operation_record, sort_keys=True))
            for generated in (runtime_header, program_source):
                self.assertNotIn("instruction_bytes", generated)
                self.assertNotIn(".byte", generated)
            self.assertNotIn("long double", interpreter_source)
            self.assertNotIn("stage_b_eval_x87", interpreter_source)
            self.assertNotIn("stage_b_x87_binary", interpreter_source)

    def test_contiguous_x87_commands_lower_to_ordered_singletons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            encoded = bytes.fromhex("d9e8ddd8")
            row = _replay_row(encoded=encoded)
            row["instructions"] = [
                {
                    "rva": 0x1000,
                    "size": 2,
                    "bytes": "d9e8",
                    "mnemonic": "fld1",
                    "op_str": "",
                },
                {
                    "rva": 0x1002,
                    "size": 2,
                    "bytes": "ddd8",
                    "mnemonic": "fstp",
                    "op_str": "st(0)",
                },
            ]
            fpu = row["fpu_state"]
            assert isinstance(fpu, dict)
            replay = fpu["replay"]
            assert isinstance(replay, dict)
            replay["instructions"] = [
                {"rva": 0x1000, "size": 2, "bytes": "d9e8"},
                {"rva": 0x1002, "size": 2, "bytes": "ddd8"},
            ]
            _write_machine(machine, [row])

            transfer = compile_stage_b_interpreter_program(machine)[0]

            self.assertEqual(
                [action.op for action in transfer.actions],
                ["typed_x87", "typed_x87", "outcome_fallthrough"],
            )
            self.assertEqual([action.args for action in transfer.actions[:2]], [(0,), (1,)])
            self.assertEqual(
                [(item.rva_start, item.rva_end) for item in transfer.x87_operations],
                [(0x1000, 0x1002), (0x1002, 0x1004)],
            )
            self.assertEqual(
                [item.operation.mnemonic for item in transfer.x87_operations],
                ["fld1", "fstp"],
            )

    def test_checked_schedule_uses_post_replay_state_for_ordinary_effects(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("native C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            package_dir = root / "package"
            _write_machine(machine, [_scheduled_mixed_row()])

            transfer = compile_stage_b_interpreter_program(machine)[0]
            replay_action = next(
                index
                for index, action in enumerate(transfer.actions)
                if action.op == "typed_x87"
            )
            post_replay_register = next(
                index
                for index, action in enumerate(transfer.actions)
                if action.op == "set_reg" and action.aux == 0
            )
            register_node = next(
                node for node in transfer.nodes if node.op == "reg" and node.aux == 0
            )
            self.assertLess(replay_action, post_replay_register)
            self.assertEqual(register_node.immediate, 1)
            self.assertEqual(transfer.x87_nodes, ())

            package = write_stage_b_interpreter_package(
                state_machine=machine, out=package_dir
            )
            self.assertEqual(package["status"], "ready")
            self.assertEqual(package["counts"]["x87_nodes"], 0)
            harness = root / "mixed-replay-harness.c"
            harness.write_text(
                r'''
#include "state-machine-interpreter.h"

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

static stage_b_call_status checked_operation(
    stage_b_runtime *runtime, const stage_b_typed_x87_operation *program,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)input;
  if (program->rva_start != 0x1000U || program->rva_end != 0x1002U)
    return STAGE_B_CALL_UNIMPLEMENTED;
  output->eax = 40U;
  output->x87_status = 0x1234U;
  return STAGE_B_CALL_OK;
}

int main(void) {
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result;
  state.eax = 1U;
  runtime.execute_typed_x87_operation = checked_operation;
  result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != STAGE_B_FALLTHROUGH || result.target_rva != 0x1003U) return 1;
  if (state.eax != 41U) return 2;
  return state.x87_status == 0x1234U ? 0 : 3;
}
''',
                encoding="ascii",
            )
            executable = root / "mixed-replay-harness"
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
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
            subprocess.run([str(executable)], check=True, text=True, capture_output=True)

    def test_checked_schedule_mutations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            row = _scheduled_mixed_row()
            schedule = row["instruction_effect_schedule"]
            assert isinstance(schedule, dict)
            records = schedule["records"]
            assert isinstance(records, list)
            ordinary = records[1]
            assert isinstance(ordinary, dict)
            effects = ordinary["effects"]
            assert isinstance(effects, dict)
            control = effects["control"]
            assert isinstance(control, dict)
            control["target_rva"] = 0x2000
            ordinary["record_sha256"] = _json_sha256(
                {key: value for key, value in ordinary.items() if key != "record_sha256"}
            )
            schedule["schedule_sha256"] = _json_sha256(
                {key: value for key, value in schedule.items() if key != "schedule_sha256"}
            )
            fpu = row["fpu_state"]
            assert isinstance(fpu, dict)
            replay = fpu["replay"]
            assert isinstance(replay, dict)
            replay["instruction_effect_schedule"] = schedule
            _write_machine(machine, [row])

            with self.assertRaisesRegex(
                StageBInterpreterError, "final schedule targets differ"
            ) as raised:
                compile_stage_b_interpreter_program(machine)
            self.assertEqual(
                raised.exception.code, "malformed_x87_instruction_effect_schedule"
            )

    def test_branch_and_call_remain_ordinary_and_require_interleaving(self) -> None:
        for mnemonic, ordinary_bytes in (("je", "7400"), ("call", "e800000000")):
            with self.subTest(mnemonic=mnemonic), tempfile.TemporaryDirectory() as temporary:
                machine = Path(temporary) / "state-machine.jsonl"
                encoded = bytes.fromhex("d9e8" + ordinary_bytes)
                row = _replay_row(encoded=encoded)
                row["instructions"] = [
                    {
                        "rva": 0x1000,
                        "size": 2,
                        "bytes": "d9e8",
                        "mnemonic": "fld1",
                        "op_str": "",
                    },
                    {
                        "rva": 0x1002,
                        "size": len(bytes.fromhex(ordinary_bytes)),
                        "bytes": ordinary_bytes,
                        "mnemonic": mnemonic,
                        "op_str": "",
                    },
                ]
                fpu = row["fpu_state"]
                assert isinstance(fpu, dict)
                replay = fpu["replay"]
                assert isinstance(replay, dict)
                replay["instructions"] = [
                    {"rva": 0x1000, "size": 2, "bytes": "d9e8"},
                    {
                        "rva": 0x1002,
                        "size": len(bytes.fromhex(ordinary_bytes)),
                        "bytes": ordinary_bytes,
                    },
                ]
                _write_machine(machine, [row])

                with self.assertRaises(StageBInterpreterError) as raised:
                    compile_stage_b_interpreter_program(machine)

                self.assertEqual(
                    raised.exception.code, "x87_replay_interleaving_unavailable"
                )

    def test_runtime_callout_is_required_and_receives_typed_binding(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("native C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            package_dir = root / "package"
            _write_machine(machine, [_replay_row()])
            write_stage_b_interpreter_package(state_machine=machine, out=package_dir)
            harness = root / "replay-harness.c"
            harness.write_text(
                r'''
#include <string.h>
#include "state-machine-interpreter.h"

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

static stage_b_call_status checked_operation(
    stage_b_runtime *runtime, const stage_b_typed_x87_operation *program,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime;
  if (program->rva_start != 0x1000U || program->rva_end != 0x1002U ||
      program->source_size != 2U || strcmp(program->operation_identity,
        "1d432ce79277a7acd9723c0b1df3284238e4f9c190c05b1adc71be963cfeb130") != 0)
    return STAGE_B_CALL_UNIMPLEMENTED;
  *output = *input;
  output->x87_status = 0x1234U;
  return STAGE_B_CALL_OK;
}

int main(void) {
  stage_b_runtime runtime = {0};
  stage_b_machine_state state = {0};
  stage_b_step_result result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != STAGE_B_UNIMPLEMENTED) return 1;
  runtime.execute_typed_x87_operation = checked_operation;
  result = stage_b_interpreter_step(&runtime, &state, 0x1000U);
  if (result.kind != STAGE_B_FALLTHROUGH || result.target_rva != 0x1002U) return 2;
  return state.x87_status == 0x1234U ? 0 : 3;
}
''',
                encoding="ascii",
            )
            executable = root / "replay-harness"
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-I",
                    str(package_dir),
                    str(package_dir / "state-machine-interpreter.c"),
                    str(package_dir / "state-machine-program.c"),
                    str(harness),
                    "-lm",
                    "-o",
                    str(executable),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run([str(executable)], check=True, text=True, capture_output=True)

    def test_malformed_replay_digest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            row = _replay_row()
            fpu = row["fpu_state"]
            assert isinstance(fpu, dict)
            replay = fpu["replay"]
            assert isinstance(replay, dict)
            replay["bytes_sha256"] = "b" * 64
            _write_machine(machine, [row])

            with self.assertRaisesRegex(
                StageBInterpreterError, "bytes_sha256 does not match"
            ):
                compile_stage_b_interpreter_program(machine)

    def test_package_collects_sorted_actionable_replay_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            bad_sequence = _replay_row(
                identity="semantic-transfer:missing-interleaving",
                rva_start=0x3000,
                encoded=bytes.fromhex("d9e890"),
            )
            sequence = [
                {
                    "rva": 0x3000,
                    "size": 2,
                    "bytes": "d9e8",
                    "mnemonic": "fld1",
                    "op_str": "",
                },
                {
                    "rva": 0x3002,
                    "size": 1,
                    "bytes": "90",
                    "mnemonic": "nop",
                    "op_str": "",
                },
            ]
            bad_sequence["instructions"] = sequence
            sequence_fpu = bad_sequence["fpu_state"]
            assert isinstance(sequence_fpu, dict)
            sequence_replay = sequence_fpu["replay"]
            assert isinstance(sequence_replay, dict)
            sequence_replay["instructions"] = [
                {"rva": 0x3000, "size": 2, "bytes": "d9e8"},
                {"rva": 0x3002, "size": 1, "bytes": "90"},
            ]

            bad_digest = _replay_row(
                identity="semantic-transfer:bad-digest", rva_start=0x2000
            )
            digest_fpu = bad_digest["fpu_state"]
            assert isinstance(digest_fpu, dict)
            digest_replay = digest_fpu["replay"]
            assert isinstance(digest_replay, dict)
            digest_replay["bytes_sha256"] = "b" * 64
            valid = _replay_row(rva_start=0x1000)
            _write_machine(machine, [bad_sequence, valid, bad_digest])

            package = write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )
            second = write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package-second"
            )

            self.assertEqual(package["status"], "incomplete")
            self.assertEqual(package["blockers"], second["blockers"])
            self.assertEqual(package["counts"]["input_transfers"], 3)
            self.assertEqual(package["counts"]["transfers"], 1)
            self.assertEqual(package["counts"]["blocked_transfers"], 2)
            self.assertEqual(
                [blocker["rva_start"] for blocker in package["blockers"]],
                [0x2000, 0x3000],
            )
            self.assertEqual(
                [blocker["code"] for blocker in package["blockers"]],
                ["malformed_x87_replay", "x87_replay_interleaving_unavailable"],
            )
            self.assertIn(
                "instruction-ordered effect schedule",
                package["blockers"][1]["next_action"],
            )
            self.assertTrue(all(blocker["next_action"] for blocker in package["blockers"]))


if __name__ == "__main__":
    unittest.main()
