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
    compile_stage_b_interpreter_program,
    write_stage_b_interpreter_package,
)
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
    def test_exact_singleton_lowers_to_immutable_native_replay_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "state-machine.jsonl"
            _write_machine(machine, [_replay_row()])

            transfer = compile_stage_b_interpreter_program(machine)[0]
            replay = transfer.x87_replays[0]

            self.assertEqual([action.op for action in transfer.actions], [
                "replay_x87",
                "outcome_fallthrough",
            ])
            self.assertEqual(transfer.nodes, ())
            self.assertEqual(transfer.x87_nodes, ())
            self.assertEqual(replay.instruction_bytes, bytes.fromhex("d9e8"))
            self.assertEqual(replay.rva_start, 0x1000)
            self.assertEqual(replay.rva_end, 0x1002)
            self.assertEqual(replay.contract_sha256, _CONTRACT_SHA)
            with self.assertRaises(FrozenInstanceError):
                replay.rva_start = 0x2000  # type: ignore[misc]

            package = write_stage_b_interpreter_package(
                state_machine=machine, out=root / "package"
            )
            program = json.loads(
                (root / "package/state-machine-interpreter-program.json").read_text(
                    encoding="utf-8"
                )
            )
            replay_record = program["transfers"][0]["x87_replays"][0]
            self.assertEqual(package["status"], "ready")
            self.assertEqual(replay_record["instruction_bytes"], "d9e8")
            self.assertEqual(
                replay_record["instruction_bytes_sha256"], sha256_bytes(bytes.fromhex("d9e8"))
            )
            self.assertEqual(
                replay_record["transfer_instruction_bytes_sha256"],
                sha256_bytes(bytes.fromhex("d9e8")),
            )
            self.assertTrue(set(_REQUIRED_PHYSICAL_FIELDS).isdisjoint(replay_record))
            runtime_header = (
                root / "package/state-machine-runtime.h"
            ).read_text(encoding="ascii")
            program_source = (
                root / "package/state-machine-program.c"
            ).read_text(encoding="ascii")
            interpreter_source = (
                root / "package/state-machine-interpreter.c"
            ).read_text(encoding="ascii")
            self.assertIn("stage_b_x87_replay_handler", runtime_header)
            self.assertIn("replay_checked_x87_command", runtime_header)
            self.assertIn("static const stage_b_x87_replay_program", program_source)
            self.assertIn("0xd9U,0xe8U", program_source)
            self.assertIn("{ 25U, 1U, 0U, {0U,0U,0U,0U,0U} }", program_source)
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
                ["replay_x87", "replay_x87", "outcome_fallthrough"],
            )
            self.assertEqual([action.args for action in transfer.actions[:2]], [(0,), (1,)])
            self.assertEqual(
                [(item.rva_start, item.rva_end) for item in transfer.x87_replays],
                [(0x1000, 0x1002), (0x1002, 0x1004)],
            )
            self.assertEqual(
                [item.instruction_bytes_sha256 for item in transfer.x87_replays],
                [sha256_bytes(bytes.fromhex("d9e8")), sha256_bytes(bytes.fromhex("ddd8"))],
            )
            self.assertTrue(
                all(
                    item.transfer_instruction_bytes_sha256 == sha256_bytes(encoded)
                    for item in transfer.x87_replays
                )
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
                if action.op == "replay_x87"
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

static stage_b_call_status checked_replay(
    stage_b_runtime *runtime, const stage_b_x87_replay_program *program,
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
  runtime.replay_checked_x87_command = checked_replay;
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

    def test_runtime_callout_is_required_and_receives_exact_binding(self) -> None:
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

static stage_b_call_status checked_replay(
    stage_b_runtime *runtime, const stage_b_x87_replay_program *program,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime;
  if (program->rva_start != 0x1000U || program->rva_end != 0x1002U ||
      program->instruction_count != 1U || program->byte_count != 2U ||
      program->instruction_bytes[0] != 0xd9U || program->instruction_bytes[1] != 0xe8U ||
      strcmp(program->instruction_bytes_sha256,
        "852df74fff31b328b40e1bb1b4ad5d8baba06f81bef9371e7f0ddb597d97e8b4") != 0)
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
  runtime.replay_checked_x87_command = checked_replay;
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
