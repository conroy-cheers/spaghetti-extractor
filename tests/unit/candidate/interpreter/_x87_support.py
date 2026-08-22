from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from spaghetti_extractor.candidate.interpreter import (
    CandidateInterpreterError,
    compile_spx_interpreter_program,
)
from tests.unit.candidate.interpreter._support import (
    compile_spx_interpreter_machine_ir,
    write_spx_interpreter_package,
)
from spaghetti_extractor.candidate.x87 import (
    typed_x87_operation_from_micro_op,
    typed_x87_operation_from_payload,
)
from spaghetti_extractor.errors import ToolkitInputError
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
        "status": "reimplementable",
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
            "authoritative_state_type": "SpaghettiExtractor.ISA.X87.PhysicalState",
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
                "format": "spaghetti-extractor-native-exact-x87-command-replay-obligation-v1",
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
        "format": "spaghetti-extractor-machine-ir-v3",
        "record_kind": "unit",
        "id": "semantic-transfer:x87-replay",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
            "contract_sha256": _CONTRACT_SHA,
            "instruction_bytes_sha256": digest,
        },
        "x87_micro_ops": [{
            "format": "spaghetti-extractor-x87-micro-op-v1",
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
            "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
            "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                    "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                    "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
        "format": "spaghetti-extractor-static-instruction-effects-v1",
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
                    "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                    "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                    "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                    "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
            "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
            if is_x87
            else "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
        )
        executor = (
            "SpaghettiExtractor.ISA.Formal.executeInstruction"
            if is_x87
            else "SpaghettiExtractor.ISA.Formal.executeInstruction"
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
        "format": "spaghetti-extractor-static-instruction-effects-v1",
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


__all__ = tuple(name for name in globals() if not name.startswith("__"))
