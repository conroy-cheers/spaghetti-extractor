from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.authority_inputs.finite_values import FiniteU32Dataflow
from spaghetti_extractor.reconstruction.ir import (
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
    PREPARED_MACHINE_IR_FORMAT,
    MachineIRExportError,
    RvaSpan,
    _Instruction,
    _assert_byte_free,
    _bounded_predecessor_instruction_history,
    _callback_root_proposals_from_provenance,
    _classify_executable_data_before_control,
    _exceptional_control_inventory,
    _local_callback_cutpoint_proposals,
    _newly_eligible_callback_roots,
    _recovery_failure_message,
    _recover_unknown_fallthrough,
    _sanitize_schedule,
    export_machine_ir_package,
    prepare_machine_ir_units_package,
)
from spaghetti_extractor.candidate.state_machine import (
    normalize_stage_a_semantic_transfer,
)
from spaghetti_extractor.pe32.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_bytes
from spaghetti_extractor.util import sha256_file

from tests.pe_fixtures import (
    pe32_image,
    pe32_image_with_pointer_slot,
    pe32_import_image,
    pe32_tls_image,
)


_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_X87_FIELDS = [
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


def _expr_register(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _row(
    identity: str,
    rva: int,
    encoded: bytes,
    *,
    outcome: dict[str, object],
    status: str = "reimplementable",
    external_events: list[dict[str, object]] | None = None,
    ordered_events: list[dict[str, object]] | None = None,
    faults: list[dict[str, object]] | None = None,
    register_writes: list[dict[str, object]] | None = None,
    memory_events: list[dict[str, object]] | None = None,
    edge_conditions: list[dict[str, object]] | None = None,
    fpu_state: dict[str, object] | None = None,
    control_disposition: dict[str, object] | None = None,
) -> dict[str, object]:
    mnemonic = {
        b"\x90": ("nop", ""),
        b"\xc3": ("ret", ""),
        b"\xc2\x0c\x00": ("ret", "0xc"),
        b"\xd9\x00": ("fld", "dword ptr [eax]"),
        b"\xeb\xfe": ("jmp", "0x401000"),
        b"\xff\xe0": ("jmp", "eax"),
        b"\xff\x24\x85\x10\x10\x40\x00": (
            "jmp",
            "dword ptr [eax*4 + 0x401010]",
        ),
        b"\xff\x15\x40\x20\x40\x00": ("call", "dword ptr [0x402040]"),
    }[encoded]
    transfer = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": identity,
        "function": "fixture_main",
        "block_id": identity.removeprefix("semantic-transfer:"),
        "unit_kind": "semantic_transfer",
        "status": status,
        "reachable": True,
        "original": {
            "rva_start": rva,
            "rva_end": rva + len(encoded),
            "size": len(encoded),
        },
        "instructions": [
            {
                "rva": rva,
                "size": len(encoded),
                "bytes": encoded.hex(),
                "mnemonic": mnemonic[0],
                "op_str": mnemonic[1],
            }
        ],
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "expression_model": "stage-a-semantic-ir-v1",
        "pre_state": {
            "registers": {name: _expr_register(name) for name in _REGISTERS},
            "flags": {name: {"op": "flag", "name": name} for name in _FLAGS},
            "memory": {
                "op": "memory",
                "name": "mem0",
                "address_width": 32,
                "value_width": 8,
            },
        },
        "register_writes": register_writes or [],
        "flag_writes": [],
        "memory_events": memory_events or [],
        "external_events": external_events or [],
        "faults": faults or [],
        "ordered_events": ordered_events or [],
        "edge_conditions": edge_conditions or [],
        "outcome": outcome,
        "stack_delta": {
            "status": "derived",
            "net_bytes": 0,
            "expression": _expr_register("esp"),
        },
        "fpu_state": fpu_state,
        "counts": {
            "register_writes": len(register_writes or []),
            "flag_writes": 0,
            "memory_events": len(memory_events or []),
            "external_events": len(external_events or []),
            "faults": len(faults or []),
            "ordered_events": len(ordered_events or []),
            "edge_conditions": len(edge_conditions or []),
        },
        "acceptance": "test semantic transfer",
        "blocker_category": None if status == "reimplementable" else "x87_typed_lowering_required",
        "blocker": None if status == "reimplementable" else "x87 replay has not yet been typed",
        "next_action": None if status == "reimplementable" else "consume the typed x87 micro-op",
    }
    if control_disposition is not None:
        transfer["control_disposition"] = control_disposition
    return normalize_stage_a_semantic_transfer(transfer)


def _x87_state(rva: int, encoded: bytes) -> dict[str, object]:
    digest = sha256_bytes(encoded)
    return {
        "model": "native_exact_x87_command_replay_obligation_v1",
        "status": "required",
        "authoritative_state_type": "StageA.X87.PhysicalState",
        "required_fields": list(_X87_FIELDS),
        "missing_or_invalid_fields": [
            "tags",
            "pending_exception",
            "last_opcode",
            "instruction_pointer",
            "code_selector",
            "data_pointer",
            "data_selector",
        ],
        "logical_state_guidance": {
            "stack": [{"op": "fpu_reg", "args": [index]} for index in range(8)],
            "control": {"op": "fpu_control", "args": []},
            "status": {"op": "fpu_status", "args": []},
        },
        "replay": {
            "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
            "checked_decoder": "StageA.Formal.decodeInstructionExact",
            "checked_executor": "StageA.Formal.executeInstruction",
            "architecture": "x86",
            "bitness": 32,
            "image_base": 0x400000,
            "rva_start": rva,
            "rva_end": rva + len(encoded),
            "bytes": encoded.hex(),
            "bytes_sha256": digest,
            "instructions": [
                {"rva": rva, "size": len(encoded), "bytes": encoded.hex()}
            ],
        },
    }


def _write_machine(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _write_reference_contract(path: Path, original: Path) -> None:
    original_digest = sha256_file(original)
    payload = {
        "format": "stage-a-reference-contract-v1",
        "generator": "stage-a-export-reference-contract",
        "generated_at": "1970-01-01T00:00:00+00:00",
        "model": "x86-pe32-env-v1",
        "status": "pass",
        "tool_versions": {},
        "inputs": {
            "original": {"path": original.name, "sha256": original_digest, "exists": True},
            "candidate": None,
            "mapping": None,
            "layout_contract": None,
        },
        "original": {
            "sha256": original_digest,
            "machine": "i386",
            "bitness": 32,
        },
        "candidate": None,
        "constraints": {
            "executable_byte_coverage": {
                "status": "satisfied",
                "original": {
                    "mapped_code_ranges": [
                        {"rva_start": 0x1000, "rva_end": 0x1001, "size": 1}
                    ],
                    "waived_noncode_ranges": [],
                    "gaps": [],
                },
            },
            "function_ranges": {"status": "satisfied", "functions": []},
            "basic_blocks_and_cfg": {"status": "satisfied", "basic_blocks": []},
            "roots_and_jump_tables": {
                "status": "satisfied",
                "roots": [{"kind": "entry", "block_id": "return"}],
                "jump_table_targets": [],
            },
            "import_thunks": {"status": "not_applicable", "mapped_import_thunks": []},
        },
        "families": {},
        "coverage": {},
        "assumptions": [],
        "issues": [],
        "counts": {},
        "sidecars": {
            "unit_contracts": {
                "directory": ".",
                "semantic_transfer_contracts": {"path": "semantic-transfers.jsonl"},
            }
        },
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _raw_instruction_keys(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {
                "bytes",
                "instruction_bytes",
                "opcode_bytes",
                "raw_bytes",
                "encoded_instruction",
            }:
                result.add(key)
            result.update(_raw_instruction_keys(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_raw_instruction_keys(item))
    return result


__all__ = tuple(name for name in globals() if not name.startswith("__"))
