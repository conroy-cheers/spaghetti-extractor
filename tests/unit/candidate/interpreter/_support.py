from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate.interpreter import (
    SPX_INTERPRETER_DEFINEDNESS_USE_FORMAT,
    CandidateInterpreterError,
    compile_spx_interpreter_machine_ir,
    compile_spx_interpreter_program,
    write_fallback_capability_analysis,
    write_spx_interpreter_package as _write_spx_interpreter_package,
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


def _test_machine_ir_unit(row: dict[str, object]) -> dict[str, object]:
    if row.get("format") == "spaghetti-extractor-machine-ir-v2":
        return row
    original = dict(row.get("original", {}))
    semantics = {
        name: row.get(name)
        for name in (
            "pre_state",
            "register_writes",
            "flag_writes",
            "memory_events",
            "external_events",
            "faults",
            "ordered_events",
            "edge_conditions",
            "outcome",
            "stack_delta",
            "counts",
            "fpu_state",
            "instruction_effect_schedule",
        )
    }
    return {
        "format": "spaghetti-extractor-machine-ir-v2",
        "record_kind": "unit",
        "id": row["id"],
        "status": "incomplete" if row.get("status") == "incomplete" else "qualified",
        "reachable": row.get("reachable", True),
        "source": {
            "original": original,
            "contract_sha256": row.get("contract_sha256", _SHA_A),
            "instruction_bytes_sha256": row.get(
                "instruction_bytes_sha256", _SHA_B
            ),
            "semantic_export": None,
        },
        "instructions": _without_raw_instruction_material(
            row.get("instructions", [])
        ),
        "x87_micro_ops": row.get("x87_micro_ops", []),
        "semantics": semantics,
    }


def _without_raw_instruction_material(value):
    forbidden = {
        "bytes",
        "instruction_bytes",
        "opcode_bytes",
        "raw_bytes",
        "encoded_instruction",
    }
    if isinstance(value, dict):
        return {
            key: _without_raw_instruction_material(item)
            for key, item in value.items()
            if key not in forbidden
        }
    if isinstance(value, list):
        return [_without_raw_instruction_material(item) for item in value]
    return value


def write_spx_interpreter_package(*, machine_ir: Path, out: Path):
    rows = [
        json.loads(line)
        for line in Path(machine_ir).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if all(row.get("format") == "spaghetti-extractor-machine-ir-v2" for row in rows):
        strict_input = Path(machine_ir)
    else:
        strict_input = Path(machine_ir).with_name(
            f"{Path(machine_ir).stem}-strict.jsonl"
        )
        _write_machine(
            strict_input,
            [_test_machine_ir_unit(row) for row in rows],
        )
    return _write_spx_interpreter_package(machine_ir=strict_input, out=out)


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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
        "format": "spaghetti-extractor-machine-ir-v2",
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
                "format": "spaghetti-extractor-static-instruction-effects-v1",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
        "format": "spaghetti-extractor-machine-ir-v2",
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
                "format": "spaghetti-extractor-static-instruction-effects-v1",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
                "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
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
        "format": "spaghetti-extractor-machine-ir-v2",
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
                "format": "spaghetti-extractor-static-instruction-effects-v1",
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


__all__ = tuple(name for name in globals() if not name.startswith("__"))
