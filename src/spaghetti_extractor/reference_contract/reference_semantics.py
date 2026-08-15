"""Reference-contract generation, sidecars, and obligation diagnostics."""

from __future__ import annotations

import copy
import json
import os
import platform
import re
import shutil
import sys
from bisect import bisect_left
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Iterable

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

from ..pe32.stage_binary import (
    BlockSide,
    StageABinary,
    StageAImport,
    StageAInputError,
    StageASection,
    _artifact_name,
    _executable_section_for_rva,
    _parse_linker_map_functions,
    _parse_linker_map_symbol_line,
    _parse_stage_a_pe,
    _section_for_rva,
)
from ..extraction.cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    NonCodeWaiver,
    REFERENCE_CONTRACT_MODEL_ID,
    _incomplete_record,
    _mapping_source,
    _range_report,
)
from ..static_program.model import StaticUnitContext

from .map_analysis import (
    _capstone_mode,
    _generated_map_issues,
    _import_signature,
    _layout_issues,
    _section_compatibility_signature,
    _section_permission_signature,
    _section_rva_start_signature,
)
from .map_analysis import (
    _direct_cfg_edges,
    _gaps,
    _instruction_report,
)
from .map_verification import (
    _parse_block_map,
    _verify_waiver_side,
    _waiver_obligations,
)

from .abi import (
    _abi_function_evidence,
)
from .abi_arguments import (
    _abi_import_prototypes,
)
from .abi_clusters import (
    _abi_cluster_contracts,
    _abi_evidence_by_block,
    _abi_evidence_by_function,
    _abi_functions,
    _cluster_contract,
)
from .abi_comparison import (
    _contract_candidate_abi_coverage_gaps,
)
from .abi_profile import (
    _stage_a_abi_profile_comparison_gaps,
)
from .abi_support import (
    _block_id_for_instruction,
    _contract_constraint,
    _count_by,
    _safe_gap_part,
    _safe_int,
)

from .symbolic_execution import (
    _import_z3,
    _symbolic_execute,
    _symbolic_incomplete,
)
from .symbolic_expressions import (
    _expr_json,
)

def _semantic_transfer_contracts(
    binary: StageABinary,
    mappings: list[StaticUnitContext],
    contract_ref: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for mapped in mappings:
        if mapped.kind != "code":
            continue
        source = _mapping_source(mapped)
        function_name = source.get("function") if isinstance(source.get("function"), str) and source.get("function") else mapped.id
        spans = semantic_cutpoint_spans_for_side(
            binary,
            {
                "rva_start": mapped.original.rva_start,
                "rva_end": mapped.original.rva_end,
                "size": mapped.original.size,
            },
            mapped.id,
            periodic=False,
        )
        for cut_index, span in enumerate(spans):
            split = len(spans) > 1
            block_id = (
                f"{mapped.id}~semantic-{cut_index:04d}"
                if split
                else mapped.id
            )
            row = _semantic_transfer_contract(
                binary,
                mapped,
                function_name,
                contract_ref,
                semantic_side=BlockSide(
                    span["rva_start"],
                    span["rva_end"],
                ),
                semantic_block_id=block_id,
            )
            if split:
                row["semantic_cutpoint"] = {
                    "index": cut_index,
                    "parent_block_id": mapped.id,
                    "policy": "formal_stopping_instruction_v1",
                }
            rows.append(row)
    return sorted(rows, key=lambda item: (str(item.get("function") or ""), str(item.get("block_id") or "")))

def _semantic_transfer_contract(
    binary: StageABinary,
    mapped: StaticUnitContext,
    function_name: str,
    contract_ref: dict[str, Any],
    *,
    semantic_side: BlockSide | None = None,
    semantic_block_id: str | None = None,
) -> dict[str, Any]:
    side = semantic_side or mapped.original
    block_id = semantic_block_id or mapped.id
    data = binary.pe.get_data(side.rva_start, side.size)
    instructions = _semantic_disassemble_block(binary, side, data)
    base_row: dict[str, Any] = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": f"semantic-transfer:{_safe_gap_part(block_id)}",
        "unit_kind": "semantic_transfer",
        "expression_model": "stage-a-semantic-ir-v1",
        "status": "incomplete",
        "reference_contract": contract_ref,
        "function": function_name or None,
        "block_id": block_id,
        "reachable": True,
        "original": _range_report(side),
        "instruction_bytes_sha256": sha256_bytes(data),
        "instructions": instructions,
        "pre_state": _semantic_pre_state(binary),
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "outcome": {"kind": "unknown"},
        "stack_delta": None,
        "fpu_state": None,
        "counts": {
            "register_writes": 0,
            "flag_writes": 0,
            "memory_events": 0,
            "external_events": 0,
            "faults": 0,
            "ordered_events": 0,
            "edge_conditions": 0,
        },
        "acceptance": "guidance contract only; candidate static and behavioral validation remain required",
    }
    if len(data) != side.size:
        return {
            **base_row,
            "blocker_category": "unreadable_block_bytes",
            "blocker": f"expected {side.size} block bytes, read {len(data)}",
            "next_action": "fix block range or PE section mapping before generating a semantic transfer contract",
        }
    # The ordered schedule is the checked per-instruction authority consumed by
    # the hybrid completeness gate.  Emit it for singleton transfers as well as
    # larger regions so a qualified row can never rely on aggregate semantics
    # without an exact instruction replay ledger.
    instruction_effect_schedule, symbolic = _semantic_instruction_effect_schedule(
        binary,
        side,
        data,
        instructions,
        mapped,
    )
    if symbolic.get("status") != "ok":
        instruction = symbolic.get("instruction") if isinstance(symbolic.get("instruction"), dict) else None
        blocked = {
            **base_row,
            "blocker_category": symbolic.get("category") or "unsupported_semantics",
            "blocker": symbolic.get("blocker") or "block is outside the current semantic transfer model",
            "next_action": symbolic.get("next_action") or "add instruction semantics or a checked cluster summary",
            "blocking_instruction": instruction,
        }
        if instruction_effect_schedule is not None:
            blocked["instruction_effect_schedule"] = instruction_effect_schedule
        return blocked
    observables = symbolic.get("observables") if isinstance(symbolic.get("observables"), dict) else {}
    native_exact_command_replay = None
    if (
        instruction_effect_schedule is not None
        and _semantic_transfer_inventory_contains_x87(instructions)
    ):
        native_exact_command_replay = _semantic_x87_replay_binding(
            binary,
            side,
            data,
            instructions,
            instruction_effect_schedule=instruction_effect_schedule,
        )
    effects = _semantic_effects_from_observables(
        observables,
        ordered_events=symbolic.get("ordered_events"),
        native_exact_command_replay=native_exact_command_replay,
    )
    fpu_state = effects.get("fpu_state")
    if (
        isinstance(fpu_state, dict)
        and fpu_state.get("model") == _X87_REPLAY_OBLIGATION_MODEL
    ):
        return {
            **base_row,
            "blocker_category": "x87_physical_state_requires_native_exact_command_replay",
            "blocker": (
                "legacy symbolic x87 observables do not contain the physical "
                "StageA.X87.PhysicalState required by Stage B"
            ),
            "next_action": (
                "replay each exact x87 singleton with the checked Lean decoder and "
                "executor according to the instruction effect schedule, then export "
                "every physical state field"
            ),
            "instruction_effect_schedule": instruction_effect_schedule,
            **effects,
        }
    result = {
        **base_row,
        "status": "reimplementable",
        "blocker_category": None,
        "blocker": None,
        "next_action": "implement this block so the compiled candidate reproduces the transfer contract, then rerun Stage A",
        **effects,
    }
    if instruction_effect_schedule is not None:
        result["instruction_effect_schedule"] = instruction_effect_schedule
    return result

def _semantic_disassemble_block(binary: StageABinary, side: BlockSide, data: bytes) -> list[dict[str, Any]]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    return [_instruction_report(binary, insn) for insn in dis.disasm(data, binary.image_base + side.rva_start)]

def _semantic_pre_state(binary: StageABinary) -> dict[str, Any]:
    registers = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp") if binary.bitness == 32 else ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp")
    flags = ("cf", "zf", "sf", "of", "pf", "df")
    return {
        "registers": {name: _semantic_expr_json(("reg", name)) for name in registers},
        "flags": {name: _semantic_expr_json(("flag", name)) for name in flags},
        "memory": {"op": "memory", "name": "mem0", "address_width": binary.bitness, "value_width": 8},
    }

def _semantic_effects_from_observables(
    observables: dict[str, Any],
    *,
    ordered_events: Any = None,
    native_exact_command_replay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    register_writes = []
    flag_writes = []
    for key, value in sorted(observables.items()):
        if key.startswith("reg:"):
            name = key.split(":", 1)[1]
            if value != ("reg", name):
                register_writes.append({"register": name, "value": _semantic_expr_json(value)})
        elif key.startswith("flag:"):
            name = key.split(":", 1)[1]
            if value != ("flag", name):
                flag_writes.append({"flag": name, "value": _semantic_expr_json(value)})
    memory_events = [_semantic_memory_event_json(event) for event in observables.get("memory_events", [])]
    external_events = [_semantic_external_event_json(event) for event in observables.get("external_events", [])]
    faults = [_semantic_fault_json(fault) for fault in observables.get("fault_conditions", [])]
    ordered = [
        _semantic_ordered_event_json(event)
        for event in (ordered_events if isinstance(ordered_events, (list, tuple)) else ())
    ]
    outcome = _semantic_outcome_json(observables.get("outcome"))
    return {
        "register_writes": register_writes,
        "flag_writes": flag_writes,
        "memory_events": memory_events,
        "external_events": external_events,
        "faults": faults,
        "ordered_events": ordered,
        "fpu_state": _semantic_fpu_state_from_observables(
            observables,
            native_exact_command_replay=native_exact_command_replay,
        ),
        "edge_conditions": _semantic_edge_conditions(outcome),
        "outcome": outcome,
        "stack_delta": _semantic_stack_delta_from_observables(observables),
        "counts": {
            "register_writes": len(register_writes),
            "flag_writes": len(flag_writes),
            "memory_events": len(memory_events),
            "external_events": len(external_events),
            "faults": len(faults),
            "ordered_events": len(ordered),
            "edge_conditions": len(_semantic_edge_conditions(outcome)),
        },
    }

def _semantic_ordered_event_json(event: Any) -> dict[str, Any]:
    if not isinstance(event, tuple) or len(event) != 3:
        return {"kind": "unknown", "raw": _expr_json(event)}
    family, instruction_rva, payload = event
    if family == "memory":
        result = _semantic_memory_event_json(payload)
    elif family == "external":
        result = _semantic_external_event_json(payload)
    elif family == "fault":
        result = _semantic_fault_json(payload)
    else:
        result = {"kind": "unknown", "raw": _expr_json(payload)}
    return {"family": str(family), "instruction_rva": int(instruction_rva), **result}

_X87_PHYSICAL_OBSERVABLE_FIELDS = (
    ("stack", "fpu_stack"),
    ("tags", "fpu_tags"),
    ("control", "fpu_control"),
    ("status", "fpu_status"),
    ("pending_exception", "fpu_pending_exception"),
    ("last_opcode", "fpu_last_opcode"),
    ("instruction_pointer", "fpu_instruction_pointer"),
    ("code_selector", "fpu_code_selector"),
    ("data_pointer", "fpu_data_pointer"),
    ("data_selector", "fpu_data_selector"),
)

_X87_REPLAY_OBLIGATION_MODEL = "native_exact_x87_command_replay_obligation_v1"

_X87_SINGLETON_CHECKED_DECODER = "StageA.Formal.decodeInstructionExact"

_X87_SINGLETON_CHECKED_EXECUTOR = "StageA.Formal.executeInstruction"

_ORDINARY_CHECKED_DECODER = "StageA.Formal.decodeInstructionExact"

_ORDINARY_CHECKED_EXECUTOR = "StageA.Formal.executeInstruction"

_SEMANTIC_X87_SINGLETON_MNEMONICS = frozenset(
    {
        "wait",
        "fld",
        "fld1",
        "fldz",
        "fild",
        "fst",
        "fstp",
        "fist",
        "fistp",
        "fisttp",
        "fadd",
        "faddp",
        "fsub",
        "fsubp",
        "fsubr",
        "fsubrp",
        "fiadd",
        "fimul",
        "fisub",
        "fisubr",
        "fidiv",
        "fidivr",
        "fmul",
        "fmulp",
        "fdiv",
        "fdivp",
        "fdivr",
        "fdivrp",
        "fxch",
        "fchs",
        "fxam",
        "fnstcw",
        "fldcw",
        "fnstsw",
        "fcom",
        "fcomp",
        "ficom",
        "ficomp",
        "fcomi",
        "fcomip",
        "fucomi",
        "fucomip",
        "fcompi",
        "fucompi",
        "fsin",
        "fcos",
        "fclex",
        "fnclex",
        "fninit",
    }
)

def _semantic_fpu_state_from_observables(
    observables: dict[str, Any],
    *,
    native_exact_command_replay: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    present = {
        output_name: observables[input_name]
        for output_name, input_name in _X87_PHYSICAL_OBSERVABLE_FIELDS
        if input_name in observables
    }
    if not present and native_exact_command_replay is None:
        return None

    converted = {
        name: (
            [_semantic_expr_json(item) for item in value]
            if name in {"stack", "tags"} and isinstance(value, (list, tuple))
            else _semantic_expr_json(value)
        )
        for name, value in present.items()
    }
    missing_or_invalid = [
        output_name
        for output_name, _input_name in _X87_PHYSICAL_OBSERVABLE_FIELDS
        if not _semantic_x87_physical_field_valid(output_name, converted.get(output_name))
    ]
    if not missing_or_invalid:
        return {
            "model": "symbolic_x87_stack_v1",
            **converted,
        }

    logical_guidance = {
        name: converted[name]
        for name in ("stack", "control", "status")
        if name in converted
    }
    return {
        "model": _X87_REPLAY_OBLIGATION_MODEL,
        "status": "required",
        "authoritative_state_type": "StageA.X87.PhysicalState",
        "required_fields": [
            output_name for output_name, _input_name in _X87_PHYSICAL_OBSERVABLE_FIELDS
        ],
        "missing_or_invalid_fields": missing_or_invalid,
        "logical_state_guidance": logical_guidance,
        "replay": {
            "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
            "checked_decoder": _X87_SINGLETON_CHECKED_DECODER,
            "checked_decoder_scope": "each_x87_singleton_instruction",
            "checked_executor": _X87_SINGLETON_CHECKED_EXECUTOR,
            "checked_executor_scope": "each_x87_singleton_instruction",
            **(native_exact_command_replay or {}),
        },
    }

def _semantic_x87_physical_field_valid(name: str, value: Any) -> bool:
    if name in {"stack", "tags"}:
        return (
            isinstance(value, list)
            and len(value) == 8
            and all(_semantic_x87_expression_valid(item) for item in value)
        )
    return _semantic_x87_expression_valid(value)

def _semantic_x87_expression_valid(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("op"), str)

def _semantic_x87_replay_binding(
    binary: StageABinary,
    side: BlockSide,
    data: bytes,
    instructions: list[dict[str, Any]],
    *,
    instruction_effect_schedule: dict[str, Any],
) -> dict[str, Any]:
    return {
        "architecture": "x86",
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "rva_start": side.rva_start,
        "rva_end": side.rva_end,
        "bytes": data.hex(),
        "bytes_sha256": sha256_bytes(data),
        "instruction_effect_schedule": instruction_effect_schedule,
        "instructions": [
            {
                key: instruction[key]
                for key in ("rva", "size", "bytes")
                if key in instruction
            }
            for instruction in instructions
        ],
    }

def _semantic_transfer_inventory_contains_x87(
    instructions: list[dict[str, Any]],
) -> bool:
    return any(
        str(instruction.get("mnemonic") or "").lower()
        in _SEMANTIC_X87_SINGLETON_MNEMONICS
        for instruction in instructions
        if isinstance(instruction, dict)
    )

def _semantic_instruction_effect_schedule(
    binary: StageABinary,
    side: BlockSide,
    data: bytes,
    instructions: list[dict[str, Any]],
    mapped: StaticUnitContext,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Propose an exact-byte instruction ledger for checked Lean replay.

    Capstone reports are inventory hints only.  Every classification remains bound
    to exact PE bytes and names the Lean decoder/executor that must replay it.  The
    ledger is also the Stage B authority for ordering effects across instructions;
    aggregate final-state expressions cannot recover that ordering around calls.
    """

    transfer_digest = sha256_bytes(data)
    records: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    expected_rva = side.rva_start
    external_call_index = 0
    final_symbolic: dict[str, Any] = {
        "status": "incomplete",
        "category": "x87_instruction_effect_schedule_incomplete",
        "blocker": "x87 instruction effect schedule contains no instructions",
        "next_action": "export at least one exact decoded instruction",
    }

    for index, instruction in enumerate(instructions):
        instruction_rva = instruction.get("rva")
        instruction_size = instruction.get("size")
        instruction_hex = instruction.get("bytes")
        mnemonic = str(instruction.get("mnemonic") or "").lower()
        if (
            not isinstance(instruction_rva, int)
            or not isinstance(instruction_size, int)
            or instruction_size <= 0
            or not isinstance(instruction_hex, str)
        ):
            blocker_rva = instruction_rva if isinstance(instruction_rva, int) else expected_rva
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                blocker_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "decoded instruction inventory lacks exact RVA, size, or bytes",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break
        try:
            instruction_bytes = bytes.fromhex(instruction_hex)
        except ValueError:
            instruction_bytes = b""
        if (
            instruction_rva != expected_rva
            or len(instruction_bytes) != instruction_size
            or data[
                instruction_rva - side.rva_start :
                instruction_rva - side.rva_start + instruction_size
            ]
            != instruction_bytes
        ):
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                instruction_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "decoded instruction inventory does not reconstruct the exact PE span",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break

        instruction_end = instruction_rva + instruction_size
        instruction_side = BlockSide(instruction_rva, instruction_end)
        instruction_mapping = StaticUnitContext(
            id=f"{mapped.id}~instruction-{index}",
            original=instruction_side,
            kind=mapped.kind,
            invariant_checked=mapped.invariant_checked,
            source=mapped.source,
        )
        instruction_symbolic = _symbolic_execute(
            binary,
            instruction_side,
            instruction_bytes,
            "original",
            instruction_mapping,
            external_call_index_base=external_call_index,
        )
        if instruction_symbolic.get("status") != "ok":
            final_symbolic = instruction_symbolic
            blockers.append(
                _semantic_instruction_effect_blocker(
                    index, instruction, instruction_symbolic
                )
            )
            break

        current_observables = instruction_symbolic.get("observables")
        current_ordered_events = instruction_symbolic.get("ordered_events")
        if not isinstance(current_observables, dict) or not isinstance(
            current_ordered_events, tuple
        ):
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                instruction_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "symbolic instruction prefix did not emit structured observables",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break

        local_pre_state = _semantic_initial_instruction_observables(instruction_rva)
        effects = _semantic_instruction_effect_delta(
            local_pre_state,
            current_observables,
            (),
            current_ordered_events,
        )
        if effects is None:
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                instruction_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "symbolic prefix effects are not a stable extension of the prior instruction",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break

        instruction_class = (
            "x87_singleton_checked_replay"
            if mnemonic in _SEMANTIC_X87_SINGLETON_MNEMONICS
            else "ordinary_symbolic_instruction"
        )
        checked_decoder = (
            _X87_SINGLETON_CHECKED_DECODER
            if instruction_class == "x87_singleton_checked_replay"
            else _ORDINARY_CHECKED_DECODER
        )
        checked_executor = (
            _X87_SINGLETON_CHECKED_EXECUTOR
            if instruction_class == "x87_singleton_checked_replay"
            else _ORDINARY_CHECKED_EXECUTOR
        )
        record: dict[str, Any] = {
            "index": index,
            "rva_start": instruction_rva,
            "rva_end": instruction_end,
            "bytes": instruction_bytes.hex(),
            "bytes_sha256": sha256_bytes(instruction_bytes),
            "transfer_bytes_sha256": transfer_digest,
            "instruction_class": instruction_class,
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "source": "normalized_symbolic_equivalence_v1",
                "proof_authority": False,
                "mnemonic_guidance": mnemonic,
                "operand_guidance": str(instruction.get("op_str") or ""),
                "checked_decoder": checked_decoder,
                "checked_executor": checked_executor,
            },
            "symbolic_pre_state_sha256": _semantic_json_sha256(local_pre_state),
            "symbolic_post_state_sha256": _semantic_json_sha256(current_observables),
            "effects": effects,
        }
        if instruction_class == "x87_singleton_checked_replay":
            record["x87_singleton_replay"] = {
                "rva_start": instruction_rva,
                "rva_end": instruction_end,
                "bytes": instruction_bytes.hex(),
                "bytes_sha256": sha256_bytes(instruction_bytes),
                "checked_decoder": _X87_SINGLETON_CHECKED_DECODER,
                "checked_executor": _X87_SINGLETON_CHECKED_EXECUTOR,
                "physical_state_effect": (
                    "produced_by_checked_executor_not_inferred_by_exporter"
                ),
            }
        record["record_sha256"] = _semantic_json_sha256(record)
        records.append(record)
        external_call_index += len(current_observables.get("external_events", ()))
        expected_rva = instruction_end

    if not blockers and expected_rva != side.rva_end:
        final_symbolic = _symbolic_incomplete(
            "original",
            "x87_instruction_effect_schedule_incomplete",
            expected_rva,
            "<decode>",
            "",
            "decoded instruction inventory does not cover the complete transfer span",
        )
        blockers.append(
            _semantic_instruction_effect_blocker(len(records), {}, final_symbolic)
        )

    if not blockers:
        final_symbolic = _symbolic_execute(
            binary,
            side,
            data,
            "original",
            mapped,
        )
        if final_symbolic.get("status") != "ok":
            blockers.append(
                _semantic_instruction_effect_blocker(
                    len(records), instructions[-1] if instructions else {}, final_symbolic
                )
            )

    schedule: dict[str, Any] = {
        "format": "stage-a-instruction-ordered-effect-schedule-v1",
        "status": "complete" if not blockers else "incomplete",
        "proof_authority": False,
        "ordering": "strict_contiguous_rva_order",
        "rva_start": side.rva_start,
        "rva_end": side.rva_end,
        "transfer_bytes_sha256": transfer_digest,
        "records": records,
        "blockers": blockers,
        "counts": {
            "instructions": len(records),
            "x87_singletons": sum(
                record.get("instruction_class") == "x87_singleton_checked_replay"
                for record in records
            ),
            "ordinary_instructions": sum(
                record.get("instruction_class") == "ordinary_symbolic_instruction"
                for record in records
            ),
            "blockers": len(blockers),
        },
    }
    schedule["schedule_sha256"] = _semantic_json_sha256(schedule)
    return schedule, final_symbolic

_semantic_x87_instruction_effect_schedule = _semantic_instruction_effect_schedule

def _semantic_initial_instruction_observables(rva: int) -> dict[str, Any]:
    observables = {
        f"reg:{name}": ("reg", name)
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    observables.update(
        {
            f"flag:{name}": ("flag", name)
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        }
    )
    observables.update(
        {
            "outcome": ("fallthrough", rva),
            "memory_events": (),
            "external_events": (),
            "fault_conditions": (),
        }
    )
    return observables

def _semantic_instruction_effect_delta(
    previous: dict[str, Any],
    current: dict[str, Any],
    previous_ordered: tuple[Any, ...],
    current_ordered: tuple[Any, ...],
) -> dict[str, Any] | None:
    sequence_names = ("memory_events", "external_events", "fault_conditions")
    deltas: dict[str, tuple[Any, ...]] = {}
    for name in sequence_names:
        before = previous.get(name, ())
        after = current.get(name, ())
        if (
            not isinstance(before, tuple)
            or not isinstance(after, tuple)
            or after[: len(before)] != before
        ):
            return None
        deltas[name] = after[len(before) :]
    if current_ordered[: len(previous_ordered)] != previous_ordered:
        return None

    register_writes = []
    defined_flag_writes = []
    undefined_flags = []
    undefined_flag_writes = []
    for key, value in sorted(current.items()):
        if key.startswith("reg:") and previous.get(key) != value:
            register_writes.append(
                {"register": key.split(":", 1)[1], "value": _semantic_expr_json(value)}
            )
        elif key.startswith("flag:") and previous.get(key) != value:
            name = key.split(":", 1)[1]
            converted = _semantic_expr_json(value)
            if _semantic_json_contains_op(converted, "undefined_flag"):
                undefined_flags.append(name)
                undefined_flag_writes.append({"flag": name, "value": converted})
            else:
                defined_flag_writes.append({"flag": name, "value": converted})

    memory_events = [
        _semantic_memory_event_json(event) for event in deltas["memory_events"]
    ]
    call_effects = [
        _semantic_external_event_json(event) for event in deltas["external_events"]
    ]
    faults = [_semantic_fault_json(event) for event in deltas["fault_conditions"]]
    ordered_events = [
        _semantic_ordered_event_json(event)
        for event in current_ordered[len(previous_ordered) :]
    ]
    result = {
        "register_writes": register_writes,
        "defined_flag_writes": defined_flag_writes,
        "undefined_flags": undefined_flags,
        "undefined_flag_writes": undefined_flag_writes,
        "memory_events": memory_events,
        "faults": faults,
        "control": _semantic_outcome_json(current.get("outcome")),
        "call_effects": call_effects,
        "ordered_events": ordered_events,
    }
    result["counts"] = {
        name: len(result[name])
        for name in (
            "register_writes",
            "defined_flag_writes",
            "undefined_flags",
            "undefined_flag_writes",
            "memory_events",
            "faults",
            "call_effects",
            "ordered_events",
        )
    }
    return result

def _semantic_instruction_effect_blocker(
    index: int,
    instruction: dict[str, Any],
    symbolic: dict[str, Any],
) -> dict[str, Any]:
    rva = instruction.get("rva")
    blocking_instruction = symbolic.get("instruction")
    if not isinstance(rva, int) and isinstance(blocking_instruction, dict):
        rva = blocking_instruction.get("rva")
    raw_bytes = instruction.get("bytes")
    try:
        exact_bytes = bytes.fromhex(raw_bytes) if isinstance(raw_bytes, str) else b""
    except ValueError:
        exact_bytes = b""
    blocker = {
        "index": index,
        "rva": rva,
        "bytes": exact_bytes.hex(),
        "bytes_sha256": sha256_bytes(exact_bytes),
        "category": symbolic.get("category")
        or "x87_instruction_effect_schedule_incomplete",
        "blocker": symbolic.get("blocker")
        or "instruction effects could not be represented",
        "next_action": symbolic.get("next_action")
        or "add checked per-instruction semantics",
    }
    blocker["blocker_sha256"] = _semantic_json_sha256(blocker)
    return blocker

def _semantic_json_contains_op(value: Any, operation: str) -> bool:
    if isinstance(value, dict):
        if value.get("op") == operation:
            return True
        return any(_semantic_json_contains_op(item, operation) for item in value.values())
    if isinstance(value, list):
        return any(_semantic_json_contains_op(item, operation) for item in value)
    return False

def _semantic_json_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )

def _semantic_expr_json(value: Any) -> Any:
    if not isinstance(value, tuple) or not value:
        if isinstance(value, list):
            return [_semantic_expr_json(item) for item in value]
        if isinstance(value, dict):
            return {str(key): _semantic_expr_json(item) for key, item in value.items()}
        return value
    op = str(value[0])
    if op == "const":
        return {"op": "const", "width": 32, "value": int(value[1]) & 0xFFFFFFFF}
    if op == "reg":
        return {"op": "reg", "width": 32, "name": str(value[1])}
    if op == "flag":
        return {"op": "flag", "name": str(value[1])}
    if op == "fs_base":
        return {"op": "fs_base", "width": 32}
    if op == "mem32":
        return {"op": "load", "width": 4, "address": _semantic_expr_json(value[1])}
    if op == "mem":
        return {"op": "load", "width": int(value[1]) // 8, "address": _semantic_expr_json(value[2])}
    if op == "env_response":
        return {"op": "env_response", "width": 32, "index": int(value[1])}
    if op == "call_response":
        return {"op": "call_response", "width": 32, "call_index": int(value[1]), "register": str(value[2])}
    if op == "call_mem":
        return {"op": "call_memory_load", "width": int(value[2]) // 8, "call_index": int(value[1]), "address": _semantic_expr_json(value[3])}
    if op == "call_flag":
        return {"op": "call_flag", "call_index": int(value[1]), "flag": str(value[2])}
    if op == "undefined_bv":
        result = {
            "op": "undefined_bv",
            "width": 32,
            "reason": str(value[1]),
            "id": str(value[2]),
        }
        if len(value) == 4:
            result["defined_value"] = _semantic_expr_json(value[3])
        return result
    if op == "undefined_flag":
        return {"op": "undefined_flag", "reason": str(value[1]), "id": str(value[2])}
    if op == "write_bits":
        offset = int(value[2])
        width = int(value[3])
        field_mask = (((1 << width) - 1) << offset) & 0xFFFFFFFF
        clear_mask = (~field_mask) & 0xFFFFFFFF
        inserted = _semantic_expr_json(value[4])
        if offset:
            inserted = {
                "op": "shl32",
                "args": [
                    inserted,
                    {"op": "const", "width": 32, "value": offset},
                ],
            }
        return {
            "op": "or32",
            "args": [
                {
                    "op": "and32",
                    "args": [
                        _semantic_expr_json(value[1]),
                        {"op": "const", "width": 32, "value": clear_mask},
                    ],
                },
                {
                    "op": "and32",
                    "args": [
                        inserted,
                        {"op": "const", "width": 32, "value": field_mask},
                    ],
                },
            ],
        }
    if op in {"true", "false"}:
        return {"op": op}
    op_map = {
        "add": "add32",
        "sub": "sub32",
        "mul": "mul32",
        "xor": "xor32",
        "and": "and32",
        "or": "or32",
        "bvnot": "not32",
        "neg": "neg32",
        "shl": "shl32",
        "lshr": "lshr32",
        "ashr": "sar",
        "sext": "sign_extend",
        "ite": "ite",
        "ult": "ult32",
        "eq": "eq",
        "msb": "msb32",
        "msb_w": "msb",
        "not": "not",
        "bool_and": "and_bool",
        "bool_or": "or_bool",
        "bool_xor": "xor_bool",
        "bool_eq": "eq_bool",
        "add_overflow": "add_overflow32",
        "sub_overflow": "sub_overflow32",
        "add_overflow_w": "add_overflow",
        "sub_overflow_w": "sub_overflow",
        "shift_cf": "shift_cf",
        "shift_of": "shift_of",
        "bool_bit": "bool_to_bit",
        "adc_carry": "adc_carry",
        "adc_overflow": "adc_overflow",
        "sbb_borrow": "sbb_borrow",
        "sbb_overflow": "sbb_overflow",
        "imul_low": "imul_low32",
        "imul_high": "imul_high32",
        "imul_overflow": "imul_overflow",
        "mul_low": "mul_low32",
        "mul_high": "mul_high32",
        "mul_carry": "mul_carry",
        "parity": "parity",
        "udiv_quot": "udiv_quot32",
        "udiv_rem": "udiv_rem32",
        "udiv_valid": "udiv_valid32",
        "bsr_index": "bsr_index",
        "tzcnt": "tzcnt",
        "fpu_bits_lo": "fpu_bits_lo32",
        "fpu_bits_hi": "fpu_bits_hi32",
        "fpu_int32": "fpu_int32",
        "fpu_status_word": "fpu_status_word",
        "fpu_control_word": "fpu_control_word",
    }
    return {"op": op_map.get(op, op), "args": [_semantic_expr_json(item) for item in value[1:]]}

def _semantic_memory_event_json(event: Any) -> dict[str, Any]:
    if isinstance(event, tuple) and len(event) >= 2 and event[0] == "read":
        mem = event[1]
        if isinstance(mem, tuple) and len(mem) > 1 and mem[0] == "mem32":
            return {"kind": "read", "width": 4, "address": _semantic_expr_json(mem[1])}
        if isinstance(mem, tuple) and len(mem) > 2 and mem[0] == "mem":
            return {"kind": "read", "width": int(mem[1]) // 8, "address": _semantic_expr_json(mem[2])}
        if isinstance(mem, tuple) and len(mem) > 3 and mem[0] == "call_mem":
            return {"kind": "read", "width": int(mem[2]) // 8, "address": _semantic_expr_json(mem[3]), "memory_epoch": {"kind": "internal_call", "call_index": int(mem[1])}}
        return {"kind": "read", "width": 4, "address": _semantic_expr_json(mem)}
    if isinstance(event, tuple) and len(event) >= 3 and event[0] == "write":
        mem = event[1]
        if isinstance(mem, tuple) and len(mem) > 1 and mem[0] == "mem32":
            return {"kind": "write", "width": 4, "address": _semantic_expr_json(mem[1]), "value": _semantic_expr_json(event[2])}
        if isinstance(mem, tuple) and len(mem) > 2 and mem[0] == "mem":
            return {"kind": "write", "width": int(mem[1]) // 8, "address": _semantic_expr_json(mem[2]), "value": _semantic_expr_json(event[2])}
        if isinstance(mem, tuple) and len(mem) > 3 and mem[0] == "call_mem":
            return {
                "kind": "write",
                "width": int(mem[2]) // 8,
                "address": _semantic_expr_json(mem[3]),
                "value": _semantic_expr_json(event[2]),
                "memory_epoch": {"kind": "internal_call", "call_index": int(mem[1])},
            }
        return {"kind": "write", "width": 4, "address": _semantic_expr_json(mem), "value": _semantic_expr_json(event[2])}
    return {"kind": "unknown", "raw": _expr_json(event)}

def _semantic_external_event_json(event: Any) -> dict[str, Any]:
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "external_call":
        result = {
            "kind": "external_call",
            "dll": event[1],
            "symbol": event[2],
            "ordinal": event[3],
            "arguments": [_semantic_expr_json(item) for item in event[4]],
        }
        if len(event) >= 6 and isinstance(event[5], tuple) and event[5]:
            boundary = event[5]
            if boundary[0] == "machine_call_boundary":
                result["return_rva"] = int(boundary[1])
                result["input_model"] = "captured_machine_call_boundary_v1"
                result["register_inputs"] = _semantic_call_register_inputs_json(
                    boundary[2] if len(boundary) > 2 else ()
                )
                result["stack_inputs"] = _semantic_call_stack_inputs_json(
                    boundary[3] if len(boundary) > 3 else ()
                )
                result["flag_inputs"] = _semantic_call_register_inputs_json(
                    boundary[4] if len(boundary) > 4 else ()
                )
            elif boundary[0] == "auto_call_inputs":
                # Backward-compatible decoding for cached v1 symbolic summaries.
                result["input_model"] = "captured_visible_register_and_stack_inputs_v1"
                result["register_inputs"] = _semantic_call_register_inputs_json(
                    boundary[1] if len(boundary) > 1 else ()
                )
                result["stack_inputs"] = _semantic_call_stack_inputs_json(
                    boundary[2] if len(boundary) > 2 else ()
                )
                result["flag_inputs"] = _semantic_call_register_inputs_json(
                    boundary[3] if len(boundary) > 3 else ()
                )
        return result
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "internal_call":
        return {
            "kind": "internal_call",
            "target_rva": int(event[1]),
            "return_rva": int(event[2]),
            "register_inputs": _semantic_call_register_inputs_json(event[3]),
            "stack_inputs": _semantic_call_stack_inputs_json(event[4]),
            "flag_inputs": _semantic_call_register_inputs_json(event[5] if len(event) > 5 else ()),
            "effect_model": "uninterpreted_internal_call_response_v1",
        }
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "indirect_call":
        return {
            "kind": "indirect_call",
            "target": _semantic_expr_json(event[1]),
            "return_rva": int(event[2]),
            "register_inputs": _semantic_call_register_inputs_json(event[3]),
            "stack_inputs": _semantic_call_stack_inputs_json(event[4]),
            "flag_inputs": _semantic_call_register_inputs_json(event[5] if len(event) > 5 else ()),
            "effect_model": "uninterpreted_indirect_call_response_v1",
        }
    if isinstance(event, tuple) and len(event) >= 6 and event[0] == "rep_movsd":
        return {
            "kind": "rep_movsd",
            "index": int(event[1]),
            "destination": _semantic_expr_json(event[2]),
            "source": _semantic_expr_json(event[3]),
            "count": _semantic_expr_json(event[4]),
            "direction_flag": _semantic_expr_json(event[5]),
            "effect_model": "symbolic_string_copy_v1",
        }
    if isinstance(event, tuple) and len(event) >= 8 and event[0] == "rep_movs":
        return {
            "kind": "rep_movs",
            "index": int(event[1]),
            "element_width": int(event[2]),
            "address_size": int(event[3]),
            "destination": _semantic_expr_json(event[4]),
            "source": _semantic_expr_json(event[5]),
            "count": _semantic_expr_json(event[6]),
            "direction_flag": _semantic_expr_json(event[7]),
            "effect_model": "symbolic_string_copy_v2",
            "restart_semantics": "element_committed_v1",
        }
    if isinstance(event, tuple) and len(event) >= 6 and event[0] == "rep_stosd":
        return {
            "kind": "rep_stosd",
            "index": int(event[1]),
            "destination": _semantic_expr_json(event[2]),
            "value": _semantic_expr_json(event[3]),
            "count": _semantic_expr_json(event[4]),
            "direction_flag": _semantic_expr_json(event[5]),
            "effect_model": "symbolic_string_fill_v1",
        }
    if isinstance(event, tuple) and len(event) >= 8 and event[0] == "rep_stos":
        return {
            "kind": "rep_stos",
            "index": int(event[1]),
            "element_width": int(event[2]),
            "address_size": int(event[3]),
            "destination": _semantic_expr_json(event[4]),
            "value": _semantic_expr_json(event[5]),
            "count": _semantic_expr_json(event[6]),
            "direction_flag": _semantic_expr_json(event[7]),
            "effect_model": "symbolic_string_fill_v2",
            "restart_semantics": "element_committed_v1",
        }
    if isinstance(event, tuple) and len(event) >= 8 and event[0] == "rep_scas":
        return {
            "kind": "rep_scas",
            "index": int(event[1]),
            "element_width": int(event[2]),
            "address_size": int(event[3]),
            "destination": _semantic_expr_json(event[4]),
            "accumulator": _semantic_expr_json(event[5]),
            "count": _semantic_expr_json(event[6]),
            "direction_flag": _semantic_expr_json(event[7]),
            "repeat_condition": "while_not_equal_v1",
            "comparison_model": "subtraction_flags_v1",
            "segment_model": "flat_es_zero_v1",
            "effect_model": "symbolic_string_scan_v1",
            "restart_semantics": "element_committed_v1",
            "fault_model": "read_before_commit_v1",
            "owned_register_outputs": ["edi", "ecx"],
            "owned_flag_outputs": ["cf", "pf", "af", "zf", "sf", "of"],
        }
    return {"kind": "unknown_external_event", "raw": _expr_json(event)}

def _semantic_fault_json(fault: Any) -> dict[str, Any]:
    if isinstance(fault, tuple) and len(fault) == 3:
        return {
            "kind": str(fault[0]),
            "condition": _semantic_expr_json(fault[1]),
            "instruction_rva": int(fault[2]),
        }
    return {"kind": "unknown", "raw": _expr_json(fault)}

def _semantic_call_register_inputs_json(items: Any) -> dict[str, Any]:
    result = {}
    for item in items if isinstance(items, tuple) else ():
        if isinstance(item, tuple) and len(item) == 2:
            result[str(item[0])] = _semantic_expr_json(item[1])
    return result

def _semantic_call_stack_inputs_json(items: Any) -> list[dict[str, Any]]:
    result = []
    for item in items if isinstance(items, tuple) else ():
        if isinstance(item, tuple) and len(item) == 3:
            result.append({"offset": int(item[0]), "width": int(item[1]) // 8, "value": _semantic_expr_json(item[2])})
    return result

def _semantic_outcome_json(outcome: Any) -> dict[str, Any]:
    if not isinstance(outcome, tuple) or not outcome:
        return {"kind": "unknown", "raw": _expr_json(outcome)}
    kind = str(outcome[0])
    if kind == "fallthrough":
        return {"kind": "fallthrough", "target_rva": outcome[1]}
    if kind == "jump":
        return {"kind": "jump", "target_rva": outcome[1]}
    if kind == "branch":
        return {
            "kind": "branch",
            "condition": _semantic_expr_json(outcome[1]),
            "true_target_rva": outcome[2],
            "false_target_rva": outcome[3],
        }
    if kind == "return":
        return {"kind": "return", "value": _semantic_expr_json(outcome[1])}
    if kind == "call":
        return {"kind": "direct_call", "target_rva": outcome[1], "return_rva": outcome[2]}
    if kind == "indirect_jump":
        return {"kind": "indirect_jump", "target": _semantic_expr_json(outcome[1])}
    if kind == "indirect_jump_table":
        switch_contract = outcome[2] if len(outcome) > 2 and isinstance(outcome[2], dict) else {}
        return {
            "kind": "indirect_jump_table",
            "target": _semantic_expr_json(outcome[1]),
            "switch_contract": switch_contract,
            "target_rvas": [
                target_rva
                for item in switch_contract.get("case_targets", []) if isinstance(switch_contract.get("case_targets"), list) and isinstance(item, dict)
                for target_rva in [_safe_int(item.get("target_rva"))]
                if target_rva is not None
            ],
        }
    if kind == "external_jump":
        return {"kind": "external_jump", "dll": outcome[1], "symbol": outcome[2], "ordinal": outcome[3]}
    return {"kind": kind, "raw": _expr_json(outcome)}

def _semantic_edge_conditions(outcome: dict[str, Any]) -> list[dict[str, Any]]:
    kind = outcome.get("kind")
    if kind == "branch":
        return [
            {"target_rva": outcome.get("true_target_rva"), "condition": outcome.get("condition")},
            {"target_rva": outcome.get("false_target_rva"), "condition": {"op": "not", "args": [outcome.get("condition")]}},
        ]
    if kind in {"fallthrough", "jump"}:
        return [{"target_rva": outcome.get("target_rva"), "condition": {"op": "true"}}]
    if kind == "indirect_jump_table":
        switch_contract = outcome.get("switch_contract") if isinstance(outcome.get("switch_contract"), dict) else {}
        case_targets = switch_contract.get("case_targets") if isinstance(switch_contract.get("case_targets"), list) else []
        return [
            {
                "target_rva": target_rva,
                "condition": {
                    "op": "jump_table_case",
                    "index": item.get("index"),
                    "instruction_rva": switch_contract.get("instruction", {}).get("rva")
                    if isinstance(switch_contract.get("instruction"), dict)
                    else None,
                },
            }
            for item in case_targets
            if isinstance(item, dict)
            for target_rva in [_safe_int(item.get("target_rva"))]
            if target_rva is not None
        ]
    return []

def _semantic_stack_delta_from_observables(observables: dict[str, Any]) -> dict[str, Any]:
    esp = observables.get("reg:esp")
    delta = _semantic_stack_delta_expr(esp)
    if delta is None:
        return {"status": "unknown", "expression": _semantic_expr_json(esp)}
    return {"status": "derived", "net_bytes": delta, "expression": _semantic_expr_json(esp)}

def _semantic_stack_delta_expr(expr: Any) -> int | None:
    affine = _semantic_stack_affine_expr(expr)
    if affine is None or affine[0] != 1:
        return None
    unsigned = affine[1] & 0xFFFF_FFFF
    return unsigned - (1 << 32) if unsigned >= 1 << 31 else unsigned

def _semantic_stack_affine_expr(expr: Any) -> tuple[int, int] | None:
    """Reduce exact bit-vector addition/subtraction to ``a*ESP + b``."""

    if expr == ("reg", "esp"):
        return 1, 0
    if (
        isinstance(expr, tuple)
        and len(expr) == 2
        and expr[0] == "const"
        and isinstance(expr[1], int)
        and not isinstance(expr[1], bool)
    ):
        return 0, int(expr[1])
    if not isinstance(expr, tuple) or not expr:
        return None
    operation = expr[0]
    if operation == "add" and len(expr) >= 3:
        coefficient = 0
        constant = 0
        for part in expr[1:]:
            reduced = _semantic_stack_affine_expr(part)
            if reduced is None:
                return None
            coefficient += reduced[0]
            constant += reduced[1]
        return coefficient, constant
    if operation == "sub" and len(expr) == 3:
        left = _semantic_stack_affine_expr(expr[1])
        right = _semantic_stack_affine_expr(expr[2])
        if left is None or right is None:
            return None
        return left[0] - right[0], left[1] - right[1]
    return None

def _semantic_memory_frame_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    frames: dict[str, dict[str, Any]] = {}
    accesses: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for access_kind, access_list_name in (("read", "memory_reads"), ("write", "memory_writes")):
            for index, access in enumerate(function.get(access_list_name, []) if isinstance(function.get(access_list_name), list) else []):
                if not isinstance(access, dict):
                    continue
                frame = _semantic_memory_frame_for_access(access)
                frames.setdefault(str(frame["id"]), frame)
                instruction = access.get("instruction") if isinstance(access.get("instruction"), dict) else {}
                accesses.append(
                    {
                        "id": f"memory-access:{_safe_gap_part(function_name)}:{instruction.get('rva', 'unknown')}:{access_kind}:{index}",
                        "function": function_name or None,
                        "block_id": _block_id_for_instruction(function, instruction),
                        "access": access_kind,
                        "width": access.get("width"),
                        "frame_id": frame["id"],
                        "frame_kind": frame["frame_kind"],
                        "addressing": access.get("addressing") if isinstance(access.get("addressing"), dict) else {},
                        "instruction": instruction,
                        "status": "classified" if frame["frame_kind"] != "unknown" else "incomplete",
                        "blocker": None if frame["frame_kind"] != "unknown" else "memory frame could not be classified from static addressing evidence",
                        "source_access": access,
                    }
                )
    return {
        "format": "stage-a-memory-frame-contracts-v1",
        "reference_contract": contract_ref,
        "frames": sorted(frames.values(), key=lambda item: str(item.get("id") or "")),
        "accesses": sorted(accesses, key=lambda item: str(item.get("id") or "")),
        "counts": {
            "frames": len(frames),
            "accesses": len(accesses),
            "by_frame_kind": _count_by(list(frames.values()), "frame_kind"),
            "by_access": _count_by(accesses, "access"),
        },
    }

def _semantic_memory_frame_for_access(access: dict[str, Any]) -> dict[str, Any]:
    role = str(access.get("memory_role") or "unknown")
    section = access.get("memory_section") if isinstance(access.get("memory_section"), dict) else {}
    addressing = access.get("addressing") if isinstance(access.get("addressing"), dict) else {}
    base = str(addressing.get("base") or "")
    entry_pointer = access.get("entry_register_pointer") if isinstance(access.get("entry_register_pointer"), dict) else {}
    if role == "import_address_table":
        frame_kind = "iat.import"
        frame_key = str(access.get("memory_rva") or "unknown")
    elif role.startswith("global_"):
        frame_kind = "global.rw" if section.get("writable") is True else "global.ro"
        frame_key = str(section.get("name") or access.get("memory_rva") or "unknown")
    elif role == "stack_argument_slot":
        frame_kind = "stack.arg"
        frame_key = base or "stack"
    elif role in {"stack_local_slot", "stack_pointer_slot"}:
        frame_kind = "stack.local"
        frame_key = base or "stack"
    elif entry_pointer:
        frame_kind = "object.pointer_candidate"
        frame_key = str(entry_pointer.get("register") or base or "entry")
    elif role == "argument_pointer_deref":
        frame_kind = "object.argument_pointer"
        frame_key = base or "argument"
    elif role == "global_pointer_deref":
        frame_kind = "object.global_pointer"
        frame_key = base or str(access.get("memory_rva") or "global")
    elif role == "computed_pointer_deref":
        frame_kind = "object.computed_pointer"
        frame_key = base or "computed"
    elif role == "absolute_memory_slot":
        frame_kind = "absolute.memory"
        frame_key = str(access.get("memory_rva") or "absolute")
    elif role == "computed_memory":
        frame_kind = "computed.memory"
        frame_key = base or "computed"
    else:
        frame_kind = f"role.{_safe_gap_part(role)}" if role else "role.unknown"
        frame_key = role
    return {
        "id": f"frame:{_safe_gap_part(frame_kind)}:{_safe_gap_part(frame_key)}",
        "frame_kind": frame_kind,
        "memory_role": role,
        "section": section or None,
        "base_register": base or None,
        "entry_register_pointer": entry_pointer or None,
        "status": "classified",
    }

def _semantic_call_summary_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    summaries: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for index, callsite in enumerate(function.get("callsites", []) if isinstance(function.get("callsites"), list) else []):
            if not isinstance(callsite, dict):
                continue
            summary = _semantic_call_summary(function_name, index, callsite)
            summaries.append(summary)
    return {
        "format": "stage-a-call-summary-contracts-v1",
        "reference_contract": contract_ref,
        "calls": sorted(summaries, key=lambda item: str(item.get("id") or "")),
        "counts": {
            "calls": len(summaries),
            "by_status": _count_by(summaries, "status"),
            "by_target_kind": _count_by(summaries, "target_kind"),
        },
    }

def _semantic_call_summary(function_name: str, index: int, callsite: dict[str, Any]) -> dict[str, Any]:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    inventory = callsite.get("argument_inventory") if isinstance(callsite.get("argument_inventory"), dict) else {}
    hidden = callsite.get("hidden_sret_or_out_param_evidence") if isinstance(callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    varargs = callsite.get("varargs_evidence") if isinstance(callsite.get("varargs_evidence"), dict) else {}
    targets = callsite.get("function_pointer_targets") if isinstance(callsite.get("function_pointer_targets"), list) else []
    blockers: list[str] = []
    indirect_boundary = (target.get("kind") == "function_pointer" and target.get("status") == "unresolved")
    if any(isinstance(item, dict) and item.get("status") == "unresolved" for item in targets) and not indirect_boundary:
        blockers.append("function-pointer target set is unresolved")
    fmt = varargs.get("format_string") if isinstance(varargs.get("format_string"), dict) else {}
    if fmt.get("status") == "incomplete":
        blockers.append(str(fmt.get("reason") or "varargs format-string inventory is incomplete"))
    status = "complete" if not blockers else "incomplete"
    return {
        "id": str(callsite.get("id") or f"callsite:{_safe_gap_part(function_name)}:{index}"),
        "function": function_name or None,
        "block_id": callsite.get("block_id"),
        "status": status,
        "target_kind": target.get("kind") or "unknown",
        "target": target,
        "calling_convention": inventory.get("calling_convention") or "unknown",
        "argument_inventory": inventory,
        "return_value": {"register": "eax", "status": "environment_response_or_direct_call_result"},
        "stack_delta": callsite.get("stack_delta") if isinstance(callsite.get("stack_delta"), dict) else {"status": "unknown"},
        "hidden_sret_or_out_param_evidence": hidden,
        "varargs_evidence": varargs,
        "function_pointer_targets": targets,
        "indirect_boundary": {"status": "explicit", "effect_model": "preserve_target_expression_and_call_response"} if indirect_boundary else None,
        "blockers": blockers,
        "next_action": _semantic_call_summary_next_action(function_name, target, blockers, varargs, hidden),
        "source_callsite": callsite,
    }

def _semantic_call_summary_next_action(
    function_name: str,
    target: dict[str, Any],
    blockers: list[str],
    varargs: dict[str, Any],
    hidden: dict[str, Any],
) -> str:
    if blockers:
        if any("function-pointer" in item for item in blockers):
            return f"recover finite function-pointer targets for {function_name} or keep the indirect boundary explicit"
        if varargs.get("status") == "candidate" or any("varargs" in item or "format" in item for item in blockers):
            return f"recover the format-string and variadic argument inventory for {function_name}"
        return f"complete the call summary for {function_name}"
    if varargs.get("status") == "candidate":
        return "preserve the variadic import/prototype boundary exactly in generated C"
    if hidden.get("status") == "candidate":
        return "preserve the hidden sret/out-param channel across this call"
    if target.get("kind") == "import":
        return "preserve this call as an import/environment boundary"
    return "preserve this call target, argument inventory, and return-value use"

__all__ = [
    '_ORDINARY_CHECKED_DECODER',
    '_ORDINARY_CHECKED_EXECUTOR',
    '_SEMANTIC_X87_SINGLETON_MNEMONICS',
    '_X87_PHYSICAL_OBSERVABLE_FIELDS',
    '_X87_REPLAY_OBLIGATION_MODEL',
    '_X87_SINGLETON_CHECKED_DECODER',
    '_X87_SINGLETON_CHECKED_EXECUTOR',
    '_semantic_call_register_inputs_json',
    '_semantic_call_stack_inputs_json',
    '_semantic_call_summary',
    '_semantic_call_summary_contracts',
    '_semantic_call_summary_next_action',
    '_semantic_disassemble_block',
    '_semantic_edge_conditions',
    '_semantic_effects_from_observables',
    '_semantic_expr_json',
    '_semantic_external_event_json',
    '_semantic_fault_json',
    '_semantic_fpu_state_from_observables',
    '_semantic_initial_instruction_observables',
    '_semantic_instruction_effect_blocker',
    '_semantic_instruction_effect_delta',
    '_semantic_instruction_effect_schedule',
    '_semantic_json_contains_op',
    '_semantic_json_sha256',
    '_semantic_memory_event_json',
    '_semantic_memory_frame_contracts',
    '_semantic_memory_frame_for_access',
    '_semantic_ordered_event_json',
    '_semantic_outcome_json',
    '_semantic_pre_state',
    '_semantic_stack_delta_expr',
    '_semantic_stack_delta_from_observables',
    '_semantic_transfer_contract',
    '_semantic_transfer_contracts',
    '_semantic_transfer_inventory_contains_x87',
    '_semantic_x87_expression_valid',
    '_semantic_x87_instruction_effect_schedule',
    '_semantic_x87_physical_field_valid',
    '_semantic_x87_replay_binding',
]
