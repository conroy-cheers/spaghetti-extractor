"""Symbolic x86 block execution used to propose semantic contracts."""

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
    _is_conditional_jump,
    _parse_int,
)
from ..static_program.model import StaticUnitContext

from .map_analysis import (
    _capstone_mode,
)
from .map_analysis import (
    _external_import_call,
    _resolved_branch_target,
)
from .map_verification import (
    _external_import_jump,
)

from .abi_control_flow import (
    _abi_indexed_jump_table_contract,
)
from .abi_instruction import (
    _abi_mem_operand_report,
)

from .symbolic_expressions import (
    _canonical_expr,
    _expr_add,
    _expr_lshr,
    _expr_mask,
    _expr_mul,
)

_X86_REGISTER_PARTS: dict[str, tuple[str, int, int]] = {
    "eax": ("eax", 0, 32),
    "ax": ("eax", 0, 16),
    "al": ("eax", 0, 8),
    "ah": ("eax", 8, 8),
    "ebx": ("ebx", 0, 32),
    "bx": ("ebx", 0, 16),
    "bl": ("ebx", 0, 8),
    "bh": ("ebx", 8, 8),
    "ecx": ("ecx", 0, 32),
    "cx": ("ecx", 0, 16),
    "cl": ("ecx", 0, 8),
    "ch": ("ecx", 8, 8),
    "edx": ("edx", 0, 32),
    "dx": ("edx", 0, 16),
    "dl": ("edx", 0, 8),
    "dh": ("edx", 8, 8),
    "esi": ("esi", 0, 32),
    "si": ("esi", 0, 16),
    "edi": ("edi", 0, 32),
    "di": ("edi", 0, 16),
    "ebp": ("ebp", 0, 32),
    "bp": ("ebp", 0, 16),
    "esp": ("esp", 0, 32),
    "sp": ("esp", 0, 16),
}

def _is_supported_register_name(name: str) -> bool:
    return name.lower() in _X86_REGISTER_PARTS

def _operand_width_bits(insn: Any, operand: Any) -> int:
    if operand.type == X86_OP_REG:
        name = insn.reg_name(operand.reg).lower()
        part = _X86_REGISTER_PARTS.get(name)
        if part is not None:
            return part[2]
    size = int(getattr(operand, "size", 0) or 0)
    return max(1, size) * 8 if size else 32

def _read_register_expr(name: str, registers: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    part = _X86_REGISTER_PARTS.get(name.lower())
    if part is None:
        return None
    base, offset, width = part
    value = registers.get(base)
    if value is None:
        return None
    if (
        value[0] == "write_bits"
        and int(value[2]) == offset
        and int(value[3]) == width
    ):
        return _expr_mask(value[4], width)
    if offset:
        value = _expr_lshr(value, ("const", offset))
    return _expr_mask(value, width)

def _write_register_expr(name: str, value: tuple[Any, ...], registers: dict[str, tuple[Any, ...]]) -> bool:
    part = _X86_REGISTER_PARTS.get(name.lower())
    if part is None:
        return False
    base, offset, width = part
    value = _expr_mask(value, width)
    if width == 32 and offset == 0:
        registers[base] = value
        return True
    current = registers.get(base)
    if current is None:
        return False
    if (
        current[0] == "write_bits"
        and int(current[2]) == offset
        and int(current[3]) == width
    ):
        current = current[1]
    registers[base] = ("write_bits", current, offset, width, value)
    return True

def _operand_expr(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    *,
    width_bits: int | None = None,
) -> tuple[Any, ...] | None:
    width_bits = width_bits or _operand_width_bits(insn, operand)
    if operand.type == X86_OP_IMM:
        return _expr_mask(("const", int(operand.imm) & 0xFFFFFFFF), width_bits)
    if operand.type == X86_OP_REG:
        name = insn.reg_name(operand.reg)
        value = _read_register_expr(name, registers)
        return _expr_mask(value, width_bits) if value is not None else None
    return None

def _read_operand_expr(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    width_bits: int | None = None,
    memory_epoch: int | None = None,
) -> tuple[Any, ...] | None:
    width_bits = width_bits or _operand_width_bits(insn, operand)
    value = _operand_expr(insn, operand, registers, width_bits=width_bits)
    if value is not None:
        return value
    if operand.type != X86_OP_MEM:
        return None
    address = _mem_address_expr(insn, operand, registers)
    if address is None:
        return None
    return _memory_read_expr(address, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)

def _write_operand_expr(
    insn: Any,
    operand: Any,
    value: tuple[Any, ...],
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    width_bits: int | None = None,
) -> bool:
    width_bits = width_bits or _operand_width_bits(insn, operand)
    if operand.type == X86_OP_REG:
        return _write_register_expr(insn.reg_name(operand.reg), value, registers)
    if operand.type == X86_OP_MEM:
        address = _mem_address_expr(insn, operand, registers)
        if address is None:
            return False
        _memory_write_expr(address, width_bits, value, memory_events, memory_writes)
        return True
    return False

def _memory_expr(width_bits: int, address: tuple[Any, ...]) -> tuple[Any, ...]:
    return ("mem32", address) if width_bits == 32 else ("mem", width_bits, address)

def _memory_epoch_expr(width_bits: int, address: tuple[Any, ...], memory_epoch: int | None) -> tuple[Any, ...]:
    if memory_epoch is None:
        return _memory_expr(width_bits, address)
    return ("call_mem", int(memory_epoch), width_bits, address)

def _memory_read_expr(
    address: tuple[Any, ...],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    width_bits: int = 32,
    memory_epoch: int | None = None,
) -> tuple[Any, ...]:
    canonical_address = _canonical_expr(address)
    memory_events.append(("read", _memory_epoch_expr(width_bits, canonical_address, memory_epoch)))
    for written_address, written_width, written_value in reversed(memory_writes):
        if written_width == width_bits and _canonical_expr(written_address) == canonical_address:
            return _expr_mask(written_value, width_bits)
    return _memory_epoch_expr(width_bits, canonical_address, memory_epoch)

def _memory_write_expr(
    address: tuple[Any, ...],
    width_bits: int,
    value: tuple[Any, ...],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> None:
    canonical_address = _canonical_expr(address)
    value = _expr_mask(value, width_bits)
    memory_events.append(("write", _memory_expr(width_bits, canonical_address), value))
    memory_writes.append((canonical_address, width_bits, value))

def _external_call_contract(mapped: StaticUnitContext, index: int) -> dict[str, Any] | None:
    calls = mapped.source.get("external_calls", mapped.source.get("external_events", []))
    if not isinstance(calls, list) or index >= len(calls):
        return None
    contract = calls[index]
    return contract if isinstance(contract, dict) else None

def _external_call_args(
    insn: Any,
    contract: dict[str, Any],
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    memory_epoch: int | None = None,
) -> list[tuple[Any, ...]] | None:
    args = contract.get("args", [])
    if not isinstance(args, list):
        return None
    result: list[tuple[Any, ...]] = []
    for arg in args:
        expr = _external_arg_expr(insn, arg, registers, memory_events, memory_writes, memory_epoch=memory_epoch)
        if expr is None:
            return None
        result.append(expr)
    return result

def _external_arg_expr(
    insn: Any,
    spec: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    memory_epoch: int | None = None,
) -> tuple[Any, ...] | None:
    if isinstance(spec, int):
        return ("const", spec)
    if isinstance(spec, str):
        return _read_register_expr(spec.lower(), registers)
    if not isinstance(spec, dict):
        return None
    if "const" in spec:
        return ("const", _parse_int(spec["const"]))
    register_name = spec.get("reg") or spec.get("register")
    if register_name is None and spec.get("kind") == "reg":
        register_name = spec.get("name")
    if register_name is not None:
        return _read_register_expr(str(register_name).lower(), registers)
    stack_offset = spec.get("stack") if "stack" in spec else spec.get("stack_offset")
    if stack_offset is None and spec.get("kind") == "stack":
        stack_offset = spec.get("offset", 0)
    if stack_offset is not None:
        address = _expr_add(registers["esp"], ("const", _parse_int(stack_offset)))
        return _memory_read_expr(address, memory_events, memory_writes, memory_epoch=memory_epoch)
    if spec.get("kind") == "memory":
        base_name = str(spec.get("base", "esp")).lower()
        base = registers.get(base_name)
        if base is None:
            return None
        address = _expr_add(base, ("const", _parse_int(spec.get("offset", 0))))
        return _memory_read_expr(address, memory_events, memory_writes, memory_epoch=memory_epoch)
    return None

def _internal_call_event(
    event_index: int,
    target_rva: int,
    return_rva: int,
    registers: dict[str, tuple[Any, ...]],
    flags: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> tuple[Any, ...]:
    register_inputs = _call_register_inputs(registers)
    flag_inputs = _call_flag_inputs(flags)
    stack_inputs = _call_stack_inputs(registers, memory_writes)
    return ("internal_call", int(target_rva), int(return_rva), register_inputs, stack_inputs, flag_inputs)

def _external_import_call_event(
    event_index: int,
    imported: StageAImport,
    return_rva: int,
    registers: dict[str, tuple[Any, ...]],
    flags: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    auto_inputs: bool,
) -> tuple[Any, ...]:
    extras: tuple[Any, ...] = ()
    if auto_inputs:
        extras = (
            (
                "machine_call_boundary",
                int(return_rva),
                _call_register_inputs(registers),
                _call_stack_inputs(registers, memory_writes),
                _call_flag_inputs(flags),
            ),
        )
    return ("external_call", imported.dll, imported.symbol, imported.ordinal, (), *extras)

def _indirect_call_event(
    event_index: int,
    target: tuple[Any, ...],
    return_rva: int,
    registers: dict[str, tuple[Any, ...]],
    flags: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> tuple[Any, ...]:
    return (
        "indirect_call",
        _canonical_expr(target),
        int(return_rva),
        _call_register_inputs(registers),
        _call_stack_inputs(registers, memory_writes),
        _call_flag_inputs(flags),
    )

def _call_register_inputs(registers: dict[str, tuple[Any, ...]]) -> tuple[tuple[str, tuple[Any, ...]], ...]:
    return tuple((name, _canonical_expr(registers[name])) for name in sorted(registers))

def _call_flag_inputs(flags: dict[str, tuple[Any, ...]]) -> tuple[tuple[str, tuple[Any, ...]], ...]:
    return tuple((name, _canonical_expr(flags[name])) for name in sorted(flags))

def _call_stack_inputs(
    registers: dict[str, tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> tuple[tuple[int, int, tuple[Any, ...]], ...]:
    return tuple(_stack_argument_writes(registers.get("esp", ("reg", "esp")), memory_writes))

def _stack_argument_writes(
    esp: tuple[Any, ...],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
) -> list[tuple[int, int, tuple[Any, ...]]]:
    result: set[tuple[int, int]] = set()
    for address, width_bits, _value in memory_writes:
        offset = _stack_relative_offset(address, esp)
        if offset is None or offset < 0 or offset > 0x100:
            continue
        result.add((offset, width_bits))
    return [
        (
            offset,
            width_bits,
            _memory_expr(
                width_bits,
                _canonical_expr(_expr_add(esp, ("const", offset))),
            ),
        )
        for offset, width_bits in sorted(result)
    ]

def _stack_relative_offset(address: tuple[Any, ...], esp: tuple[Any, ...]) -> int | None:
    address = _canonical_expr(address)
    esp = _canonical_expr(esp)
    if address == esp:
        return 0
    if isinstance(address, tuple) and address and address[0] == "add":
        offset = 0
        saw_esp = False
        for part in address[1:]:
            if part == esp:
                saw_esp = True
            elif isinstance(part, tuple) and len(part) == 2 and part[0] == "const":
                offset = (offset + int(part[1])) & 0xFFFFFFFF
            else:
                return None
        if not saw_esp:
            return None
        if offset & 0x80000000:
            offset -= 0x100000000
        return offset
    if isinstance(address, tuple) and len(address) == 3 and address[0] == "sub" and address[1] == esp:
        right = address[2]
        if isinstance(right, tuple) and len(right) == 2 and right[0] == "const":
            return -int(right[1])
    return None

def _parse_external_stack_adjust(contract: dict[str, Any]) -> int:
    value = contract.get("stack_adjust", contract.get("stack_bytes_cleaned", 0))
    return _parse_int(value) if value is not None else 0

def _x87_memory_value(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    memory_epoch: int | None,
    integer: bool = False,
) -> tuple[Any, ...] | None:
    if operand.type != X86_OP_MEM:
        return None
    address = _mem_address_expr(insn, operand, registers)
    if address is None:
        return None
    width_bits = _operand_width_bits(insn, operand)
    if width_bits <= 32:
        value = _memory_read_expr(address, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
        return ("fpu_int", width_bits, value) if integer else ("fpu_mem", width_bits, value)
    low = _memory_read_expr(address, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
    high = _memory_read_expr(_expr_add(address, ("const", 4)), memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
    return ("fpu_mem64", low, high)

def _x87_operand_value(
    insn: Any,
    operand: Any,
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    fpu_stack: list[tuple[Any, ...]],
    *,
    memory_epoch: int | None,
    integer: bool = False,
) -> tuple[Any, ...] | None:
    if operand.type == X86_OP_MEM:
        return _x87_memory_value(insn, operand, registers, memory_events, memory_writes, memory_epoch=memory_epoch, integer=integer)
    index = _x87_st_index(insn.op_str)
    if index is not None and 0 <= index < len(fpu_stack):
        return fpu_stack[index]
    return None

def _x87_st_index(text: str) -> int | None:
    text = text.strip().lower()
    if not text:
        return None
    if "st(" not in text:
        return 0 if text == "st" or text == "st(0)" else None
    start = text.find("st(") + 3
    end = text.find(")", start)
    if end <= start:
        return None
    try:
        return int(text[start:end])
    except ValueError:
        return None

def _x87_push(fpu_stack: list[tuple[Any, ...]], value: tuple[Any, ...]) -> None:
    fpu_stack.insert(0, _canonical_expr(value))
    del fpu_stack[8:]

def _x87_pop(fpu_stack: list[tuple[Any, ...]]) -> tuple[Any, ...]:
    value = fpu_stack.pop(0) if fpu_stack else ("fpu_empty",)
    while len(fpu_stack) < 8:
        fpu_stack.append(("fpu_empty", len(fpu_stack)))
    return value

def _x87_store_memory(
    insn: Any,
    operand: Any,
    value: tuple[Any, ...],
    control: tuple[Any, ...],
    registers: dict[str, tuple[Any, ...]],
    memory_events: list[tuple[Any, ...]],
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]],
    *,
    integer: bool,
) -> bool:
    if operand.type != X86_OP_MEM:
        return False
    address = _mem_address_expr(insn, operand, registers)
    if address is None:
        return False
    width_bits = _operand_width_bits(insn, operand)
    if integer:
        _memory_write_expr(address, min(width_bits, 32), ("fpu_int32", value, control), memory_events, memory_writes)
        return True
    if width_bits <= 32:
        _memory_write_expr(address, width_bits, ("fpu_bits_lo", value), memory_events, memory_writes)
        return True
    _memory_write_expr(address, 32, ("fpu_bits_lo", value), memory_events, memory_writes)
    _memory_write_expr(_expr_add(address, ("const", 4)), 32, ("fpu_bits_hi", value), memory_events, memory_writes)
    return True

def _x87_binary(operator: str, left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    return ("fpu_" + operator, _canonical_expr(left), _canonical_expr(right))

def _mem_address_expr(insn: Any, operand: Any, registers: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    mem = operand.mem
    parts: list[tuple[Any, ...]] = []
    if mem.segment:
        segment = insn.reg_name(mem.segment).lower()
        if segment == "fs":
            parts.append(("fs_base",))
        elif segment not in {"cs", "ds", "es", "ss"}:
            return None
    if mem.base:
        base = registers.get(insn.reg_name(mem.base))
        if base is None:
            return None
        parts.append(base)
    if mem.index:
        index = registers.get(insn.reg_name(mem.index))
        if index is None:
            return None
        parts.append(_expr_mul(index, ("const", int(mem.scale))))
    if mem.disp:
        parts.append(("const", int(mem.disp) & 0xFFFFFFFF))
    if not parts:
        return ("const", 0)
    expr = parts[0]
    for part in parts[1:]:
        expr = _expr_add(expr, part)
    return _canonical_expr(expr)

__all__ = [
    '_X86_REGISTER_PARTS',
    '_call_flag_inputs',
    '_call_register_inputs',
    '_call_stack_inputs',
    '_external_arg_expr',
    '_external_call_args',
    '_external_call_contract',
    '_external_import_call_event',
    '_indirect_call_event',
    '_internal_call_event',
    '_is_supported_register_name',
    '_mem_address_expr',
    '_memory_epoch_expr',
    '_memory_expr',
    '_memory_read_expr',
    '_memory_write_expr',
    '_operand_expr',
    '_operand_width_bits',
    '_parse_external_stack_adjust',
    '_read_operand_expr',
    '_read_register_expr',
    '_stack_argument_writes',
    '_stack_relative_offset',
    '_write_operand_expr',
    '_write_register_expr',
    '_x87_binary',
    '_x87_memory_value',
    '_x87_operand_value',
    '_x87_pop',
    '_x87_push',
    '_x87_st_index',
    '_x87_store_memory',
]
