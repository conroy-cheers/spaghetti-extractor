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
    _coff_symbol_aliases_by_rva,
    _executable_section_for_rva,
    _parse_linker_map_functions,
    _parse_linker_map_symbol_line,
    _parse_stage_a_pe,
    _section_for_rva,
)
from ..extraction.cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    BlockMapping,
    _is_conditional_jump,
    _parse_int,
)

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

_STRING_INSTRUCTION_ENCODINGS: dict[bytes, tuple[str, int, bool]] = {
    b"\xa4": ("move", 1, False),
    b"\x66\xa5": ("move", 2, False),
    b"\xa5": ("move", 4, False),
    b"\xf3\xa4": ("move", 1, True),
    b"\xf3\x66\xa5": ("move", 2, True),
    b"\x66\xf3\xa5": ("move", 2, True),
    b"\xf3\xa5": ("move", 4, True),
    b"\xaa": ("store", 1, False),
    b"\x66\xab": ("store", 2, False),
    b"\xab": ("store", 4, False),
    b"\xf3\xaa": ("store", 1, True),
    b"\xf3\x66\xab": ("store", 2, True),
    b"\x66\xf3\xab": ("store", 2, True),
    b"\xf3\xab": ("store", 4, True),
    b"\xf2\xae": ("scan_not_equal", 1, True),
}
from .symbolic_expressions import (
    _bool_and,
    _bool_eq,
    _bool_not,
    _bool_xor,
    _canonical_expr,
    _expr_add,
    _expr_and,
    _expr_ashr,
    _expr_bool_bit,
    _expr_imul_high,
    _expr_imul_low,
    _expr_ite,
    _expr_lshr,
    _expr_mask,
    _expr_mul,
    _expr_mul_high,
    _expr_mul_low,
    _expr_neg,
    _expr_not,
    _expr_or,
    _expr_shift_pair,
    _expr_shl,
    _expr_sign_extend,
    _expr_sub,
)

from .symbolic_flags import (
    _arithmetic_flags,
    _branch_condition,
    _carry_arithmetic_flags,
    _logical_flags,
    _logical_result,
    _setcc_condition,
    _shift_flags,
    _undefined_arithmetic_flags,
    _undefined_bv,
)

from .symbolic_operands import (
    _external_call_args,
    _external_call_contract,
    _external_import_call_event,
    _indirect_call_event,
    _internal_call_event,
    _is_supported_register_name,
    _mem_address_expr,
    _memory_read_expr,
    _memory_write_expr,
    _operand_width_bits,
    _parse_external_stack_adjust,
    _read_operand_expr,
    _read_register_expr,
    _write_operand_expr,
    _write_register_expr,
    _x87_binary,
    _x87_operand_value,
    _x87_pop,
    _x87_push,
    _x87_st_index,
    _x87_store_memory,
)


class _InstructionTaggedEvents(list[tuple[Any, ...]]):
    def __init__(self, kind: str, ordered: list[tuple[str, int, tuple[Any, ...]]]) -> None:
        super().__init__()
        self.kind = kind
        self.ordered = ordered
        self.instruction_rva = 0

    def append(self, item: tuple[Any, ...]) -> None:
        super().append(item)
        self.ordered.append((self.kind, self.instruction_rva, item))

def _symbolic_execute(
    binary: StageABinary,
    side: BlockSide,
    data: bytes,
    binary_name: str,
    mapped: BlockMapping,
    *,
    external_call_index_base: int = 0,
) -> dict[str, Any]:
    if binary.bitness != 32:
        return {
            "status": "incomplete",
            "category": "unsupported_semantics",
            "blocker": "Stage A SMT symbolic execution is currently implemented only for x86 PE32 blocks",
            "next_action": "use a checked generated mapping proof or add x86_64 PE32+ symbolic semantics",
            "binary": binary_name,
            "bitness": binary.bitness,
        }
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    base = binary.image_base + side.rva_start
    registers = {name: ("reg", name) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")}
    flags = {name: ("flag", name) for name in ("cf", "zf", "sf", "of", "pf", "df")}
    fpu_stack: list[tuple[Any, ...]] = [("fpu_reg", index) for index in range(8)]
    fpu_control: tuple[Any, ...] = ("fpu_control",)
    fpu_status: tuple[Any, ...] = ("fpu_status",)
    fpu_touched = False
    outcome: tuple[Any, ...] = ("fallthrough", side.rva_end)
    ordered_events: list[tuple[str, int, tuple[Any, ...]]] = []
    memory_events = _InstructionTaggedEvents("memory", ordered_events)
    memory_writes: list[tuple[tuple[Any, ...], int, tuple[Any, ...]]] = []
    external_events = _InstructionTaggedEvents("external", ordered_events)
    fault_conditions = _InstructionTaggedEvents("fault", ordered_events)
    memory_epoch: int | None = None
    terminated = False

    instructions = list(dis.disasm(data, base))
    for insn in instructions:
        rva = int(insn.address - binary.image_base)
        memory_events.instruction_rva = rva
        external_events.instruction_rva = rva
        fault_conditions.instruction_rva = rva
        mnemonic = insn.mnemonic
        operands = insn.operands
        if terminated:
            return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "bytes after a modeled block terminator are not supported")

        if mnemonic == "nop":
            continue
        if mnemonic in {"jmp", "ljmp"}:
            imported_jump = _external_import_jump(binary, insn)
            if imported_jump is not None:
                event_index = external_call_index_base + len(external_events)
                external_events.append(
                    _external_import_call_event(
                        event_index,
                        imported_jump,
                        rva + int(insn.size),
                        registers,
                        flags,
                        memory_writes,
                        auto_inputs=True,
                    )
                )
                outcome = ("external_jump", imported_jump.dll, imported_jump.symbol, imported_jump.ordinal)
                terminated = True
                continue
            target = _resolved_branch_target(binary, insn)
            if target is None:
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "jump target is not resolved")
                target_expr = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                if target_expr is None:
                    return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "jump target expression is not modeled")
                if operands[0].type == X86_OP_MEM:
                    addressing = _abi_mem_operand_report(insn, operands[0])
                    table_contract = _abi_indexed_jump_table_contract(binary, side, instructions, insn, addressing)
                    if table_contract is not None and table_contract.get("evidence_status") == "derived":
                        outcome = ("indirect_jump_table", target_expr, table_contract)
                        terminated = True
                        continue
                outcome = ("indirect_jump", target_expr)
                terminated = True
                continue
            outcome = ("jump", target)
            terminated = True
            continue
        if _is_conditional_jump(mnemonic):
            target = _resolved_branch_target(binary, insn)
            if target is None:
                return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "direct conditional branch target is not resolved")
            condition = _branch_condition(mnemonic, flags)
            if condition is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "conditional branch predicate is not modeled")
            outcome = ("branch", condition, target, rva + int(insn.size))
            terminated = True
            continue
        if mnemonic == "call":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported call operand shape")
            imported = _external_import_call(binary, insn)
            if imported is not None:
                event_index = external_call_index_base + len(external_events)
                contract = _external_call_contract(mapped, event_index)
                if contract is None:
                    external_events.append(
                        _external_import_call_event(
                            event_index,
                            imported,
                            rva + int(insn.size),
                            registers,
                            flags,
                            memory_writes,
                            auto_inputs=True,
                        )
                    )
                    memory_writes.clear()
                    memory_epoch = event_index
                    for name in registers:
                        registers[name] = ("call_response", event_index, name)
                    for name in flags:
                        flags[name] = ("call_flag", event_index, name)
                    continue
                args = _external_call_args(insn, contract, registers, memory_events, memory_writes, memory_epoch=memory_epoch)
                if args is None:
                    return _symbolic_incomplete(
                        binary_name,
                        "unsupported_semantics",
                        rva,
                        mnemonic,
                        insn.op_str,
                        "external call argument contract is not supported",
                    )
                event = (
                    "external_call",
                    imported.dll,
                    imported.symbol,
                    imported.ordinal,
                    tuple(args),
                )
                external_events.append(event)
                registers["eax"] = ("env_response", event_index)
                stack_adjust = _parse_external_stack_adjust(contract)
                if stack_adjust:
                    registers["esp"] = _expr_add(registers["esp"], ("const", stack_adjust))
                continue
            target = _resolved_branch_target(binary, insn)
            if target is None:
                target_expr = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                if target_expr is None:
                    return _symbolic_incomplete(binary_name, "unknown_target", rva, mnemonic, insn.op_str, "indirect call target expression is not modeled")
                event_index = external_call_index_base + len(external_events)
                external_events.append(
                    _indirect_call_event(
                        event_index,
                        target_expr,
                        rva + int(insn.size),
                        registers,
                        flags,
                        memory_writes,
                    )
                )
                memory_writes.clear()
                memory_epoch = event_index
                for name in registers:
                    registers[name] = ("call_response", event_index, name)
                for name in flags:
                    flags[name] = ("call_flag", event_index, name)
                continue
            event_index = external_call_index_base + len(external_events)
            external_events.append(
                _internal_call_event(
                    event_index,
                    target,
                    rva + int(insn.size),
                    registers,
                    flags,
                    memory_writes,
                )
            )
            memory_writes.clear()
            memory_epoch = event_index
            for name in registers:
                registers[name] = ("call_response", event_index, name)
            for name in flags:
                flags[name] = ("call_flag", event_index, name)
            continue
        if mnemonic == "ret":
            if len(operands) > 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported ret operand shape")
            stack_adjust = 4
            if len(operands) == 1:
                if operands[0].type != X86_OP_IMM:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported ret operand")
                stack_adjust += int(operands[0].imm) & 0xFFFFFFFF
            outcome = ("return", _memory_read_expr(registers["esp"], memory_events, memory_writes, memory_epoch=memory_epoch))
            registers["esp"] = _expr_add(registers["esp"], ("const", stack_adjust))
            terminated = True
            continue
        if mnemonic == "leave":
            frame = registers["ebp"]
            registers["ebp"] = _memory_read_expr(
                frame,
                memory_events,
                memory_writes,
                memory_epoch=memory_epoch,
            )
            registers["esp"] = _expr_add(frame, ("const", 4))
            continue
        if mnemonic in {"clc", "cld", "std"}:
            if mnemonic == "clc":
                flags["cf"] = ("false",)
            else:
                flags["df"] = ("true",) if mnemonic == "std" else ("false",)
            continue
        if mnemonic == "mov":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov operand shape")
            if operands[0].type == X86_OP_REG:
                dst = insn.reg_name(operands[0].reg)
                width_bits = _operand_width_bits(insn, operands[0])
                src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
                if src is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov source operand")
                if not _write_register_expr(dst, src, registers):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov destination register")
                continue
            if operands[0].type == X86_OP_MEM:
                width_bits = _operand_width_bits(insn, operands[0])
                address = _mem_address_expr(insn, operands[0], registers)
                value = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
                if address is None or value is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov memory write operand")
                _memory_write_expr(address, width_bits, value, memory_events, memory_writes)
                continue
            return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mov destination operand")
        if mnemonic in {"movzx", "movsx"}:
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported movzx/movsx operand shape")
            dst = insn.reg_name(operands[0].reg)
            src_width = _operand_width_bits(insn, operands[1])
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=src_width, memory_epoch=memory_epoch)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported movzx/movsx source operand")
            value = _expr_mask(src, src_width) if mnemonic == "movzx" else _expr_sign_extend(src, src_width)
            if not _write_register_expr(dst, value, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported movzx/movsx destination register")
            continue
        if mnemonic == "push":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported push operand shape")
            value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, memory_epoch=memory_epoch)
            if value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported push operand")
            new_esp = _expr_sub(registers["esp"], ("const", 4))
            _memory_write_expr(new_esp, 32, value, memory_events, memory_writes)
            registers["esp"] = new_esp
            continue
        if mnemonic in {"pushal", "pushad"}:
            original_esp = registers["esp"]
            saved = (
                registers["eax"],
                registers["ecx"],
                registers["edx"],
                registers["ebx"],
                original_esp,
                registers["ebp"],
                registers["esi"],
                registers["edi"],
            )
            for index, value in enumerate(saved, start=1):
                address = _expr_sub(original_esp, ("const", 4 * index))
                _memory_write_expr(address, 32, value, memory_events, memory_writes)
            registers["esp"] = _expr_sub(original_esp, ("const", 32))
            continue
        if mnemonic == "pop":
            if len(operands) != 1 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination pop is modeled")
            if _operand_width_bits(insn, operands[0]) != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit pop destinations are modeled")
            stack = registers["esp"]
            value = _memory_read_expr(stack, memory_events, memory_writes, memory_epoch=memory_epoch)
            registers["esp"] = _expr_add(stack, ("const", 4))
            if operands[0].type == X86_OP_REG:
                dst = insn.reg_name(operands[0].reg)
                if not _is_supported_register_name(dst) or not _write_register_expr(dst, value, registers):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported pop destination register")
                continue
            if not _write_operand_expr(
                insn,
                operands[0],
                value,
                registers,
                memory_events,
                memory_writes,
                width_bits=32,
            ):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported pop destination memory")
            continue
        if mnemonic in {"add", "sub"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination arithmetic is modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported arithmetic source operand")
            result = _expr_add(left, src) if mnemonic == "add" else _expr_sub(left, src)
            result = _expr_mask(result, width_bits)
            flags.update(_arithmetic_flags(mnemonic, left, src, result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported arithmetic destination operand")
            continue
        if mnemonic in {"inc", "dec"}:
            if len(operands) != 1 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination unary arithmetic is modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits not in {8, 16, 32}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 8/16/32-bit inc/dec is modeled")
            value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported inc/dec destination operand")
            operation = "add" if mnemonic == "inc" else "sub"
            one = ("const", 1)
            result = (
                _expr_add(value, one)
                if mnemonic == "inc"
                else _expr_sub(value, one)
            )
            result = _expr_mask(result, width_bits)
            updated_flags = _arithmetic_flags(
                operation,
                value,
                one,
                result,
                width_bits=width_bits,
            )
            updated_flags.pop("cf")
            flags.update(updated_flags)
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported inc/dec destination operand")
            continue
        if mnemonic in {"adc", "sbb"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination carry arithmetic is modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported carry arithmetic source operand")
            carry_bit = _expr_bool_bit(flags["cf"])
            if mnemonic == "adc":
                result = _expr_add(_expr_add(left, src), carry_bit)
            else:
                result = _expr_sub(_expr_sub(left, src), carry_bit)
            result = _expr_mask(result, width_bits)
            flags.update(_carry_arithmetic_flags(mnemonic, left, src, flags["cf"], result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported carry arithmetic destination operand")
            continue
        if mnemonic == "imul":
            if len(operands) == 1:
                width_bits = _operand_width_bits(insn, operands[0])
                if width_bits != 32:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit one-operand imul is modeled")
                src = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                if src is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul source operand")
                left = registers["eax"]
                low = _expr_imul_low(left, src)
                high = _expr_imul_high(left, src)
                registers["eax"] = low
                registers["edx"] = high
                flags.update(_undefined_arithmetic_flags("imul", rva, keep={"cf": ("imul_overflow", 32, left, src, low, high), "of": ("imul_overflow", 32, left, src, low, high)}))
                continue
            if len(operands) in {2, 3} and operands[0].type == X86_OP_REG:
                width_bits = _operand_width_bits(insn, operands[0])
                if width_bits != 32:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit imul destinations are modeled")
                dst = insn.reg_name(operands[0].reg)
                left = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                right = _read_operand_expr(insn, operands[2], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch) if len(operands) == 3 else _read_register_expr(dst, registers)
                if left is None or right is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul operand")
                result = _expr_imul_low(left, right)
                if not _write_register_expr(dst, result, registers):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul destination register")
                flags.update(_undefined_arithmetic_flags("imul", rva, keep={"cf": ("imul_overflow", 32, left, right, result, _expr_imul_high(left, right)), "of": ("imul_overflow", 32, left, right, result, _expr_imul_high(left, right))}))
                continue
            return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported imul operand shape")
        if mnemonic == "mul":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mul operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit mul is modeled")
            src = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported mul source operand")
            left = registers["eax"]
            low = _expr_mul_low(left, src)
            high = _expr_mul_high(left, src)
            registers["eax"] = low
            registers["edx"] = high
            carry = ("mul_carry", 32, left, src, high)
            flags.update(_undefined_arithmetic_flags("mul", rva, keep={"cf": carry, "of": carry}))
            continue
        if mnemonic == "div":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported div operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit div is modeled")
            divisor = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            if divisor is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported div source operand")
            dividend_high = registers["edx"]
            dividend_low = registers["eax"]
            valid = ("udiv_valid", dividend_high, dividend_low, divisor)
            registers["eax"] = _expr_ite(
                valid,
                ("udiv_quot", dividend_high, dividend_low, divisor),
                ("undefined_bv", "div_fault", f"0x{rva:x}:eax"),
            )
            registers["edx"] = _expr_ite(
                valid,
                ("udiv_rem", dividend_high, dividend_low, divisor),
                ("undefined_bv", "div_fault", f"0x{rva:x}:edx"),
            )
            flags.update(_undefined_arithmetic_flags("div", rva))
            fault_conditions.append(("divide_error", _bool_not(valid), rva))
            continue
        if mnemonic == "idiv":
            if len(operands) != 1:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported idiv operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit idiv is modeled")
            divisor = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            if divisor is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported idiv source operand")
            high = registers["edx"]
            low = registers["eax"]
            dividend_negative = ("msb_w", 32, high)
            divisor_negative = ("msb_w", 32, divisor)
            absolute_low = _expr_ite(
                dividend_negative,
                _expr_add(_expr_not(low), ("const", 1)),
                low,
            )
            low_carry = _expr_ite(_bool_eq(low, ("const", 0)), ("const", 1), ("const", 0))
            absolute_high = _expr_ite(
                dividend_negative,
                _expr_add(_expr_not(high), low_carry),
                high,
            )
            absolute_divisor = _expr_ite(
                divisor_negative,
                _expr_sub(("const", 0), divisor),
                divisor,
            )
            quotient_magnitude = ("udiv_quot", absolute_high, absolute_low, absolute_divisor)
            remainder_magnitude = ("udiv_rem", absolute_high, absolute_low, absolute_divisor)
            quotient_negative = _bool_xor(dividend_negative, divisor_negative)
            quotient_bound = _expr_ite(
                quotient_negative,
                ("const", 0x80000001),
                ("const", 0x80000000),
            )
            valid = _bool_and(
                ("udiv_valid", absolute_high, absolute_low, absolute_divisor),
                ("ult", quotient_magnitude, quotient_bound),
            )
            signed_quotient = _expr_ite(
                quotient_negative,
                _expr_sub(("const", 0), quotient_magnitude),
                quotient_magnitude,
            )
            signed_remainder = _expr_ite(
                dividend_negative,
                _expr_sub(("const", 0), remainder_magnitude),
                remainder_magnitude,
            )
            registers["eax"] = _expr_ite(valid, signed_quotient, ("undefined_bv", "idiv_fault", f"0x{rva:x}:eax"))
            registers["edx"] = _expr_ite(valid, signed_remainder, ("undefined_bv", "idiv_fault", f"0x{rva:x}:edx"))
            flags.update(_undefined_arithmetic_flags("idiv", rva))
            fault_conditions.append(("divide_error", _bool_not(valid), rva))
            continue
        if mnemonic == "cdq":
            if operands:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cdq operand shape")
            registers["edx"] = _expr_ite(("msb_w", 32, registers["eax"]), ("const", 0xFFFFFFFF), ("const", 0))
            continue
        if mnemonic == "cwde":
            if operands:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cwde operand shape")
            registers["eax"] = _expr_sign_extend(_read_register_expr("ax", registers) or ("const", 0), 16)
            continue
        if mnemonic == "cmp":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmp operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmp operand")
            flags.update(_arithmetic_flags("sub", left, right, _expr_sub(left, right), width_bits=width_bits))
            continue
        if mnemonic in {"xor", "and", "or"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register/memory-destination logical operations are modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported logical source operand")
            result = _logical_result(mnemonic, left, src)
            result = _expr_mask(result, width_bits)
            flags.update(_logical_flags(result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported logical destination operand")
            continue
        if mnemonic == "test":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported test operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported test operand")
            flags.update(_logical_flags(_expr_and(left, right), width_bits=width_bits))
            continue
        if mnemonic == "lea":
            if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type != X86_OP_MEM:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea operand shape")
            dst = insn.reg_name(operands[0].reg)
            if not _is_supported_register_name(dst):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            src = _mem_address_expr(insn, operands[1], registers)
            if src is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea address expression")
            if not _write_register_expr(dst, src, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported lea destination register")
            continue
        if mnemonic in {"shl", "sal", "shr", "sar"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported shift operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            count = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=8, memory_epoch=memory_epoch)
            if left is None or count is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported shift operand")
            count = _expr_and(count, ("const", 0x1F))
            if mnemonic in {"shl", "sal"}:
                result = _expr_shl(left, count)
            elif mnemonic == "shr":
                result = _expr_lshr(left, count)
            else:
                result = _expr_ashr(_expr_mask(left, width_bits), count, width_bits)
            result = _expr_mask(result, width_bits)
            flags.update(
                _shift_flags(
                    mnemonic,
                    left,
                    count,
                    result,
                    flags,
                    rva=rva,
                    width_bits=width_bits,
                )
            )
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported shift destination operand")
            continue
        if mnemonic == "rcr":
            if (
                len(operands) != 2
                or operands[0].type not in {X86_OP_REG, X86_OP_MEM}
                or operands[1].type != X86_OP_IMM
                or (int(operands[1].imm) & 0x1F) != 1
            ):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit rcr destinations with an immediate count of one are modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit rcr destinations are modeled")
            value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            if value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported rcr destination operand")
            result = _expr_or(
                _expr_lshr(value, ("const", 1)),
                _expr_shl(_expr_bool_bit(flags["cf"]), ("const", 31)),
            )
            result = _expr_mask(result, 32)
            flags["cf"] = _bool_eq(_expr_and(value, ("const", 1)), ("const", 1))
            flags["of"] = _bool_xor(
                ("msb_w", 32, result),
                _bool_eq(
                    _expr_and(_expr_lshr(result, ("const", 30)), ("const", 1)),
                    ("const", 1),
                ),
            )
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=32):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported rcr destination operand")
            continue
        if mnemonic in {"shld", "shrd"}:
            if len(operands) != 3 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported double-shift operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            count = _read_operand_expr(insn, operands[2], registers, memory_events, memory_writes, width_bits=8, memory_epoch=memory_epoch)
            if left is None or right is None or count is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported double-shift operand")
            count = _expr_and(count, ("const", 0x1F))
            result = _expr_shift_pair(mnemonic, left, right, count, width_bits)
            flags.update(
                _shift_flags(
                    mnemonic,
                    left,
                    count,
                    result,
                    flags,
                    rva=rva,
                    width_bits=width_bits,
                )
            )
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported double-shift destination operand")
            continue
        if mnemonic in {"bsr", "tzcnt"}:
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported bit-scan operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit bit-scan destinations are modeled")
            dst = insn.reg_name(operands[0].reg)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            current = _read_register_expr(dst, registers)
            if src is None or current is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported bit-scan operand")
            if mnemonic == "bsr":
                result = _expr_ite(
                    ("eq", src, ("const", 0)),
                    _undefined_bv("bsr-zero-source", rva, dst, current),
                    ("bsr_index", 32, src),
                )
                flags.update(_undefined_arithmetic_flags("bsr", rva, keep={"zf": ("eq", src, ("const", 0))}))
            else:
                result = ("tzcnt", 32, src)
                flags.update(_undefined_arithmetic_flags("tzcnt", rva, keep={"cf": ("eq", src, ("const", 0)), "zf": ("eq", result, ("const", 0))}))
            if not _write_register_expr(dst, result, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported bit-scan destination register")
            continue
        string_instruction = _STRING_INSTRUCTION_ENCODINGS.get(bytes(insn.bytes))
        if string_instruction is not None and string_instruction[0] == "move":
            _, width_bytes, repeated = string_instruction
            if repeated:
                event_index = external_call_index_base + len(external_events)
                df = flags.get("df", ("flag", "df"))
                external_events.append(
                    (
                        "rep_movs",
                        event_index,
                        width_bytes,
                        32,
                        registers["edi"],
                        registers["esi"],
                        registers["ecx"],
                        df,
                    )
                )
                delta = _expr_mul(registers["ecx"], ("const", width_bytes))
                signed_delta = _expr_ite(df, _expr_neg(delta), delta)
                registers["edi"] = _expr_add(registers["edi"], signed_delta)
                registers["esi"] = _expr_add(registers["esi"], signed_delta)
                registers["ecx"] = ("const", 0)
                memory_writes.clear()
                memory_epoch = event_index
                continue
            step = _expr_ite(
                flags.get("df", ("flag", "df")),
                ("const", (-width_bytes) & 0xFFFFFFFF),
                ("const", width_bytes),
            )
            src_address = registers["esi"]
            dst_address = registers["edi"]
            value = _memory_read_expr(
                src_address,
                memory_events,
                memory_writes,
                width_bits=width_bytes * 8,
                memory_epoch=memory_epoch,
            )
            _memory_write_expr(
                dst_address,
                width_bytes * 8,
                value,
                memory_events,
                memory_writes,
            )
            src_address = _expr_add(src_address, step)
            dst_address = _expr_add(dst_address, step)
            registers["esi"] = src_address
            registers["edi"] = dst_address
            continue
        if string_instruction is not None and string_instruction[0] == "store":
            _, width_bytes, repeated = string_instruction
            value = _read_register_expr(
                {1: "al", 2: "ax", 4: "eax"}[width_bytes], registers
            )
            if value is None:
                return _symbolic_incomplete(
                    binary_name,
                    "unsupported_semantics",
                    rva,
                    mnemonic,
                    insn.op_str,
                    "string-store accumulator value is not modeled",
                )
            if repeated:
                event_index = external_call_index_base + len(external_events)
                df = flags.get("df", ("flag", "df"))
                external_events.append(
                    (
                        "rep_stos",
                        event_index,
                        width_bytes,
                        32,
                        registers["edi"],
                        value,
                        registers["ecx"],
                        df,
                    )
                )
                delta = _expr_mul(registers["ecx"], ("const", width_bytes))
                signed_delta = _expr_ite(df, _expr_neg(delta), delta)
                registers["edi"] = _expr_add(registers["edi"], signed_delta)
                registers["ecx"] = ("const", 0)
                memory_writes.clear()
                memory_epoch = event_index
                continue
            step = _expr_ite(
                flags.get("df", ("flag", "df")),
                ("const", (-width_bytes) & 0xFFFFFFFF),
                ("const", width_bytes),
            )
            dst_address = registers["edi"]
            _memory_write_expr(
                dst_address,
                width_bytes * 8,
                value,
                memory_events,
                memory_writes,
            )
            dst_address = _expr_add(dst_address, step)
            registers["edi"] = dst_address
            continue
        if string_instruction == ("scan_not_equal", 1, True):
            accumulator = _read_register_expr("al", registers)
            if accumulator is None:
                return _symbolic_incomplete(
                    binary_name,
                    "unsupported_semantics",
                    rva,
                    mnemonic,
                    insn.op_str,
                    "string-scan accumulator value is not modeled",
                )
            event_index = external_call_index_base + len(external_events)
            external_events.append(
                (
                    "rep_scas",
                    event_index,
                    1,
                    32,
                    registers["edi"],
                    accumulator,
                    registers["ecx"],
                    flags.get("df", ("flag", "df")),
                )
            )
            # The restartable scan action owns EDI, ECX, and all comparison
            # flags.  Its result depends on the first matching memory byte, so
            # no ordinary expression-tree write may replace those outputs.
            continue
        if mnemonic in {"cmpxchg", "lock cmpxchg"}:
            if len(operands) != 2 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            dst_value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            src_value = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            eax_value = _read_register_expr("eax", registers)
            if dst_value is None or src_value is None or eax_value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg operand")
            compare_left = _expr_mask(eax_value, width_bits)
            compare_right = _expr_mask(dst_value, width_bits)
            equal = ("eq", compare_left, compare_right)
            flags.update(_arithmetic_flags("sub", compare_left, compare_right, _expr_sub(compare_left, compare_right), width_bits=width_bits))
            flags["zf"] = equal
            if not _write_operand_expr(insn, operands[0], _expr_ite(equal, src_value, dst_value), registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg destination")
            if not _write_register_expr("eax", _expr_ite(equal, eax_value, dst_value), registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmpxchg eax update")
            continue
        if mnemonic == "wait":
            continue
        if mnemonic in {
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
        }:
            fpu_touched = True
            if mnemonic == "fninit":
                fpu_stack = [("fpu_reg", index) for index in range(8)]
                fpu_control = ("fpu_control_init",)
                fpu_status = ("fpu_status_init",)
                continue
            if mnemonic in {"fclex", "fnclex"}:
                if operands:
                    return _symbolic_incomplete(
                        binary_name,
                        "unsupported_semantics",
                        rva,
                        mnemonic,
                        insn.op_str,
                        "x87 clear-exception instructions take no operands",
                    )
                fpu_status = (
                    "fpu_clear_exceptions",
                    _canonical_expr(fpu_status),
                )
                continue
            if mnemonic == "fld1":
                _x87_push(fpu_stack, ("fpu_const", "1"))
                continue
            if mnemonic == "fldz":
                _x87_push(fpu_stack, ("fpu_const", "0"))
                continue
            if mnemonic in {"fld", "fild"}:
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 load operand shape")
                value = _x87_operand_value(
                    insn,
                    operands[0],
                    registers,
                    memory_events,
                    memory_writes,
                    fpu_stack,
                    memory_epoch=memory_epoch,
                    integer=mnemonic == "fild",
                )
                if value is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 load operand")
                _x87_push(fpu_stack, value)
                continue
            if mnemonic in {"fst", "fstp", "fist", "fistp", "fisttp"}:
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 store operand shape")
                value = fpu_stack[0]
                if operands[0].type == X86_OP_MEM:
                    if not _x87_store_memory(
                        insn,
                        operands[0],
                        value,
                        fpu_control,
                        registers,
                        memory_events,
                        memory_writes,
                        integer=mnemonic in {"fist", "fistp", "fisttp"},
                    ):
                        return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 memory store")
                else:
                    index = _x87_st_index(insn.op_str)
                    if index is None or index >= len(fpu_stack):
                        return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 register store")
                    fpu_stack[index] = value
                if mnemonic in {"fstp", "fistp", "fisttp"}:
                    _x87_pop(fpu_stack)
                continue
            if mnemonic in {
                "fadd",
                "fsub",
                "fsubr",
                "fmul",
                "fdiv",
                "fdivr",
                "fiadd",
                "fisub",
                "fisubr",
                "fimul",
                "fidiv",
                "fidivr",
            }:
                value = fpu_stack[0]
                if operands:
                    value = _x87_operand_value(
                        insn,
                        operands[0],
                        registers,
                        memory_events,
                        memory_writes,
                        fpu_stack,
                        memory_epoch=memory_epoch,
                        integer=mnemonic.startswith("fi"),
                    )
                    if value is None:
                        return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 arithmetic operand")
                op = mnemonic[2:] if mnemonic.startswith("fi") else mnemonic[1:]
                if mnemonic in {"fsubr", "fdivr", "fisubr", "fidivr"}:
                    fpu_stack[0] = _x87_binary(op, value, fpu_stack[0])
                else:
                    fpu_stack[0] = _x87_binary(op, fpu_stack[0], value)
                continue
            if mnemonic in {"faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp"}:
                index = _x87_st_index(insn.op_str) if insn.op_str else 1
                if index is None or index <= 0 or index >= len(fpu_stack):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 pop arithmetic operand")
                base_op = mnemonic[1:].removesuffix("p")
                if mnemonic in {"fsubrp", "fdivrp"}:
                    fpu_stack[index] = _x87_binary(base_op, fpu_stack[0], fpu_stack[index])
                else:
                    fpu_stack[index] = _x87_binary(base_op, fpu_stack[index], fpu_stack[0])
                _x87_pop(fpu_stack)
                continue
            if mnemonic == "fxch":
                index = _x87_st_index(insn.op_str)
                if index is None or index >= len(fpu_stack):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fxch operand")
                fpu_stack[0], fpu_stack[index] = fpu_stack[index], fpu_stack[0]
                continue
            if mnemonic == "fchs":
                fpu_stack[0] = ("fpu_neg", _canonical_expr(fpu_stack[0]))
                continue
            if mnemonic in {"fsin", "fcos"}:
                fpu_stack[0] = (
                    f"fpu_{mnemonic[1:]}",
                    _canonical_expr(fpu_stack[0]),
                    _canonical_expr(fpu_control),
                )
                fpu_status = (
                    "fpu_transcendental_status",
                    mnemonic,
                    _canonical_expr(fpu_status),
                    _canonical_expr(fpu_stack[0]),
                )
                continue
            if mnemonic == "fxam":
                fpu_status = ("fpu_fxam", _canonical_expr(fpu_stack[0]))
                continue
            if mnemonic == "fnstcw":
                if len(operands) != 1 or operands[0].type != X86_OP_MEM:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fnstcw operand")
                address = _mem_address_expr(insn, operands[0], registers)
                if address is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fnstcw address")
                _memory_write_expr(address, 16, ("fpu_control_word", fpu_control), memory_events, memory_writes)
                continue
            if mnemonic == "fldcw":
                if len(operands) != 1:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fldcw operand")
                value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=16, memory_epoch=memory_epoch)
                if value is None:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fldcw source")
                fpu_control = ("fpu_control_load", value)
                continue
            if mnemonic == "fnstsw":
                if insn.op_str.strip().lower() != "ax":
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only fnstsw ax is modeled")
                if not _write_register_expr("ax", ("fpu_status_word", fpu_status), registers):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported fnstsw destination")
                continue
            if mnemonic in {"fcom", "fcomp", "ficom", "ficomp"}:
                if len(operands) != 1:
                    return _symbolic_incomplete(
                        binary_name,
                        "unsupported_semantics",
                        rva,
                        mnemonic,
                        insn.op_str,
                        "unsupported x87 status-compare operand shape",
                    )
                right = _x87_operand_value(
                    insn,
                    operands[0],
                    registers,
                    memory_events,
                    memory_writes,
                    fpu_stack,
                    memory_epoch=memory_epoch,
                    integer=mnemonic.startswith("fi"),
                )
                if right is None:
                    return _symbolic_incomplete(
                        binary_name,
                        "unsupported_semantics",
                        rva,
                        mnemonic,
                        insn.op_str,
                        "unsupported x87 status-compare operand",
                    )
                fpu_status = (
                    "fpu_compare_status",
                    "ordered",
                    _canonical_expr(fpu_status),
                    _canonical_expr(fpu_stack[0]),
                    _canonical_expr(right),
                )
                if mnemonic in {"fcomp", "ficomp"}:
                    _x87_pop(fpu_stack)
                continue
            if mnemonic in {"fcomi", "fcomip", "fucomi", "fucomip", "fcompi", "fucompi"}:
                index = _x87_st_index(insn.op_str) if insn.op_str else 1
                if index is None or index >= len(fpu_stack):
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 compare operand")
                left = _canonical_expr(fpu_stack[0])
                right = _canonical_expr(fpu_stack[index])
                flags["cf"] = ("fpu_cmp_cf", left, right)
                flags["zf"] = ("fpu_cmp_zf", left, right)
                flags["pf"] = ("fpu_cmp_pf", left, right)
                flags["of"] = ("false",)
                flags["sf"] = ("false",)
                if mnemonic in {"fcomip", "fucomip", "fcompi", "fucompi"}:
                    _x87_pop(fpu_stack)
                continue
        if mnemonic in {"not", "neg"}:
            if len(operands) != 1 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported unary operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if value is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported unary operand")
            result = _expr_mask(_expr_not(value) if mnemonic == "not" else _expr_neg(value), width_bits)
            if mnemonic == "neg":
                flags.update(_arithmetic_flags("sub", ("const", 0), value, result, width_bits=width_bits))
            if not _write_operand_expr(insn, operands[0], result, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported unary destination operand")
            continue
        if mnemonic == "bt":
            if len(operands) != 2 or operands[0].type != X86_OP_REG or operands[1].type not in {X86_OP_REG, X86_OP_IMM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register-base bt with register/immediate index is modeled")
            width_bits = _operand_width_bits(insn, operands[0])
            if width_bits != 32:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit register-base bt is modeled")
            base_value = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            bit_index = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
            if base_value is None or bit_index is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported bt operand")
            selected = _expr_and(
                _expr_lshr(base_value, _expr_and(bit_index, ("const", 0x1F))),
                ("const", 1),
            )
            flags.update(_undefined_arithmetic_flags(
                "bt",
                rva,
                keep={"cf": _bool_eq(selected, ("const", 1))},
            ))
            continue
        if mnemonic.startswith("set"):
            if len(operands) != 1 or operands[0].type not in {X86_OP_REG, X86_OP_MEM}:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported setcc operand shape")
            condition = _setcc_condition(mnemonic, flags)
            if condition is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported setcc condition")
            value = _expr_ite(condition, ("const", 1), ("const", 0))
            if not _write_operand_expr(insn, operands[0], value, registers, memory_events, memory_writes, width_bits=8):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported setcc destination operand")
            continue
        if mnemonic.startswith("cmov"):
            if len(operands) != 2 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmovcc operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            dst = insn.reg_name(operands[0].reg)
            current = _read_register_expr(dst, registers)
            src = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            condition = _setcc_condition("set" + mnemonic[4:], flags)
            if current is None or src is None or condition is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmovcc operand")
            if not _write_register_expr(dst, _expr_ite(condition, src, current), registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported cmovcc destination register")
            continue
        if mnemonic == "xchg":
            if len(operands) != 2:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg operand shape")
            width_bits = _operand_width_bits(insn, operands[0])
            left = _read_operand_expr(insn, operands[0], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            right = _read_operand_expr(insn, operands[1], registers, memory_events, memory_writes, width_bits=width_bits, memory_epoch=memory_epoch)
            if left is None or right is None:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg operand")
            if not _write_operand_expr(insn, operands[0], right, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg first destination")
            if not _write_operand_expr(insn, operands[1], left, registers, memory_events, memory_writes, width_bits=width_bits):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported xchg second destination")
            continue

        return _symbolic_incomplete(
            binary_name,
            "unsupported_semantics",
            rva,
            mnemonic,
            insn.op_str,
            f"instruction {mnemonic} is not modeled by normalized_symbolic_equivalence_v1",
        )

    observables = {f"reg:{name}": _canonical_expr(registers[name]) for name in sorted(registers)}
    for name in sorted(flags):
        observables[f"flag:{name}"] = _canonical_expr(flags[name])
    observables["outcome"] = _canonical_expr(outcome)
    observables["memory_events"] = tuple(_canonical_expr(event) for event in memory_events)
    observables["external_events"] = tuple(_canonical_expr(event) for event in external_events)
    observables["fault_conditions"] = tuple(_canonical_expr(fault) for fault in fault_conditions)
    if fpu_touched:
        observables["fpu_stack"] = tuple(_canonical_expr(item) for item in fpu_stack)
        observables["fpu_control"] = _canonical_expr(fpu_control)
        observables["fpu_status"] = _canonical_expr(fpu_status)
    return {"status": "ok", "observables": observables, "ordered_events": tuple(ordered_events)}

def _import_z3() -> Any | None:
    try:
        return import_module("z3")
    except ImportError:
        return None

def _symbolic_incomplete(binary_name: str, category: str, rva: int, mnemonic: str, op_str: str, blocker: str) -> dict[str, Any]:
    return {
        "status": "incomplete",
        "category": category,
        "binary": binary_name,
        "blocker": f"{blocker} at RVA 0x{rva:x}",
        "next_action": "add instruction semantics, an invariant lemma, or mark this block out of model",
        "instruction": {"rva": rva, "mnemonic": mnemonic, "op_str": op_str},
    }

__all__ = [
    '_InstructionTaggedEvents',
    '_import_z3',
    '_symbolic_execute',
    '_symbolic_incomplete',
]
