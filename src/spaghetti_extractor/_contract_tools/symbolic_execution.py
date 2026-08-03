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

from ..stage_binary import (
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
from ..relational.semantic_cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    BlockMapping,
    _is_conditional_jump,
    _parse_int,
)

from .map_generation import (
    _capstone_mode,
    _external_import_call,
    _external_import_jump,
    _resolved_branch_target,
)

from .abi import (
    _abi_indexed_jump_table_contract,
    _abi_mem_operand_report,
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
        if mnemonic == "pop":
            if len(operands) != 1 or operands[0].type != X86_OP_REG:
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only register-destination pop is modeled")
            dst = insn.reg_name(operands[0].reg)
            if not _is_supported_register_name(dst):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "only 32-bit general registers are modeled")
            value = _memory_read_expr(registers["esp"], memory_events, memory_writes, memory_epoch=memory_epoch)
            if not _write_register_expr(dst, value, registers):
                return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported pop destination register")
            registers["esp"] = _expr_add(registers["esp"], ("const", 4))
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
        if mnemonic in {"movsd", "rep movsd"}:
            count = 1
            if mnemonic == "rep movsd":
                ecx_value = _canonical_expr(registers["ecx"])
                if not (isinstance(ecx_value, tuple) and len(ecx_value) == 2 and ecx_value[0] == "const"):
                    event_index = external_call_index_base + len(external_events)
                    df = flags.get("df", ("flag", "df"))
                    external_events.append(("rep_movsd", event_index, registers["edi"], registers["esi"], registers["ecx"], df))
                    delta = _expr_mul(registers["ecx"], ("const", 4))
                    signed_delta = _expr_ite(df, _expr_neg(delta), delta)
                    registers["edi"] = _expr_add(registers["edi"], signed_delta)
                    registers["esi"] = _expr_add(registers["esi"], signed_delta)
                    registers["ecx"] = ("const", 0)
                    memory_writes.clear()
                    memory_epoch = event_index
                    continue
                count = int(ecx_value[1])
                if count < 0 or count > 64:
                    return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "rep movsd count is outside the bounded static unroll limit")
            step = _expr_ite(flags.get("df", ("flag", "df")), ("const", 0xFFFFFFFC), ("const", 4))
            src_address = registers["esi"]
            dst_address = registers["edi"]
            for _ in range(count):
                value = _memory_read_expr(src_address, memory_events, memory_writes, width_bits=32, memory_epoch=memory_epoch)
                _memory_write_expr(dst_address, 32, value, memory_events, memory_writes)
                src_address = _expr_add(src_address, step)
                dst_address = _expr_add(dst_address, step)
            registers["esi"] = src_address
            registers["edi"] = dst_address
            if mnemonic == "rep movsd":
                registers["ecx"] = ("const", 0)
            continue
        if mnemonic == "rep stosd":
            ecx_value = _canonical_expr(registers["ecx"])
            if (
                isinstance(ecx_value, tuple)
                and len(ecx_value) == 2
                and ecx_value[0] == "const"
                and 0 <= int(ecx_value[1]) <= 64
            ):
                count = int(ecx_value[1])
                step = _expr_ite(
                    flags.get("df", ("flag", "df")),
                    ("const", 0xFFFFFFFC),
                    ("const", 4),
                )
                dst_address = registers["edi"]
                for _ in range(count):
                    _memory_write_expr(
                        dst_address,
                        32,
                        registers["eax"],
                        memory_events,
                        memory_writes,
                    )
                    dst_address = _expr_add(dst_address, step)
                registers["edi"] = dst_address
                registers["ecx"] = ("const", 0)
                continue

            event_index = external_call_index_base + len(external_events)
            df = flags.get("df", ("flag", "df"))
            external_events.append(
                (
                    "rep_stosd",
                    event_index,
                    registers["edi"],
                    registers["eax"],
                    registers["ecx"],
                    df,
                )
            )
            delta = _expr_mul(registers["ecx"], ("const", 4))
            signed_delta = _expr_ite(df, _expr_neg(delta), delta)
            registers["edi"] = _expr_add(registers["edi"], signed_delta)
            registers["ecx"] = ("const", 0)
            memory_writes.clear()
            memory_epoch = event_index
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
            "fcomi",
            "fcomip",
            "fucomi",
            "fucomip",
            "fcompi",
            "fucompi",
            "fninit",
        }:
            fpu_touched = True
            if mnemonic == "fninit":
                fpu_stack = [("fpu_reg", index) for index in range(8)]
                fpu_control = ("fpu_control_init",)
                fpu_status = ("fpu_status_init",)
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
            if mnemonic in {"fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr"}:
                value = fpu_stack[0]
                if operands:
                    value = _x87_operand_value(insn, operands[0], registers, memory_events, memory_writes, fpu_stack, memory_epoch=memory_epoch)
                    if value is None:
                        return _symbolic_incomplete(binary_name, "unsupported_semantics", rva, mnemonic, insn.op_str, "unsupported x87 arithmetic operand")
                op = mnemonic[1:]
                if mnemonic in {"fsubr", "fdivr"}:
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

def _branch_condition(mnemonic: str, flags: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    cf = flags["cf"]
    zf = flags["zf"]
    sf = flags["sf"]
    of = flags["of"]
    pf = flags.get("pf", ("flag", "pf"))
    conditions = {
        "ja": _bool_and(_bool_not(cf), _bool_not(zf)),
        "jnbe": _bool_and(_bool_not(cf), _bool_not(zf)),
        "jae": _bool_not(cf),
        "jnb": _bool_not(cf),
        "jnc": _bool_not(cf),
        "jb": cf,
        "jc": cf,
        "jnae": cf,
        "jbe": _bool_or(cf, zf),
        "jna": _bool_or(cf, zf),
        "je": zf,
        "jz": zf,
        "jne": _bool_not(zf),
        "jnz": _bool_not(zf),
        "jg": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "jnle": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "jge": _bool_eq(sf, of),
        "jnl": _bool_eq(sf, of),
        "jl": _bool_xor(sf, of),
        "jnge": _bool_xor(sf, of),
        "jle": _bool_or(zf, _bool_xor(sf, of)),
        "jng": _bool_or(zf, _bool_xor(sf, of)),
        "jno": _bool_not(of),
        "jo": of,
        "jp": pf,
        "jpe": pf,
        "jnp": _bool_not(pf),
        "jpo": _bool_not(pf),
        "jns": _bool_not(sf),
        "js": sf,
    }
    return conditions.get(mnemonic)

def _arithmetic_flags(
    operator: str,
    left: tuple[Any, ...],
    right: tuple[Any, ...],
    result: tuple[Any, ...],
    *,
    width_bits: int = 32,
) -> dict[str, tuple[Any, ...]]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    result = _expr_mask(result, width_bits)
    if operator == "add":
        cf = ("ult", result, left)
        of = ("add_overflow_w", width_bits, left, right, result)
    else:
        cf = ("ult", left, right)
        of = ("sub_overflow_w", width_bits, left, right, result)
    return {
        "cf": cf,
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": of,
        "pf": ("parity", width_bits, result),
    }

def _logical_flags(result: tuple[Any, ...], *, width_bits: int = 32) -> dict[str, tuple[Any, ...]]:
    result = _expr_mask(result, width_bits)
    return {
        "cf": ("false",),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": ("false",),
        "pf": ("parity", width_bits, result),
    }

def _logical_result(operator: str, left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    if operator == "xor":
        return _expr_xor(left, right)
    if operator == "and":
        return _expr_and(left, right)
    if operator == "or":
        return _expr_or(left, right)
    raise StageAInputError(f"unsupported logical operator {operator!r}")

def _carry_arithmetic_flags(
    operator: str,
    left: tuple[Any, ...],
    right: tuple[Any, ...],
    carry: tuple[Any, ...],
    result: tuple[Any, ...],
    *,
    width_bits: int,
) -> dict[str, tuple[Any, ...]]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    carry_bit = _expr_mask(_expr_bool_bit(carry), width_bits)
    result = _expr_mask(result, width_bits)
    if operator == "adc":
        return {
            "cf": ("adc_carry", width_bits, left, right, carry_bit, result),
            "zf": ("eq", result, ("const", 0)),
            "sf": ("msb_w", width_bits, result),
            "of": ("adc_overflow", width_bits, left, right, carry_bit, result),
            "pf": ("parity", width_bits, result),
        }
    return {
        "cf": ("sbb_borrow", width_bits, left, right, carry_bit, result),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": ("sbb_overflow", width_bits, left, right, carry_bit, result),
        "pf": ("parity", width_bits, result),
    }

def _shift_flags(
    mnemonic: str,
    left: tuple[Any, ...],
    count: tuple[Any, ...],
    result: tuple[Any, ...],
    prior_flags: dict[str, tuple[Any, ...]],
    *,
    rva: int,
    width_bits: int,
) -> dict[str, tuple[Any, ...]]:
    effective_count = _expr_and(count, ("const", 0x1F))
    count_is_zero = _bool_eq(effective_count, ("const", 0))
    count_is_one = _bool_eq(effective_count, ("const", 1))
    count_within_width = ("ult", effective_count, ("const", width_bits + 1))
    result = _expr_mask(result, width_bits)
    shifted_cf = ("shift_cf", mnemonic, width_bits, _expr_mask(left, width_bits), effective_count)
    active_cf = _expr_ite(
        count_within_width,
        shifted_cf,
        _undefined_flag("shift_count_exceeds_width", rva, "cf"),
    )
    shifted_of = ("shift_of", mnemonic, width_bits, _expr_mask(left, width_bits), effective_count, result)
    return {
        "cf": _expr_ite(count_is_zero, prior_flags["cf"], active_cf),
        "zf": _expr_ite(count_is_zero, prior_flags["zf"], ("eq", result, ("const", 0))),
        "sf": _expr_ite(count_is_zero, prior_flags["sf"], ("msb_w", width_bits, result)),
        "of": _expr_ite(
            count_is_zero,
            prior_flags["of"],
            _expr_ite(
                count_is_one,
                shifted_of,
                _undefined_flag("shift_overflow_undefined", rva, "of"),
            ),
        ),
        "pf": _expr_ite(count_is_zero, prior_flags["pf"], ("parity", width_bits, result)),
    }

def _undefined_flag(reason: str, rva: int, name: str) -> tuple[Any, ...]:
    return ("undefined_flag", reason, f"{rva:x}:{name}")

def _undefined_bv(
    reason: str,
    rva: int,
    name: str,
    defined_value: tuple[Any, ...] | None = None,
) -> tuple[Any, ...]:
    base = ("undefined_bv", reason, f"{rva:x}:{name}")
    return base if defined_value is None else (*base, defined_value)

def _undefined_arithmetic_flags(reason: str, rva: int, *, keep: dict[str, tuple[Any, ...]] | None = None) -> dict[str, tuple[Any, ...]]:
    keep = keep or {}
    return {name: keep.get(name, _undefined_flag(reason, rva, name)) for name in ("cf", "zf", "sf", "of", "pf")}

def _setcc_condition(mnemonic: str, flags: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    suffix = mnemonic[3:] if mnemonic.startswith("set") else mnemonic
    aliases = {
        "e": "z",
        "ne": "nz",
        "nae": "b",
        "c": "b",
        "nb": "ae",
        "nc": "ae",
        "be": "be",
        "na": "be",
        "nbe": "a",
        "nge": "l",
        "nl": "ge",
        "ng": "le",
        "nle": "g",
        "pe": "p",
        "po": "np",
    }
    key = aliases.get(suffix, suffix)
    zf = flags["zf"]
    cf = flags["cf"]
    sf = flags["sf"]
    of = flags["of"]
    pf = flags.get("pf", ("flag", "pf"))
    conditions = {
        "z": zf,
        "nz": _bool_not(zf),
        "a": _bool_and(_bool_not(cf), _bool_not(zf)),
        "ae": _bool_not(cf),
        "b": cf,
        "be": _bool_or(cf, zf),
        "g": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "ge": _bool_eq(sf, of),
        "l": _bool_xor(sf, of),
        "le": _bool_or(zf, _bool_xor(sf, of)),
        "o": of,
        "no": _bool_not(of),
        "s": sf,
        "ns": _bool_not(sf),
        "p": pf,
        "np": _bool_not(pf),
    }
    return conditions.get(key)

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
    field_mask = ((1 << width) - 1) << offset
    clear_mask = (~field_mask) & 0xFFFFFFFF
    shifted = _expr_shl(value, ("const", offset)) if offset else value
    registers[base] = _expr_or(_expr_and(current, ("const", clear_mask)), shifted)
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

def _external_call_contract(mapped: BlockMapping, index: int) -> dict[str, Any] | None:
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

def _expr_add(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) + int(right[1])) & 0xFFFFFFFF)
    terms = sorted(_flatten_expr("add", left) + _flatten_expr("add", right), key=repr)
    return ("add", *terms)

def _expr_sub(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) - int(right[1])) & 0xFFFFFFFF)
    return ("sub", left, right)

def _expr_mul(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0) or right == ("const", 0):
        return ("const", 0)
    if left == ("const", 1):
        return right
    if right == ("const", 1):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("mul", left, right)

def _expr_mask(value: tuple[Any, ...] | None, width_bits: int) -> tuple[Any, ...]:
    if value is None:
        return ("const", 0)
    if isinstance(value, tuple) and len(value) >= 3 and value[0] == "sext" and int(value[1]) == width_bits:
        return _expr_mask(value[2], width_bits)
    value = _canonical_expr(value)
    if width_bits >= 32:
        return value
    mask = (1 << width_bits) - 1
    if value[0] == "const":
        return ("const", int(value[1]) & mask)
    if value[0] == "and" and ("const", mask) in value[1:]:
        return value
    return _expr_and(value, ("const", mask))

def _expr_sign_extend(value: tuple[Any, ...], width_bits: int) -> tuple[Any, ...]:
    value = _expr_mask(value, width_bits)
    if width_bits >= 32:
        return value
    if value[0] == "const":
        raw = int(value[1]) & ((1 << width_bits) - 1)
        sign_bit = 1 << (width_bits - 1)
        if raw & sign_bit:
            raw |= (~((1 << width_bits) - 1)) & 0xFFFFFFFF
        return ("const", raw & 0xFFFFFFFF)
    return ("sext", width_bits, value)

def _expr_shl(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) << (int(right[1]) & 31)) & 0xFFFFFFFF)
    return ("shl", left, right)

def _expr_lshr(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) & 0xFFFFFFFF) >> (int(right[1]) & 31))
    return ("lshr", left, right)

def _expr_ashr(left: tuple[Any, ...], right: tuple[Any, ...], width_bits: int = 32) -> tuple[Any, ...]:
    left = _expr_mask(left, width_bits)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        shift = int(right[1]) & 31
        raw = int(left[1]) & ((1 << width_bits) - 1)
        if raw & (1 << (width_bits - 1)):
            signed = raw - (1 << width_bits)
        else:
            signed = raw
        return ("const", (signed >> shift) & ((1 << width_bits) - 1))
    return ("ashr", width_bits, left, right)

def _expr_not(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value[0] == "const":
        return ("const", (~int(value[1])) & 0xFFFFFFFF)
    return ("bvnot", value)

def _expr_neg(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value[0] == "const":
        return ("const", (-int(value[1])) & 0xFFFFFFFF)
    return ("neg", value)

def _expr_ite(condition: tuple[Any, ...], when_true: tuple[Any, ...], when_false: tuple[Any, ...]) -> tuple[Any, ...]:
    condition = _canonical_expr(condition)
    when_true = _canonical_expr(when_true)
    when_false = _canonical_expr(when_false)
    if condition == ("true",):
        return when_true
    if condition == ("false",):
        return when_false
    if when_true == when_false:
        return when_true
    return ("ite", condition, when_true, when_false)

def _expr_bool_bit(condition: tuple[Any, ...]) -> tuple[Any, ...]:
    condition = _canonical_expr(condition)
    if condition == ("true",):
        return ("const", 1)
    if condition == ("false",):
        return ("const", 0)
    return ("bool_bit", condition)

def _expr_imul_low(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("imul_low", left, right)

def _expr_imul_high(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        signed_left = _signed32(int(left[1]))
        signed_right = _signed32(int(right[1]))
        return ("const", ((signed_left * signed_right) >> 32) & 0xFFFFFFFF)
    return ("imul_high", left, right)

def _expr_mul_low(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("mul_low", left, right)

def _expr_mul_high(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (((int(left[1]) & 0xFFFFFFFF) * (int(right[1]) & 0xFFFFFFFF)) >> 32) & 0xFFFFFFFF)
    return ("mul_high", left, right)

def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value

def _expr_shift_pair(mnemonic: str, left: tuple[Any, ...], right: tuple[Any, ...], count: tuple[Any, ...], width_bits: int) -> tuple[Any, ...]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    count = _expr_and(count, ("const", 0x1F))
    inverse = _expr_sub(("const", width_bits), count)
    if mnemonic == "shrd":
        return _expr_mask(_expr_or(_expr_lshr(left, count), _expr_shl(right, inverse)), width_bits)
    return _expr_mask(_expr_or(_expr_shl(left, count), _expr_lshr(right, inverse)), width_bits)

def _expr_xor(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("const", 0)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) ^ int(right[1]))
    terms = sorted(_flatten_expr("xor", left) + _flatten_expr("xor", right), key=repr)
    return ("xor", *terms)

def _expr_and(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0) or right == ("const", 0):
        return ("const", 0)
    if left == ("const", 0xFFFFFFFF):
        return right
    if right == ("const", 0xFFFFFFFF):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) & int(right[1]))
    if repr(right) < repr(left):
        left, right = right, left
    return ("and", left, right)

def _expr_or(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) | int(right[1]))
    if repr(right) < repr(left):
        left, right = right, left
    return ("or", left, right)

def _bool_not(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value == ("true",):
        return ("false",)
    if value == ("false",):
        return ("true",)
    if isinstance(value, tuple) and value and value[0] == "not":
        return value[1]
    return ("not", value)

def _bool_and(*values: tuple[Any, ...]) -> tuple[Any, ...]:
    terms: list[tuple[Any, ...]] = []
    for value in values:
        value = _canonical_expr(value)
        if value == ("false",):
            return ("false",)
        if value == ("true",):
            continue
        terms.extend(_flatten_expr("bool_and", value))
    if not terms:
        return ("true",)
    if len(terms) == 1:
        return terms[0]
    return ("bool_and", *sorted(terms, key=repr))

def _bool_or(*values: tuple[Any, ...]) -> tuple[Any, ...]:
    terms: list[tuple[Any, ...]] = []
    for value in values:
        value = _canonical_expr(value)
        if value == ("true",):
            return ("true",)
        if value == ("false",):
            continue
        terms.extend(_flatten_expr("bool_or", value))
    if not terms:
        return ("false",)
    if len(terms) == 1:
        return terms[0]
    return ("bool_or", *sorted(terms, key=repr))

def _bool_xor(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("false",)
    if left == ("false",):
        return right
    if right == ("false",):
        return left
    if left == ("true",):
        return _bool_not(right)
    if right == ("true",):
        return _bool_not(left)
    if repr(right) < repr(left):
        left, right = right, left
    return ("bool_xor", left, right)

def _bool_eq(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("true",)
    if left == ("true",):
        return right
    if right == ("true",):
        return left
    if left == ("false",):
        return _bool_not(right)
    if right == ("false",):
        return _bool_not(left)
    if repr(right) < repr(left):
        left, right = right, left
    return ("bool_eq", left, right)

def _flatten_expr(operator: str, expr: tuple[Any, ...]) -> list[tuple[Any, ...]]:
    if expr and expr[0] == operator:
        return list(expr[1:])
    return [expr]

def _canonical_expr(expr: Any) -> Any:
    if not isinstance(expr, tuple) or not expr:
        return expr
    op = expr[0]
    if op == "const":
        return ("const", int(expr[1]) & 0xFFFFFFFF)
    if op in {"reg", "flag", "true", "false", "env_response", "call_response", "call_flag", "undefined_bv", "undefined_flag"}:
        return expr
    if op == "add":
        result: tuple[Any, ...] = ("const", 0)
        for part in expr[1:]:
            result = _expr_add(result, _canonical_expr(part))
        return result
    if op == "sub":
        return _expr_sub(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "mul":
        return _expr_mul(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "xor":
        result: tuple[Any, ...] = ("const", 0)
        for part in expr[1:]:
            result = _expr_xor(result, _canonical_expr(part))
        return result
    if op == "and":
        return _expr_and(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "or":
        return _expr_or(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "bvnot":
        return _expr_not(_canonical_expr(expr[1]))
    if op == "neg":
        return _expr_neg(_canonical_expr(expr[1]))
    if op == "shl":
        return _expr_shl(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "lshr":
        return _expr_lshr(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "ashr":
        return _expr_ashr(_canonical_expr(expr[2]), _canonical_expr(expr[3]), int(expr[1]))
    if op == "sext":
        return _expr_sign_extend(_canonical_expr(expr[2]), int(expr[1]))
    if op == "ite":
        return _expr_ite(_canonical_expr(expr[1]), _canonical_expr(expr[2]), _canonical_expr(expr[3]))
    if op == "not":
        return _bool_not(_canonical_expr(expr[1]))
    if op == "bool_and":
        return _bool_and(*[_canonical_expr(part) for part in expr[1:]])
    if op == "bool_or":
        return _bool_or(*[_canonical_expr(part) for part in expr[1:]])
    if op == "bool_xor":
        return _bool_xor(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "bool_eq":
        return _bool_eq(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op in {
        "eq",
        "ult",
        "msb",
        "msb_w",
        "add_overflow",
        "sub_overflow",
        "add_overflow_w",
        "sub_overflow_w",
        "shift_cf",
        "shift_of",
        "adc_carry",
        "adc_overflow",
        "sbb_borrow",
        "sbb_overflow",
        "imul_overflow",
        "mul_carry",
        "parity",
        "fpu_cmp_cf",
        "fpu_cmp_zf",
        "fpu_cmp_pf",
        "bool_bit",
        "mem32",
        "mem",
        "call_mem",
        "imul_low",
        "imul_high",
        "mul_low",
        "mul_high",
        "udiv_quot",
        "udiv_rem",
        "udiv_valid",
        "bsr_index",
        "tzcnt",
        "fpu_bits_lo",
        "fpu_bits_hi",
        "fpu_int32",
        "fpu_status_word",
        "fpu_control_word",
    }:
        return tuple(_canonical_expr(part) for part in expr)
    return tuple(_canonical_expr(part) for part in expr)

def _expr_json(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_expr_json(item) for item in value]
    if isinstance(value, list):
        return [_expr_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _expr_json(item) for key, item in value.items()}
    return value

__all__ = [
    '_InstructionTaggedEvents',
    '_X86_REGISTER_PARTS',
    '_arithmetic_flags',
    '_bool_and',
    '_bool_eq',
    '_bool_not',
    '_bool_or',
    '_bool_xor',
    '_branch_condition',
    '_call_flag_inputs',
    '_call_register_inputs',
    '_call_stack_inputs',
    '_canonical_expr',
    '_carry_arithmetic_flags',
    '_expr_add',
    '_expr_and',
    '_expr_ashr',
    '_expr_bool_bit',
    '_expr_imul_high',
    '_expr_imul_low',
    '_expr_ite',
    '_expr_json',
    '_expr_lshr',
    '_expr_mask',
    '_expr_mul',
    '_expr_mul_high',
    '_expr_mul_low',
    '_expr_neg',
    '_expr_not',
    '_expr_or',
    '_expr_shift_pair',
    '_expr_shl',
    '_expr_sign_extend',
    '_expr_sub',
    '_expr_xor',
    '_external_arg_expr',
    '_external_call_args',
    '_external_call_contract',
    '_external_import_call_event',
    '_flatten_expr',
    '_import_z3',
    '_indirect_call_event',
    '_internal_call_event',
    '_is_supported_register_name',
    '_logical_flags',
    '_logical_result',
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
    '_setcc_condition',
    '_shift_flags',
    '_signed32',
    '_stack_argument_writes',
    '_stack_relative_offset',
    '_symbolic_execute',
    '_symbolic_incomplete',
    '_undefined_arithmetic_flags',
    '_undefined_bv',
    '_undefined_flag',
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
