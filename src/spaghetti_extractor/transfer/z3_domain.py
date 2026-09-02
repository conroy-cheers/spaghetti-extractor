"""Supporting Z3 reconstruction for the canonical transfer-v2 core."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import z3

from .interpretation import DomainOperationCoverageV2, total_domain_coverage_v2
from .model import TransferPlanError, _FLAGS, _REGISTERS, _Transfer
from .operations import EFFECT_OPERATIONS_V2, TERMINATOR_OPERATIONS_V2


_Z3_REJECTED_EXPRESSIONS_V2 = frozenset({
    "sar",
    "sign_extend",
    "msb",
    "parity",
    "add_overflow",
    "sub_overflow",
    "imul_high32",
    "mul_high32",
    "imul_overflow",
    "mul_carry",
    "udiv_quot32",
    "udiv_rem32",
    "udiv_valid32",
    "bsr_index",
    "tzcnt",
    "sbb_borrow",
    "sbb_overflow",
    "adc_carry",
    "adc_overflow",
    "shift_cf",
    "shift_of",
    "fpu_control",
    "fpu_control_init",
    "fpu_status",
    "fpu_status_init",
    "fpu_tag",
    "fpu_pending_exception",
    "fpu_last_opcode",
    "fpu_instruction_pointer",
    "fpu_code_selector",
    "fpu_data_pointer",
    "fpu_data_selector",
    "fpu_control_load",
    "fpu_control_word",
    "fpu_status_word",
})


def z3_operation_coverage_v2() -> DomainOperationCoverageV2:
    return total_domain_coverage_v2(
        "z3_reconstruction",
        rejected_expressions=_Z3_REJECTED_EXPRESSIONS_V2,
        # This domain reconstructs expression terms only.  It must not imply
        # that state transitions or root outcomes have Z3 semantics merely
        # because their operand expressions can be reconstructed.
        rejected_effects=EFFECT_OPERATIONS_V2,
        rejected_terminators=TERMINATOR_OPERATIONS_V2,
    )


def _symbol(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


@dataclass
class Z3TransferInputsV2:
    memory: z3.ArrayRef = field(
        default_factory=lambda: z3.Array(
            "transfer_memory", z3.BitVecSort(32), z3.BitVecSort(8)
        )
    )
    initial_registers: tuple[z3.BitVecRef, ...] = field(
        default_factory=lambda: tuple(
            z3.BitVec(f"initial_{name}", 32) for name in _REGISTERS
        )
    )
    current_registers: tuple[z3.BitVecRef, ...] = field(
        default_factory=lambda: tuple(
            z3.BitVec(f"current_{name}", 32) for name in _REGISTERS
        )
    )
    initial_flags: tuple[z3.BoolRef, ...] = field(
        default_factory=lambda: tuple(
            z3.Bool(f"initial_{name}") for name in (*_FLAGS, "af")
        )
    )
    current_flags: tuple[z3.BoolRef, ...] = field(
        default_factory=lambda: tuple(
            z3.Bool(f"current_{name}") for name in (*_FLAGS, "af")
        )
    )
    call_registers: tuple[z3.BitVecRef, ...] = field(
        default_factory=lambda: tuple(
            z3.BitVec(f"call_{name}", 32) for name in _REGISTERS
        )
    )
    call_flags: tuple[z3.BoolRef, ...] = field(
        default_factory=lambda: tuple(
            z3.Bool(f"call_{name}") for name in (*_FLAGS, "af")
        )
    )
    initial_fs_base: z3.BitVecRef = field(
        default_factory=lambda: z3.BitVec("initial_fs_base", 32)
    )
    current_fs_base: z3.BitVecRef = field(
        default_factory=lambda: z3.BitVec("current_fs_base", 32)
    )


def _bool(value: z3.ExprRef, context: str) -> z3.BoolRef:
    if not z3.is_bool(value):
        raise TransferPlanError(
            f"{context} requires a predicate operand",
            code="malformed_transfer_type",
        )
    return value


def _bv(value: z3.ExprRef, context: str) -> z3.BitVecRef:
    if not z3.is_bv(value) or value.size() != 32:
        raise TransferPlanError(
            f"{context} requires a 32-bit operand",
            code="malformed_transfer_type",
        )
    return value


def _read(memory: z3.ArrayRef, address: z3.BitVecRef, width: int) -> z3.BitVecRef:
    bytes_le = [
        z3.Select(memory, address + z3.BitVecVal(offset, 32))
        for offset in range(width)
    ]
    value = bytes_le[0] if width == 1 else z3.Concat(*reversed(bytes_le))
    return value if width == 4 else z3.ZeroExt(32 - width * 8, value)


def reconstruct_expressions_z3_v2(
    transfer: _Transfer,
    inputs: Z3TransferInputsV2 | None = None,
) -> tuple[z3.ExprRef, ...]:
    """Reconstruct the exact supported expression subset; never authorize."""

    state = inputs or Z3TransferInputsV2()
    values: list[z3.ExprRef] = []
    for index, node in enumerate(transfer.nodes):
        if node.op in _Z3_REJECTED_EXPRESSIONS_V2:
            raise TransferPlanError(
                f"{transfer.identity}: Z3 reconstruction rejects {node.op!r}",
                code="z3_transfer_operation_unavailable",
                next_action="use a checked domain handler before Z3 reasoning",
            )
        args = [values[item] for item in node.args]
        op = node.op
        if op == "const":
            result: z3.ExprRef = z3.BitVecVal(node.immediate, 32)
        elif op == "reg":
            result = (
                state.current_registers if node.immediate
                else state.initial_registers
            )[node.aux]
        elif op == "flag":
            result = (
                state.current_flags if node.immediate else state.initial_flags
            )[node.aux]
        elif op == "fs_base":
            result = state.current_fs_base if node.immediate else state.initial_fs_base
        elif op in {"true", "false"}:
            result = z3.BoolVal(op == "true")
        elif op in {"undefined_bv", "undefined_flag"}:
            if node.identity is None:
                raise TransferPlanError(
                    "Z3 undefined value lacks a stable identity",
                    code="malformed_transfer_undefined_identity",
                )
            name = f"undefined_{node.immediate:08x}_{_symbol(node.identity)}"
            result = z3.Bool(name) if op == "undefined_flag" else z3.BitVec(name, 32)
        elif op == "call_response":
            result = state.call_registers[node.aux]
        elif op == "call_flag":
            result = state.call_flags[node.aux]
        elif op == "load":
            result = _read(state.memory, _bv(args[0], op), node.aux)
        elif op in {"add32", "mul32", "xor32", "and32", "or32"}:
            words = [_bv(item, op) for item in args]
            result = words[0]
            for word in words[1:]:
                result = {
                    "add32": result + word,
                    "mul32": result * word,
                    "xor32": result ^ word,
                    "and32": result & word,
                    "or32": result | word,
                }[op]
        elif op == "sub32":
            result = _bv(args[0], op) - _bv(args[1], op)
        elif op == "not32":
            result = ~_bv(args[0], op)
        elif op == "neg32":
            result = -_bv(args[0], op)
        elif op == "shl32":
            result = _bv(args[0], op) << (_bv(args[1], op) & 31)
        elif op == "lshr32":
            result = z3.LShR(_bv(args[0], op), _bv(args[1], op) & 31)
        elif op == "ult32":
            result = z3.ULT(_bv(args[0], op), _bv(args[1], op))
        elif op == "eq":
            result = _bv(args[0], op) == _bv(args[1], op)
        elif op == "eq_bool":
            result = _bool(args[0], op) == _bool(args[1], op)
        elif op == "xor_bool":
            result = z3.Xor(_bool(args[0], op), _bool(args[1], op))
        elif op == "not":
            result = z3.Not(_bool(args[0], op))
        elif op == "and_bool":
            result = z3.And(*(_bool(item, op) for item in args))
        elif op == "or_bool":
            result = z3.Or(*(_bool(item, op) for item in args))
        elif op == "bool_to_bit":
            result = z3.If(
                _bool(args[0], op), z3.BitVecVal(1, 32), z3.BitVecVal(0, 32)
            )
        elif op == "ite":
            result = z3.If(_bool(args[0], op), args[1], args[2])
        elif op in {"imul_low32", "mul_low32"}:
            result = _bv(args[0], op) * _bv(args[1], op)
        else:
            raise TransferPlanError(
                f"{transfer.identity}: Z3 handler is absent for {op!r}",
                code="transfer_domain_coverage_incomplete",
            )
        values.append(result)
    return tuple(values)


__all__ = [
    "Z3TransferInputsV2",
    "reconstruct_expressions_z3_v2",
    "z3_operation_coverage_v2",
]
