"""Render checked typed x87 operations and IA-32 state shims."""

from __future__ import annotations

from ..errors import ToolkitInputError
from ..transfer.x87 import (
    X87_MEMORY_NO_SIZE_MNEMONICS,
    X87_MEMORY_SIZE_KEYWORDS,
)
from .module_runtime_plan import NativeX87Operation, _STATE_OFFSETS


def _render_typed_x87_instruction(operation: NativeX87Operation) -> str:
    typed = operation.operation
    operand = typed.operand
    if operand.kind == "none":
        return typed.mnemonic
    if operand.kind == "ax":
        return f"{typed.mnemonic} ax"
    if operand.kind == "stack":
        registers = operand.registers
        if typed.mnemonic == "fxch" and len(registers) == 2:
            if registers[0] != 0:
                raise ToolkitInputError("typed fxch first operand must be st(0)")
            registers = registers[1:]
        return f"{typed.mnemonic} " + ", ".join(
            f"st({index})" for index in registers
        )
    if operand.kind != "memory":
        raise ToolkitInputError(
            f"unsupported typed x87 operand kind {operand.kind!r}"
        )
    terms: list[str] = []
    if operand.image_rva is not None:
        if (
            operation.target_rva != operand.image_rva
            or not (
                operation.relocation_type == 3
                and operation.relocation_width == 4
                or operation.fixed_image_base == operation.image_base
            )
        ):
            raise ToolkitInputError(
                "absolute typed x87 operand lacks a checked image-address binding"
            )
        terms.append(f"___ImageBase + 0x{operand.image_rva:08x}")
    if operand.base is not None:
        terms.append(operand.base)
    if operand.index is not None:
        terms.append(
            operand.index
            if operand.scale == 1
            else f"{operand.index} * {operand.scale}"
        )
    if not terms:
        raise ToolkitInputError("typed x87 memory operand has no address source")
    address = " + ".join(terms)
    if operand.displacement > 0:
        address += f" + 0x{operand.displacement:x}"
    elif operand.displacement < 0:
        address += f" - 0x{-operand.displacement:x}"
    size = (
        ""
        if typed.mnemonic in X87_MEMORY_NO_SIZE_MNEMONICS
        else X87_MEMORY_SIZE_KEYWORDS.get(operand.width)
    )
    if size is None:
        raise ToolkitInputError(
            f"typed x87 memory width {operand.width} has no reviewed rendering"
        )
    return f"{typed.mnemonic} {f'{size} ' if size else ''}[{address}]"


def _restore_pushes(state_register: str) -> list[str]:
    return [
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['eflags']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['eax']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ecx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['edx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ebx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['esp']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ebp']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['esi']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['edi']}]",
    ]


def _capture_pushad_registers(output_register: str) -> list[str]:
    stack_offsets = {
        "edi": 0, "esi": 4, "ebp": 8, "ebx": 16,
        "edx": 20, "ecx": 24, "eax": 28,
    }
    lines: list[str] = []
    for field, stack_offset in stack_offsets.items():
        lines.extend([
            f"    mov ecx, DWORD PTR [esp + {stack_offset}]",
            f"    mov DWORD PTR [{output_register} + {_STATE_OFFSETS[field]}], ecx",
        ])
    lines.append("    lea ecx, [esp + 36]")
    return lines


def _capture_split_flags(output_register: str) -> list[str]:
    bits = {"cf": 0, "pf": 2, "zf": 6, "sf": 7, "df": 10, "of": 11}
    lines: list[str] = []
    for field, bit in bits.items():
        lines.extend([
            "    mov ecx, DWORD PTR [esp + 32]",
            f"    shr ecx, {bit}",
            "    and ecx, 1",
            f"    mov DWORD PTR [{output_register} + {_STATE_OFFSETS[field]}], ecx",
        ])
    return lines


__all__ = [
    "_capture_pushad_registers",
    "_capture_split_flags",
    "_render_typed_x87_instruction",
    "_restore_pushes",
]
