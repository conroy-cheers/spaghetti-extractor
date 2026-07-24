"""Shared proposal-side recognition for reviewed x86 instruction forms.

These helpers do not grant proof authority. They keep static diagnostics and
Lean-source generation aligned on the forms that the Lean decoder will later
re-decode from exact PE bytes.
"""

from __future__ import annotations

from typing import Any

from capstone import x86_const


_X87_ADDRESS_REGISTERS = {
    x86_const.X86_REG_EAX,
    x86_const.X86_REG_EBX,
    x86_const.X86_REG_ECX,
    x86_const.X86_REG_EDX,
    x86_const.X86_REG_ESI,
    x86_const.X86_REG_EDI,
    x86_const.X86_REG_EBP,
    x86_const.X86_REG_ESP,
}


def is_reviewed_x87_frame_instruction(instruction: Any) -> bool:
    """Recognize the reviewed 32-bit FNSAVE/FRSTOR memory forms.

    Capstone remains an untrusted proposal mechanism. The generated Lean
    certificate independently checks the opcode, effective address, and exact
    bytes before this form can contribute to a proof.
    """

    data = bytes(instruction.bytes)
    operands = instruction.operands
    if (
        instruction.id
        not in {x86_const.X86_INS_FNSAVE, x86_const.X86_INS_FRSTOR}
        or not data
        or data[0] != 0xDD
        or len(operands) != 1
        or operands[0].type != x86_const.X86_OP_MEM
    ):
        return False
    memory = operands[0].mem
    return (
        memory.segment == x86_const.X86_REG_INVALID
        and memory.base
        in _X87_ADDRESS_REGISTERS | {x86_const.X86_REG_INVALID}
        and memory.index
        in _X87_ADDRESS_REGISTERS | {x86_const.X86_REG_INVALID}
        and memory.scale in {1, 2, 4, 8}
        and memory.index != x86_const.X86_REG_ESP
    )
