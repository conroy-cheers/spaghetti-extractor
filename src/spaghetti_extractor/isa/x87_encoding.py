"""Small exact-byte predicates for the IA-32 x87 encoding space.

This module classifies syntax only.  It does not decode operands, state an
instruction's semantics, or grant ISA qualification.  The transfer frontend
and exact typed-x87 lowering share the predicate so adding a mnemonic to a
symbolic proposal whitelist can never be what makes an x87 instruction
representable.
"""

from __future__ import annotations


_LEGACY_PREFIX_BYTES = frozenset(
    {
        0x26,  # ES segment override
        0x2E,  # CS segment override / branch hint
        0x36,  # SS segment override
        0x3E,  # DS segment override / branch hint
        0x64,  # FS segment override
        0x65,  # GS segment override
        0x66,  # operand-size override
        0x67,  # address-size override
        0xF0,  # LOCK
        0xF2,  # REPNE
        0xF3,  # REP/REPE
    }
)


def is_x87_instruction_encoding(encoded: bytes) -> bool:
    """Return whether one exact IA-32 encoding occupies the x87 opcode space.

    The one-byte WAIT instruction is part of the x87 execution surface.  All
    other x87 instructions use a primary opcode from D8 through DF after any
    legacy prefixes.  This is deliberately only a syntactic classification;
    exact decoding and semantic qualification remain separate fail-closed
    gates.
    """

    if not isinstance(encoded, bytes) or not encoded or len(encoded) > 15:
        return False
    index = 0
    while index < len(encoded) and encoded[index] in _LEGACY_PREFIX_BYTES:
        index += 1
    if index >= len(encoded):
        return False
    opcode = encoded[index]
    return opcode == 0x9B or 0xD8 <= opcode <= 0xDF


__all__ = ["is_x87_instruction_encoding"]
