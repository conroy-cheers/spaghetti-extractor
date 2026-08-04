from __future__ import annotations

from typing import Any


LEGACY_PREFIXES = {
    0xF0,
    0xF2,
    0xF3,
    0x2E,
    0x36,
    0x3E,
    0x26,
    0x64,
    0x65,
    0x66,
    0x67,
}


def instruction_is_x87(instruction: Any) -> bool:
    encoded = bytes(instruction.bytes)
    index = 0
    while index < len(encoded) and encoded[index] in LEGACY_PREFIXES:
        index += 1
    opcode = encoded[index] if index < len(encoded) else -1
    mnemonic = str(instruction.mnemonic).lower()
    return opcode == 0x9B or (
        0xD8 <= opcode <= 0xDF and mnemonic.startswith("f")
    )


def state_only_singleton_bytes(encoded: bytes) -> bool:
    """Recognize the conservative x87 subset checked by Lean's singleton profile.

    This is proposal logic only.  The generated certificate re-decodes the exact
    PE bytes and checks ``stateOnlySingletonCommandChecked`` in Lean.
    """
    if encoded == b"\x9b":
        return True
    if len(encoded) != 2:
        return False
    opcode, modrm = encoded
    return (
        (opcode == 0xD9 and 0xC0 <= modrm <= 0xCF)
        or (opcode == 0xD9 and modrm in {0xE0, 0xE5, 0xE8, 0xEE})
        or (opcode == 0xDD and 0xD0 <= modrm <= 0xDF)
        or (opcode == 0xD8 and 0xC0 <= modrm <= 0xCF)
        or (opcode == 0xD8 and 0xD0 <= modrm <= 0xDF)
        or (opcode == 0xD8 and 0xF0 <= modrm <= 0xF7)
        or (opcode == 0xDC and 0xC8 <= modrm <= 0xCF)
        or (opcode == 0xDE and 0xC0 <= modrm <= 0xCF)
        or (opcode == 0xDE and 0xE0 <= modrm <= 0xEF)
        or (opcode == 0xDD and 0xE0 <= modrm <= 0xEF)
        or (opcode == 0xDB and modrm == 0xE3)
    )


def qualified_singleton_bytes(encoded: bytes) -> bool:
    """Recognize exact singleton forms implemented by the Lean x87 executor.

    This is only a fast proposal check.  Acceptance re-decodes the complete
    instruction span from the PE bytes with ``decodeSingletonCommand`` and
    executes it through the reviewed physical x87 semantics.  Relational
    composition remains a separate, rooted obligation.
    """
    if state_only_singleton_bytes(encoded):
        return True
    if len(encoded) < 2:
        return False
    opcode, modrm = encoded[:2]
    if not 0xD8 <= opcode <= 0xDF:
        return False

    mode = modrm >> 6
    group = (modrm >> 3) & 7
    if mode != 3:
        return (
            (opcode in {0xD8, 0xDC} and group in {0, 1, 4, 5, 6, 7})
            or (opcode in {0xD9, 0xDB} and group in {0, 2, 3, 5, 7})
            or (opcode == 0xDD and group in {0, 2, 3})
        )

    return (
        (opcode == 0xD8 and 0xC0 <= modrm <= 0xDF)
        or (opcode == 0xD8 and 0xF0 <= modrm <= 0xF7)
        or (opcode == 0xD9 and 0xC0 <= modrm <= 0xCF)
        or (opcode == 0xD9 and modrm in {0xE0, 0xE5, 0xE8, 0xEE})
        or (opcode == 0xDB and (modrm == 0xE3 or 0xE8 <= modrm <= 0xF7))
        or (opcode == 0xDC and 0xC8 <= modrm <= 0xCF)
        or (opcode == 0xDD and 0xD0 <= modrm <= 0xEF)
        or (opcode == 0xDE and 0xC0 <= modrm <= 0xCF)
        or (opcode == 0xDE and 0xE0 <= modrm <= 0xEF)
        or (opcode == 0xDF and (modrm == 0xE0 or 0xE8 <= modrm <= 0xF7))
    )
