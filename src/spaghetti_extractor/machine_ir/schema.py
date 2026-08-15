"""Canonical structural constraints for strict machine-IR artifacts."""

from __future__ import annotations


RAW_INSTRUCTION_FIELDS = frozenset({
    "bytes",
    "instruction_bytes",
    "opcode_bytes",
    "raw_bytes",
    "encoded_instruction",
})


__all__ = ["RAW_INSTRUCTION_FIELDS"]
