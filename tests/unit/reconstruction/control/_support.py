from __future__ import annotations

import json
import unittest
from hashlib import sha256
from typing import Any

from spaghetti_extractor.reconstruction.control import (
    classify_overlapping_instruction_starts,
    derive_rooted_reachable_units,
    propose_semantic_clusters,
    recover_static_pe32_jump_table_inventory,
)


IMAGE_BASE = 0x400000
TABLE_RVA = 0x2000


def _constant(value: int) -> dict[str, Any]:
    return {"op": "constant", "value": value}


def _index() -> dict[str, Any]:
    return {"op": "input_reg", "reg": "eax"}


def _table_expression() -> dict[str, Any]:
    return {
        "op": "load",
        "width": 4,
        "address": {
            "op": "add",
            "left": _constant(IMAGE_BASE + TABLE_RVA),
            "right": {
                "op": "mul",
                "left": _index(),
                "right": _constant(4),
            },
        },
    }


def _guarded_predecessor(upper_exclusive: int) -> dict[str, Any]:
    return {
        "source_unit_id": "guard",
        "edge_kind": "fallthrough",
        "guard": {
            "op": "unsigned_less",
            "left": _index(),
            "right": _constant(upper_exclusive),
        },
        "instructions": [
            {
                "mnemonic": "cmp",
                "operands": [
                    {"kind": "register", "name": "eax", "width_bits": 32},
                    {
                        "kind": "immediate",
                        "value": upper_exclusive - 1,
                        "width_bits": 32,
                    },
                ],
            },
            {
                "mnemonic": "ja",
                "operands": [
                    {"kind": "immediate", "value": IMAGE_BASE + 0x1700}
                ],
            },
        ],
    }


def _sections(*, writable_table: bool = False) -> list[dict[str, Any]]:
    return [
        {
            "name": ".text",
            "rva_start": 0x1000,
            "rva_end": 0x1800,
            "readable": True,
            "writable": False,
            "executable": True,
        },
        {
            "name": ".rdata" if not writable_table else ".data",
            "rva_start": TABLE_RVA,
            "rva_end": 0x2400,
            "readable": True,
            "writable": writable_table,
            "executable": False,
        },
    ]


def _reader(table_bytes: bytes):
    def read_rva(rva: int, size: int) -> bytes:
        if not TABLE_RVA <= rva <= TABLE_RVA + len(table_bytes):
            return b""
        offset = rva - TABLE_RVA
        return table_bytes[offset : offset + size]

    return read_rva


def _table_bytes(target_rvas: list[int]) -> bytes:
    return b"".join(
        (IMAGE_BASE + target_rva).to_bytes(4, "little")
        for target_rva in target_rvas
    )


__all__ = [name for name in globals() if not name.startswith("__")]
