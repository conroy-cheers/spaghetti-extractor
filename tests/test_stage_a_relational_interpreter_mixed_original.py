from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from pe_fixtures import pe32_image, pe32_import_image
from stage_a_relational_support import _pe32_image_with_relocation_pointer_table

from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    InterpreterMixedOriginalGenerationError,
    InterpreterMixedOriginalSpec,
    OriginalIATImport,
    OriginalImportIdentity,
    OriginalMachineImportBoundaryBindings,
    OriginalMachineImportBoundarySiteProposal,
    OriginalModuleBindings,
    OriginalPERecoveryInput,
    OriginalRegisterCodePointerBinding,
    OriginalRegisterImportBinding,
    QualifiedLeanSymbol,
    _lean_index_ref_tree,
    load_original_iat_import_proposals,
    load_original_pe_recovery_input,
    plan_interpreter_mixed_original,
    write_relational_interpreter_mixed_original,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_terminal import (
    InterpreterMixedTerminalProposal,
)


def _record(
    rva: int,
    outcome: dict[str, object],
    *,
    edges: list[int] | None = None,
    ordered: list[dict[str, object]] | None = None,
    external: list[dict[str, object]] | None = None,
    **extra: object,
) -> dict[str, object]:
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
        "outcome": outcome,
        "edge_conditions": [
            {"target_rva": target, "condition": {"op": "true"}}
            for target in (edges or [])
        ],
        "ordered_events": ordered or [],
        "external_events": external or [],
        **extra,
    }


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _pe32_static_indirect_image() -> bytes:
    image_base = 0x400000
    table_rva = 0x2000
    slot_rva = table_rva + 8
    image = bytearray(
        _pe32_image_with_relocation_pointer_table(table_rva, mask_index=True)
    )
    code = bytearray(b"\x90" * 0x41)
    code[0:10] = (
        b"\x83\xe2\x01\xff\x24\x95"
        + (image_base + table_rva).to_bytes(4, "little")
    )
    code[0x10:0x17] = (
        b"\xb8"
        + (image_base + 0x1030).to_bytes(4, "little")
        + b"\xff\xe0"
    )
    code[0x20:0x26] = (
        b"\xff\x25" + (image_base + slot_rva).to_bytes(4, "little")
    )
    code[0x30] = 0xC3
    code[0x40] = 0xC3
    image[0x200 : 0x200 + len(code)] = code
    struct.pack_into("<I", image, 0x178 + 8, len(code))

    struct.pack_into(
        "<III",
        image,
        0x400,
        image_base + 0x1010,
        image_base + 0x1020,
        image_base + 0x1040,
    )
    data_header = 0x178 + 40
    struct.pack_into("<I", image, data_header + 8, 12)
    struct.pack_into("<I", image, data_header + 36, 0x40000040)

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        return (
            struct.pack("<II", page_rva, 8 + len(entries) * 2)
            + struct.pack("<" + "H" * len(entries), *entries)
        )

    relocations = relocation_block(0x1000, [6, 0x11, 0x22]) + relocation_block(
        table_rva, [0, 4, 8]
    )
    image[0x600 : 0x800] = relocations.ljust(0x200, b"\0")
    struct.pack_into("<I", image, 0x178 + 80 + 8, len(relocations))
    struct.pack_into("<II", image, 0x120, 0x5000, len(relocations))
    return bytes(image)


def _static_indirect_rows() -> list[dict[str, object]]:
    image_base = 0x400000
    table_va = image_base + 0x2000
    slot_va = table_va + 8
    index = {
        "op": "and32",
        "args": [
            {"op": "reg", "name": "edx", "width": 32},
            {"op": "const", "value": 1, "width": 32},
        ],
    }
    return [
        {
            **_record(
                0x1000,
                {
                    "kind": "indirect_jump",
                    "target": {
                        "op": "load",
                        "width": 4,
                        "address": {
                            "op": "add32",
                            "args": [
                                {"op": "const", "value": table_va, "width": 32},
                                {
                                    "op": "mul32",
                                    "args": [
                                        index,
                                        {"op": "const", "value": 4, "width": 32},
                                    ],
                                },
                            ],
                        },
                    },
                },
                instructions=[
                    {"rva": 0x1000, "size": 3, "mnemonic": "and"},
                    {"rva": 0x1003, "size": 7, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1000, "rva_end": 0x100A, "size": 10},
        },
        {
            **_record(
                0x1010,
                {
                    "kind": "indirect_jump",
                    "target": {
                        "op": "const",
                        "value": image_base + 0x1030,
                        "width": 32,
                    },
                },
                instructions=[
                    {"rva": 0x1010, "size": 5, "mnemonic": "mov"},
                    {"rva": 0x1015, "size": 2, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1010, "rva_end": 0x1017, "size": 7},
        },
        {
            **_record(
                0x1020,
                {
                    "kind": "indirect_jump",
                    "target": {
                        "op": "load",
                        "width": 4,
                        "address": {
                            "op": "const",
                            "value": slot_va,
                            "width": 32,
                        },
                    },
                },
                instructions=[
                    {"rva": 0x1020, "size": 6, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1020, "rva_end": 0x1026, "size": 6},
        },
        _record(0x1030, {"kind": "return"}),
        _record(0x1040, {"kind": "return"}),
    ]


def _pe32_writable_static_word_call_image(
    *,
    overwrite: bool = False,
    relocation_count: int = 1,
    target_rva: int = 0x1040,
) -> bytes:
    image_base = 0x400000
    slot_rva = 0x2008
    slot_va = image_base + slot_rva
    image = bytearray(_pe32_static_indirect_image())
    code = bytearray(b"\x90" * 0x41)
    if overwrite:
        code[0:10] = (
            b"\xc7\x05"
            + slot_va.to_bytes(4, "little")
            + (image_base + target_rva).to_bytes(4, "little")
        )
        call_rva = 0x100A
    else:
        code[0:7] = b"\xc7\x04\x24\x07\x00\x00\x00"
        call_rva = 0x1007
    call_offset = call_rva - 0x1000
    code[call_offset : call_offset + 6] = b"\xff\x15" + slot_va.to_bytes(
        4, "little"
    )
    continuation_rva = call_rva + 6
    code[continuation_rva - 0x1000] = 0xC3
    code[0x40] = 0xC3
    image[0x200 : 0x200 + len(code)] = code
    struct.pack_into("<I", image, 0x178 + 8, len(code))
    struct.pack_into("<I", image, 0x408, image_base + target_rva)

    data_header = 0x178 + 40
    characteristics = struct.unpack_from("<I", image, data_header + 36)[0]
    struct.pack_into("<I", image, data_header + 36, characteristics | 0x80000000)

    data_relocation_entries = 0x600 + 16 + 8
    if relocation_count == 0:
        struct.pack_into("<H", image, data_relocation_entries + 4, 0)
    elif relocation_count == 2:
        struct.pack_into("<H", image, data_relocation_entries + 6, 0x3008)
    elif relocation_count != 1:
        raise AssertionError("unsupported fixture relocation count")
    return bytes(image)


def _writable_static_word_call_rows(
    *,
    overwrite: bool = False,
    target_rva: int = 0x1040,
    nested_stack_address: bool = False,
) -> list[dict[str, object]]:
    image_base = 0x400000
    slot_va = image_base + 0x2008
    if overwrite:
        call_rva = 0x100A
        write_address: dict[str, object] = {
            "op": "const",
            "value": slot_va,
            "width": 32,
        }
        instructions = [
            {"rva": 0x1000, "size": 10, "mnemonic": "mov"},
            {"rva": call_rva, "size": 6, "mnemonic": "call"},
        ]
    else:
        call_rva = 0x1007
        write_address = (
            {
                "op": "sub32",
                "args": [
                    {
                        "op": "sub32",
                        "args": [
                            {"op": "reg", "name": "esp", "width": 32},
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    },
                    {"op": "const", "value": 24, "width": 32},
                ],
            }
            if nested_stack_address
            else {"op": "reg", "name": "esp", "width": 32}
        )
        instructions = [
            {"rva": 0x1000, "size": 7, "mnemonic": "mov"},
            {"rva": call_rva, "size": 6, "mnemonic": "call"},
        ]
    continuation_rva = call_rva + 6
    return [
        {
            **_record(
                0x1000,
                {"kind": "fallthrough", "target_rva": continuation_rva},
                edges=[continuation_rva],
                ordered=[
                    {
                        "kind": "write",
                        "instruction_rva": 0x1000,
                        "address": write_address,
                        "value": {"op": "const", "value": 7, "width": 32},
                        "width": 4,
                    },
                    {
                        "kind": "internal_call",
                        "instruction_rva": call_rva,
                        "return_rva": continuation_rva,
                        "target_rva": target_rva,
                    },
                ],
                instructions=instructions,
            ),
            "original": {
                "rva_start": 0x1000,
                "rva_end": continuation_rva,
                "size": continuation_rva - 0x1000,
            },
        },
        _record(continuation_rva, {"kind": "return"}),
        _record(0x1040, {"kind": "return"}),
    ]


def _pe32_register_code_pointer_image(*, ambiguous: bool = False) -> bytes:
    image_base = 0x400000
    image = bytearray(_pe32_static_indirect_image())
    code = bytearray(b"\x90" * 0x51)
    code[0:10] = (
        b"\xbb"
        + (image_base + 0x1030).to_bytes(4, "little")
        + b"\xe9\x06\x00\x00\x00"
    )
    code[0x10:0x16] = b"\x90\xe9\x0a\x00\x00\x00"
    code[0x20:0x22] = b"\xff\xd3"
    code[0x22] = 0xC3
    code[0x30] = 0xC3
    code[0x40:0x4A] = (
        b"\xbb"
        + (image_base + 0x1050).to_bytes(4, "little")
        + b"\xe9\xd6\xff\xff\xff"
    )
    code[0x50] = 0xC3
    image[0x200 : 0x200 + len(code)] = code
    struct.pack_into("<I", image, 0x178 + 8, len(code))

    offsets = [1, 0x41] if ambiguous else [1]
    entries = [0x3000 | offset for offset in offsets]
    if len(entries) % 2:
        entries.append(0)
    relocations = (
        struct.pack("<II", 0x1000, 8 + len(entries) * 2)
        + struct.pack("<" + "H" * len(entries), *entries)
    )
    image[0x600 : 0x800] = relocations.ljust(0x200, b"\0")
    struct.pack_into("<I", image, 0x178 + 80 + 8, len(relocations))
    struct.pack_into("<II", image, 0x120, 0x5000, len(relocations))
    return bytes(image)


def _register_code_pointer_rows(*, ambiguous: bool = False) -> list[dict[str, object]]:
    target = {"op": "reg", "name": "ebx", "width": 32}
    rows = [
        {
            **_record(
                0x1000,
                {"kind": "jump", "target_rva": 0x1010},
                edges=[0x1010],
                instructions=[
                    {"rva": 0x1000, "size": 5, "mnemonic": "mov"},
                    {"rva": 0x1005, "size": 5, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1000, "rva_end": 0x100A, "size": 10},
        },
        {
            **_record(
                0x1010,
                {"kind": "jump", "target_rva": 0x1020},
                edges=[0x1020],
                instructions=[
                    {"rva": 0x1010, "size": 1, "mnemonic": "nop"},
                    {"rva": 0x1011, "size": 5, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1010, "rva_end": 0x1016, "size": 6},
        },
        {
            **_record(
                0x1020,
                {"kind": "fallthrough", "target_rva": 0x1022},
                edges=[0x1022],
                ordered=[
                    {
                        "kind": "indirect_call",
                        "instruction_rva": 0x1020,
                        "return_rva": 0x1022,
                        "target": target,
                    }
                ],
                instructions=[{"rva": 0x1020, "size": 2, "mnemonic": "call"}],
            ),
            "original": {"rva_start": 0x1020, "rva_end": 0x1022, "size": 2},
        },
        _record(0x1022, {"kind": "return"}),
        _record(0x1030, {"kind": "return"}),
    ]
    if ambiguous:
        rows.extend(
            [
                {
                    **_record(
                        0x1040,
                        {"kind": "jump", "target_rva": 0x1020},
                        edges=[0x1020],
                        instructions=[
                            {"rva": 0x1040, "size": 5, "mnemonic": "mov"},
                            {"rva": 0x1045, "size": 5, "mnemonic": "jmp"},
                        ],
                    ),
                    "original": {
                        "rva_start": 0x1040,
                        "rva_end": 0x104A,
                        "size": 10,
                    },
                },
                _record(0x1050, {"kind": "return"}),
            ]
        )
    return rows


def _pe32_register_import_image() -> bytes:
    image_base = 0x400000
    iat_va = image_base + 0x2040
    code = bytearray(b"\x90" * 0x23)
    code[0:11] = (
        b"\x8b\x1d"
        + iat_va.to_bytes(4, "little")
        + b"\xe9\x05\x00\x00\x00"
    )
    code[0x10:0x16] = b"\x90\xe9\x0a\x00\x00\x00"
    code[0x20:0x22] = b"\xff\xd3"
    code[0x22] = 0xC3
    return pe32_import_image(bytes(code), symbol="TestImport")


def _register_import_rows() -> list[dict[str, object]]:
    return [
        {
            **_record(
                0x1000,
                {"kind": "jump", "target_rva": 0x1010},
                edges=[0x1010],
                instructions=[
                    {"rva": 0x1000, "size": 6, "mnemonic": "mov"},
                    {"rva": 0x1006, "size": 5, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1000, "rva_end": 0x100B, "size": 11},
        },
        {
            **_record(
                0x1010,
                {"kind": "jump", "target_rva": 0x1020},
                edges=[0x1020],
                instructions=[
                    {"rva": 0x1010, "size": 1, "mnemonic": "nop"},
                    {"rva": 0x1011, "size": 5, "mnemonic": "jmp"},
                ],
            ),
            "original": {"rva_start": 0x1010, "rva_end": 0x1016, "size": 6},
        },
        {
            **_record(
                0x1020,
                {"kind": "fallthrough", "target_rva": 0x1022},
                edges=[0x1022],
                ordered=[
                    {
                        "kind": "indirect_call",
                        "instruction_rva": 0x1020,
                        "return_rva": 0x1022,
                        "target": {"op": "reg", "name": "ebx", "width": 32},
                    }
                ],
                instructions=[{"rva": 0x1020, "size": 2, "mnemonic": "call"}],
            ),
            "original": {"rva_start": 0x1020, "rva_end": 0x1022, "size": 2},
        },
        _record(0x1022, {"kind": "return"}),
    ]


def _pe32_predecessor_bounded_table_image(*, rewrite_index: bool = False) -> bytes:
    image_base = 0x400000
    table_rva = 0x2000
    image = bytearray(_pe32_static_indirect_image())
    code = bytearray(b"\x90" * 0x41)
    if rewrite_index:
        code[0:7] = b"\x89\xc2\x80\xfa\x01\x77\x19"
        table_source_offset = 7
        code[table_source_offset : table_source_offset + 3] = b"\x0f\xb6\xd2"
        jump_offset = table_source_offset + 3
        out_of_range_offset = 0x20
    else:
        code[0:5] = b"\x83\xfa\x01\x77\x0b"
        table_source_offset = 5
        jump_offset = table_source_offset
        out_of_range_offset = 0x10
    code[jump_offset : jump_offset + 7] = (
        b"\xff\x24\x95" + (image_base + table_rva).to_bytes(4, "little")
    )
    code[out_of_range_offset] = 0xC3
    code[0x30] = 0xC3
    code[0x40] = 0xC3
    image[0x200 : 0x200 + len(code)] = code
    struct.pack_into("<II", image, 0x400, image_base + 0x1030, image_base + 0x1040)
    struct.pack_into("<I", image, 0x408, 0)

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        return (
            struct.pack("<II", page_rva, 8 + len(entries) * 2)
            + struct.pack("<" + "H" * len(entries), *entries)
        )

    relocations = relocation_block(0x1000, [jump_offset + 3]) + relocation_block(
        table_rva, [0, 4]
    )
    image[0x600 : 0x800] = relocations.ljust(0x200, b"\0")
    struct.pack_into("<I", image, 0x178 + 80 + 8, len(relocations))
    struct.pack_into("<II", image, 0x120, 0x5000, len(relocations))
    return bytes(image)


def _predecessor_bounded_table_rows(
    *, rewrite_index: bool = False
) -> list[dict[str, object]]:
    image_base = 0x400000
    table_va = image_base + 0x2000
    register_index = {"op": "reg", "name": "edx", "width": 32}
    index = (
        {
            "op": "and32",
            "args": [
                register_index,
                {"op": "const", "value": 255, "width": 32},
            ],
        }
        if rewrite_index
        else register_index
    )
    table_source_rva = 0x1007 if rewrite_index else 0x1005
    out_of_range_rva = 0x1020 if rewrite_index else 0x1010
    predecessor_instructions = (
        [
            {"rva": 0x1000, "size": 2, "mnemonic": "mov"},
            {"rva": 0x1002, "size": 3, "mnemonic": "cmp"},
            {"rva": 0x1005, "size": 2, "mnemonic": "ja"},
        ]
        if rewrite_index
        else [
            {"rva": 0x1000, "size": 3, "mnemonic": "cmp"},
            {"rva": 0x1003, "size": 2, "mnemonic": "ja"},
        ]
    )
    return [
        {
            **_record(
                0x1000,
                {
                    "kind": "branch",
                    "condition": {"op": "unsupported-test-shape"},
                    "true_target_rva": out_of_range_rva,
                    "false_target_rva": table_source_rva,
                },
                edges=[out_of_range_rva, table_source_rva],
                instructions=predecessor_instructions,
            ),
            "original": {
                "rva_start": 0x1000,
                "rva_end": table_source_rva,
                "size": table_source_rva - 0x1000,
            },
        },
        {
            **_record(
                table_source_rva,
                {
                    "kind": "indirect_jump",
                    "target": {
                        "op": "load",
                        "width": 4,
                        "address": {
                            "op": "add32",
                            "args": [
                                {"op": "const", "value": table_va, "width": 32},
                                {
                                    "op": "mul32",
                                    "args": [
                                        index,
                                        {"op": "const", "value": 4, "width": 32},
                                    ],
                                },
                            ],
                        },
                    },
                },
                instructions=(
                    [
                        {"rva": table_source_rva, "size": 3, "mnemonic": "movzx"},
                        {"rva": table_source_rva + 3, "size": 7, "mnemonic": "jmp"},
                    ]
                    if rewrite_index
                    else [{"rva": table_source_rva, "size": 7, "mnemonic": "jmp"}]
                ),
            ),
            "original": {
                "rva_start": table_source_rva,
                "rva_end": table_source_rva + (10 if rewrite_index else 7),
                "size": 10 if rewrite_index else 7,
            },
        },
        _record(out_of_range_rva, {"kind": "return"}),
        _record(0x1030, {"kind": "return"}),
        _record(0x1040, {"kind": "return"}),
    ]


def _pe32_state_independent_false_edge_image(
    *, exact_guard_false: bool = True,
) -> bytes:
    image_base = 0x400000
    assigned = image_base + 0x2000
    compared = assigned if exact_guard_false else assigned + 4
    text = (
        b"\xbb" + assigned.to_bytes(4, "little")
        + b"\x81\xfb" + compared.to_bytes(4, "little")
        + b"\x74\x03"
        + b"\xff\xd0"
        + b"\xc3"
        + b"\xc3"
    )
    return pe32_import_image(text, symbol="UnusedImport")


def _state_independent_false_edge_rows() -> list[dict[str, object]]:
    source = _record(
        0x1000,
        {
            "kind": "branch",
            "true_target_rva": 0x1010,
            "false_target_rva": 0x100D,
        },
        edges=[0x1010, 0x100D],
    )
    source["original"] = {
        "rva_start": 0x1000,
        "rva_end": 0x100D,
        "size": 13,
    }
    constant_true = {
        "op": "eq",
        "args": [
            {"op": "const", "width": 32, "value": 0},
            {"op": "const", "width": 32, "value": 0},
        ],
    }
    source["edge_conditions"] = [
        {"target_rva": 0x1010, "condition": constant_true},
        {
            "target_rva": 0x100D,
            "condition": {"op": "not", "args": [constant_true]},
        },
    ]
    indirect = _record(
        0x100D,
        {"kind": "fallthrough", "target_rva": 0x100F},
        edges=[0x100F],
        ordered=[
            {
                "kind": "indirect_call",
                "instruction_rva": 0x100D,
                "return_rva": 0x100F,
                "target": {"op": "reg", "name": "eax", "width": 32},
            }
        ],
    )
    indirect["original"] = {
        "rva_start": 0x100D,
        "rva_end": 0x100F,
        "size": 2,
    }
    return [
        source,
        indirect,
        _record(0x100F, {"kind": "return"}),
        _record(0x1010, {"kind": "return"}),
    ]


def _spec(**changes: object) -> InterpreterMixedOriginalSpec:
    base = InterpreterMixedOriginalSpec(
        bindings=OriginalModuleBindings(
            module="StageA.GeneratedTinyOriginalPE",
            namespace="StageA.GeneratedRelational.TinyOriginalPE",
        ),
        entry_rva=0x1000,
        shard_size=2,
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterMixedOriginalTests(unittest.TestCase):
    def test_shard_indexes_are_composed_by_checked_height(self) -> None:
        tree = _lean_index_ref_tree(
            [("shard0", 128), ("shard1", 134), ("shard2", 134)]
        )

        self.assertEqual(tree.size, 396)
        self.assertEqual(tree.height, 7)
        self.assertLessEqual(tree.maximum_balance, 1)
        self.assertIn(".branch 396", tree.expression)

    def test_shard_index_composition_rejects_unbalanceable_forest(self) -> None:
        with self.assertRaisesRegex(
            InterpreterMixedOriginalGenerationError,
            "cannot satisfy the checked balance invariant",
        ):
            _lean_index_ref_tree([("tiny", 1), ("large", 4096)])

    def test_state_independent_false_edge_cuts_indirect_cycle_from_roots(
        self,
    ) -> None:
        image = _pe32_state_independent_false_edge_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _state_independent_false_edge_rows())
            unbound = plan_interpreter_mixed_original(state_machine, _spec())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                path.read_text(encoding="utf-8")
                for path in written
                if path.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertFalse(unbound.complete)
        self.assertEqual(unbound.state_independent_false_edge_cuts, ())
        self.assertIn(
            "unresolved_indirect_control",
            {item.reason_code for item in unbound.blockers},
        )
        self.assertTrue(plan.complete, plan.blockers)
        self.assertEqual(plan.reachable_target_ids, (0, 3))
        self.assertEqual(len(plan.state_independent_false_edge_cuts), 1)
        cut = plan.state_independent_false_edge_cuts[0]
        self.assertEqual((cut.source_rva, cut.edge_rva), (0x1000, 0x100D))
        self.assertEqual(plan.regions[0].successor_ids, (3,))
        self.assertEqual(
            [item.reason_code for item in plan.diagnostics],
            ["unreachable_indirect_control"],
        )
        self.assertIn("generatedOriginalStateIndependentFalseEdgeCut0Checked", bundle)
        self.assertIn("generatedOriginalStateIndependentFalseEdgeCut0Impossible", bundle)
        self.assertNotIn("native_decide", bundle)

    def test_writable_static_word_call_requires_named_external_authority(
        self,
    ) -> None:
        image = _pe32_writable_static_word_call_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _writable_static_word_call_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
        self.assertFalse(plan.complete)
        self.assertEqual(len(plan.blockers), 1)
        self.assertEqual(
            plan.blockers[0].reason_code, "unresolved_indirect_control"
        )
        self.assertIn(
            "external-call memory-footprint preservation",
            plan.blockers[0].detail,
        )
        self.assertIn(
            "call-frame argument provenance", plan.blockers[0].detail
        )
        self.assertEqual(
            plan.to_json()["recovered_static_indirect_controls"], []
        )

    def test_writable_static_word_call_nested_stack_address_stays_incomplete(
        self,
    ) -> None:
        image = _pe32_writable_static_word_call_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(
                state_machine,
                _writable_static_word_call_rows(nested_stack_address=True),
            )
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )

        self.assertFalse(plan.complete)
        self.assertEqual(len(plan.blockers), 1)
        self.assertIn(
            "call-frame argument provenance", plan.blockers[0].detail
        )

    def test_writable_static_word_call_rejects_overwrite_and_code_alias(self) -> None:
        cases = (
            (
                "overwrite",
                _pe32_writable_static_word_call_image(overwrite=True),
                _writable_static_word_call_rows(overwrite=True),
                "write overlaps the writable pointer slot",
            ),
            (
                "alias",
                _pe32_writable_static_word_call_image(target_rva=0x103F),
                _writable_static_word_call_rows(target_rva=0x103F),
                "resolves through a code alias",
            ),
        )
        for label, image, rows, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pe = root / "original.exe"
                pe.write_bytes(image)
                state_machine = root / "state-machine.jsonl"
                _write_jsonl(state_machine, rows)
                plan = plan_interpreter_mixed_original(
                    state_machine,
                    _spec(
                        recovery_pe=OriginalPERecoveryInput(
                            pe, hashlib.sha256(image).hexdigest()
                        )
                    ),
                )

            self.assertFalse(plan.complete)
            unresolved = [
                blocker
                for blocker in plan.blockers
                if blocker.reason_code == "unresolved_indirect_control"
            ]
            self.assertEqual(len(unresolved), 1)
            self.assertIn(expected, unresolved[0].detail)

    def test_writable_static_word_call_requires_unique_relocation_and_code_target(
        self,
    ) -> None:
        cases = (
            (
                "missing relocation",
                _pe32_writable_static_word_call_image(relocation_count=0),
                "does not have exactly one HIGHLOW relocation",
            ),
            (
                "duplicate relocation",
                _pe32_writable_static_word_call_image(relocation_count=2),
                "does not have exactly one HIGHLOW relocation",
            ),
            (
                "non-code target",
                _pe32_writable_static_word_call_image(target_rva=0x2000),
                "is not an indexed executable code target",
            ),
        )
        for label, image, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                pe = root / "original.exe"
                pe.write_bytes(image)
                state_machine = root / "state-machine.jsonl"
                _write_jsonl(state_machine, _writable_static_word_call_rows())
                plan = plan_interpreter_mixed_original(
                    state_machine,
                    _spec(
                        recovery_pe=OriginalPERecoveryInput(
                            pe, hashlib.sha256(image).hexdigest()
                        )
                    ),
                )

            self.assertFalse(plan.complete)
            unresolved = [
                blocker
                for blocker in plan.blockers
                if blocker.reason_code == "unresolved_indirect_control"
            ]
            self.assertEqual(len(unresolved), 1)
            self.assertIn(expected, unresolved[0].detail)

    def test_register_code_pointer_provenance_is_exact_and_kernel_checkable(self) -> None:
        image = _pe32_register_code_pointer_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _register_code_pointer_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                path.read_text(encoding="utf-8")
                for path in written
                if path.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertTrue(plan.complete, plan.blockers)
        self.assertEqual(plan.reachable_target_ids, (0, 1, 2, 3, 4))
        binding = plan.regions[2].indirect_sites[0].static_binding
        self.assertIsInstance(binding, OriginalRegisterCodePointerBinding)
        self.assertEqual(binding.seed_target_ids, (0,))
        self.assertEqual(binding.preserve_target_ids, (1,))
        self.assertEqual(
            [(edge.source_target_id, edge.target_target_id) for edge in binding.edges],
            [(0, 1), (1, 2)],
        )
        recovered = plan.to_json()["recovered_static_indirect_controls"]
        self.assertEqual(recovered[0]["kind"], "register_fixed_code_pointer")
        self.assertEqual(recovered[0]["seed_relocation_rvas"], [0x1001])
        self.assertIn("FixedImmutableExprRegisterOutputClaim", bundle)
        self.assertIn("IdentityRegisterOutputClaim", bundle)
        self.assertIn("FixedCodePointerRegisterIndirectCallClaim", bundle)
        self.assertIn("outcome.registerRelationDirectTargets.contains", bundle)
        self.assertNotIn("native_decide", bundle)

    def test_register_import_provenance_uses_exact_iat_and_direct_edges(self) -> None:
        image = _pe32_register_import_image()
        identity = OriginalImportIdentity("KERNEL32.dll", "TestImport")
        imported = OriginalIATImport(
            iat_va=0x402040, iat_rva=0x2040, identity=identity
        )
        contracts = QualifiedLeanSymbol(
            module="StageA.GeneratedTinyMachineContracts",
            namespace="StageA.GeneratedRelational.TinyMachineContracts",
            symbol="contracts",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _register_import_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    bindings=dataclasses.replace(
                        _spec().bindings, machine_import_call_contracts=contracts
                    ),
                    iat_imports=(imported,),
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    ),
                ),
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                path.read_text(encoding="utf-8")
                for path in written
                if path.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertTrue(plan.complete, plan.blockers)
        binding = plan.regions[2].indirect_sites[0].static_binding
        self.assertIsInstance(binding, OriginalRegisterImportBinding)
        self.assertEqual(binding.imported, imported)
        self.assertEqual(binding.seed_target_ids, (0,))
        self.assertEqual(binding.preserve_target_ids, (1,))
        self.assertIn("ImportRegisterSeedClaim", bundle)
        self.assertIn("ImportRegisterPreserveClaim", bundle)
        self.assertIn("ImportRegisterIndirectCallClaim", bundle)
        self.assertIn("outcome.registerRelationDirectTargets.contains", bundle)
        self.assertNotIn("native_decide", bundle)

    def test_register_provenance_rejects_ambiguous_finite_join(self) -> None:
        image = _pe32_register_code_pointer_image(ambiguous=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(
                state_machine, _register_code_pointer_rows(ambiguous=True)
            )
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    tls_callback_rvas=(0x1040,),
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    ),
                ),
            )

        self.assertFalse(plan.complete)
        self.assertEqual(set(plan.reachable_target_ids), {0, 1, 2, 3, 5})
        unresolved = [
            blocker
            for blocker in plan.blockers
            if blocker.reason_code == "unresolved_indirect_control"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertIn("ambiguous finite register provenance alternatives", unresolved[0].detail)

    def test_predecessor_bound_closes_exact_relocation_table(self) -> None:
        image = _pe32_predecessor_bounded_table_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _predecessor_bounded_table_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                path.read_text(encoding="utf-8")
                for path in written
                if path.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertTrue(plan.complete, plan.blockers)
        self.assertEqual(plan.reachable_target_ids, (0, 1, 2, 3, 4))
        recovered = plan.to_json()["recovered_static_indirect_controls"]
        table = recovered[0]
        self.assertEqual(table["upper_exclusive"], 2)
        self.assertIsNone(table["index_mask"])
        self.assertEqual(
            table["predecessor_bounds"],
            [
                {
                    "predecessor_target_id": 0,
                    "predecessor_rva": 0x1000,
                    "index_width_bits": 32,
                }
            ],
        )
        self.assertIn("Predecessor0BoundClosed", bundle)
        self.assertIn("edgeWeakestPrecondition", bundle)
        self.assertIn("successorRangePredicate_eval", bundle)
        self.assertNotIn("IndexUniversallyBounded", bundle)
        self.assertNotIn("native_decide", bundle)

    def test_predecessor_table_bound_rejects_mismatched_exact_comparison(self) -> None:
        image = bytearray(_pe32_predecessor_bounded_table_image())
        image[0x202] = 2
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _predecessor_bounded_table_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )

        self.assertFalse(plan.complete)
        self.assertEqual(plan.reachable_target_ids, (0, 1, 2))
        unresolved = [
            blocker
            for blocker in plan.blockers
            if blocker.reason_code == "unresolved_indirect_control"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertIn(
            "comparison immediate does not match the exact table entry count",
            unresolved[0].detail,
        )

    def test_predecessor_table_bound_proves_rewritten_index_register(self) -> None:
        image = _pe32_predecessor_bounded_table_image(rewrite_index=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(
                state_machine,
                _predecessor_bounded_table_rows(rewrite_index=True),
            )
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                path.read_text(encoding="utf-8")
                for path in written
                if path.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertTrue(plan.complete, plan.blockers)
        self.assertEqual(plan.reachable_target_ids, (0, 1, 2, 3, 4))
        table = plan.to_json()["recovered_static_indirect_controls"][0]
        self.assertEqual(table["upper_exclusive"], 2)
        self.assertEqual(table["index_mask"], 255)
        self.assertEqual(table["predecessor_bounds"][0]["index_width_bits"], 8)
        self.assertIn("edgeWeakestPrecondition", bundle)
        self.assertIn("maskedSuccessorPredicate_eval", bundle)
        self.assertNotIn("native_decide", bundle)

    def test_static_indirect_controls_expand_rooted_closure_from_exact_pe(self) -> None:
        image = _pe32_static_indirect_image()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _static_indirect_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                path.read_text(encoding="utf-8")
                for path in written
                if path.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertTrue(plan.complete, plan.blockers)
        self.assertEqual(plan.reachable_target_ids, (0, 1, 2, 3, 4))
        recovered = plan.to_json()["recovered_static_indirect_controls"]
        self.assertEqual(
            [item["kind"] for item in recovered],
            [
                "bounded_immutable_relocation_table",
                "fixed_code_address",
                "immutable_pointer_slot",
            ],
        )
        self.assertEqual(plan.regions[0].successor_ids, (1, 2))
        self.assertEqual(plan.regions[1].successor_ids, (3,))
        self.assertEqual(plan.regions[2].successor_ids, (4,))
        self.assertIn("BoundedImmutableRelocationTableJumpControlClaim", bundle)
        self.assertIn("FixedCodeAddressIndirectJumpTargetClaim", bundle)
        self.assertIn("ImmutableIndirectJumpTargetClaim", bundle)
        self.assertIn("IndexUniversallyBounded", bundle)
        self.assertNotIn("native_decide", bundle)

    def test_writable_slot_initial_target_expands_reachability_without_authority(
        self,
    ) -> None:
        image = bytearray(_pe32_static_indirect_image())
        data_header = 0x178 + 40
        characteristics = struct.unpack_from("<I", image, data_header + 36)[0]
        struct.pack_into(
            "<I", image, data_header + 36, characteristics | 0x80000000
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _static_indirect_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    entry_rva=0x1020,
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    ),
                ),
            )

        self.assertFalse(plan.complete)
        self.assertEqual(plan.reachable_target_ids, (2, 4))
        site = plan.regions[2].indirect_sites[0]
        self.assertIsNone(site.static_binding)
        self.assertEqual(site.initial_target_ids, (4,))
        self.assertEqual(plan.regions[2].successor_ids, (4,))
        proposals = plan.to_json()["initial_writable_slot_target_proposals"]
        self.assertEqual(
            proposals,
            [{
                "acceptance_authority": False,
                "instruction_rva": 0x1020,
                "source_rva": 0x1020,
                "target_ids": [4],
                "target_rvas": [0x1040],
            }],
        )
        self.assertEqual(
            [blocker.reason_code for blocker in plan.blockers],
            ["unresolved_indirect_control"],
        )

    def test_static_table_recovery_rejects_duplicate_relocation_evidence(self) -> None:
        image = bytearray(_pe32_static_indirect_image())
        data_relocation_entries = 0x600 + 16 + 8
        struct.pack_into("<H", image, data_relocation_entries + 2, 0x3000)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, _static_indirect_rows())
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )

        self.assertFalse(plan.complete)
        self.assertEqual(plan.reachable_target_ids, (0,))
        unresolved = [
            blocker
            for blocker in plan.blockers
            if blocker.reason_code == "unresolved_indirect_control"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertIn("does not have exactly one HIGHLOW relocation", unresolved[0].detail)

    def test_submitted_jump_table_inventory_cannot_expand_reachability(self) -> None:
        rows = [
            {
                **_record(
                    0x1000,
                    {
                        "kind": "indirect_jump_table",
                        "target": {"op": "reg", "name": "eax", "width": 32},
                        "target_rvas": [0x1010],
                    },
                    instructions=[{"rva": 0x1000, "size": 1, "mnemonic": "jmp"}],
                )
            },
            _record(0x1010, {"kind": "return"}),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            state_machine = Path(temporary) / "state-machine.jsonl"
            _write_jsonl(state_machine, rows)
            plan = plan_interpreter_mixed_original(state_machine, _spec())

        self.assertFalse(plan.complete)
        self.assertEqual(plan.reachable_target_ids, (0,))
        self.assertEqual(plan.regions[0].successor_ids, ())
        self.assertIn(
            "submitted jump-table targets are untrusted",
            plan.blockers[0].detail,
        )

    def test_exact_noop_direct_target_gap_is_recovered_as_checked_alias(self) -> None:
        rows = [
            {
                **_record(
                    0x1000,
                    {"kind": "jump", "target_rva": 0x1005},
                    edges=[0x1005],
                ),
                "original": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1005,
                    "size": 5,
                },
            },
            _record(0x1008, {"kind": "return"}),
        ]
        image = pe32_image(b"\xe9\x00\x00\x00\x00\x90\x90\x90\xc3")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            path = root / "state-machine.jsonl"
            _write_jsonl(path, rows)
            plan = plan_interpreter_mixed_original(
                path,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            written = write_relational_interpreter_mixed_original(
                root / "out", plan
            )
            shard = next(
                item.read_text(encoding="utf-8")
                for item in written
                if "Shard" in item.name
            )
            bundle = next(
                item.read_text(encoding="utf-8")
                for item in written
                if item.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )
        self.assertTrue(plan.complete, plan.blockers)
        self.assertEqual(plan.reachable_target_ids, (0, 1))
        self.assertEqual(plan.regions[0].successor_ids, (1,))
        self.assertEqual(plan.regions[1].alias_rvas, (0x1005,))
        self.assertEqual(
            [
                (item.alias_rva, item.canonical_rva, item.size)
                for item in plan.recovered_aliases
            ],
            [(0x1005, 0x1008, 3)],
        )
        self.assertIn("rva := 4101, paddingIndex := 0", shard)
        self.assertIn("kind := .alias 0", shard)
        self.assertIn("size := 3", bundle)

    def test_direct_target_recovery_fails_closed_on_non_noop_or_bad_hash(
        self,
    ) -> None:
        rows = [
            {
                **_record(
                    0x1000,
                    {"kind": "jump", "target_rva": 0x1005},
                    edges=[0x1005],
                ),
                "original": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1005,
                    "size": 5,
                },
            },
            _record(0x1008, {"kind": "return"}),
        ]
        image = pe32_image(b"\xe9\x00\x00\x00\x00\x40\x90\x90\xc3")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(image)
            path = root / "state-machine.jsonl"
            _write_jsonl(path, rows)
            plan = plan_interpreter_mixed_original(
                path,
                _spec(
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(image).hexdigest()
                    )
                ),
            )
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError,
                "SHA-256 does not match",
            ):
                plan_interpreter_mixed_original(
                    path,
                    _spec(
                        recovery_pe=OriginalPERecoveryInput(pe, "0" * 64)
                    ),
                )

        self.assertFalse(plan.complete)
        self.assertEqual(plan.recovered_aliases, ())
        self.assertIn(
            "instruction inc eax is not a strict no-op",
            plan.blockers[0].detail,
        )

    def test_closed_inventory_is_indexed_from_roots_without_status_fields(self) -> None:
        rows = [
            _record(
                0x1000,
                {"kind": "jump", "target_rva": 0x1010},
                edges=[0x1010],
                status="violated",
                reachable=False,
            ),
            _record(0x1010, {"kind": "return"}, status="incomplete"),
            _record(0x1020, {"kind": "return"}, status="pass"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state-machine.jsonl"
            _write_jsonl(path, rows)
            plan = plan_interpreter_mixed_original(path, _spec())

        self.assertTrue(plan.complete)
        self.assertEqual(plan.reachable_target_ids, (0, 1))
        self.assertEqual([region.target_id for region in plan.regions], [0, 1, 2])
        self.assertEqual(plan.regions[0].successor_ids, (1,))
        self.assertFalse(plan.regions[2].root)
        self.assertIn("status", plan.ignored_fields)

    def test_duplicate_rva_and_inconsistent_root_fail_before_generation(self) -> None:
        duplicate = [_record(0x1000, {"kind": "return"})] * 2
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state-machine.jsonl"
            _write_jsonl(path, duplicate)
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError, "duplicate original RVA"
            ):
                plan_interpreter_mixed_original(path, _spec())

            overlapping = [
                {
                    **_record(0x1000, {"kind": "return"}),
                    "original": {
                        "rva_start": 0x1000,
                        "rva_end": 0x1002,
                        "size": 2,
                    },
                },
                _record(0x1001, {"kind": "return"}),
            ]
            _write_jsonl(path, overlapping)
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError, "overlapping original regions"
            ):
                plan_interpreter_mixed_original(path, _spec())

            aliased = _record(0x1000, {"kind": "return"})
            aliased["original"] = {
                "rva_start": 0x1000,
                "rva_end": 0x1001,
                "size": 1,
                "aliases": [0x1002],
            }
            _write_jsonl(path, [aliased])
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError, "unsupported alias facts"
            ):
                plan_interpreter_mixed_original(path, _spec())

            _write_jsonl(path, [_record(0x1010, {"kind": "return"})])
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError, "launch root"
            ):
                plan_interpreter_mixed_original(path, _spec())

    def test_only_reachable_missing_successors_block_rooted_authority(self) -> None:
        rows = [
            _record(
                0x1000,
                {"kind": "jump", "target_rva": 0x1010},
                edges=[0x1010],
            ),
            _record(
                0x1010,
                {"kind": "indirect_jump", "target": {"op": "reg"}},
                instructions=[{"rva": 0x1010, "size": 1, "bytes": "ff"}],
            ),
            _record(
                0x1020,
                {"kind": "jump", "target_rva": 0xDEAD},
                edges=[0xDEAD],
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state-machine.jsonl"
            _write_jsonl(path, rows)
            plan = plan_interpreter_mixed_original(path, _spec())

        self.assertFalse(plan.complete)
        reasons = {blocker.reason_code for blocker in plan.blockers}
        self.assertIn("unresolved_indirect_control", reasons)
        self.assertNotIn("missing_reachable_successor", reasons)
        self.assertEqual(
            [item.reason_code for item in plan.diagnostics],
            ["unreachable_missing_successor"],
        )
        self.assertEqual(plan.regions[2].missing_successor_rvas, (0xDEAD,))
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                InterpreterMixedOriginalGenerationError,
                "refusing to emit original authority",
            ):
                write_relational_interpreter_mixed_original(temporary, plan)

        reachable_missing = [
            _record(
                0x1000,
                {"kind": "jump", "target_rva": 0xDEAD},
                edges=[0xDEAD],
            ),
            _record(0x1020, {"kind": "return"}),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state-machine.jsonl"
            _write_jsonl(path, reachable_missing)
            blocked = plan_interpreter_mixed_original(path, _spec())
        self.assertEqual(
            [item.reason_code for item in blocked.blockers],
            ["missing_reachable_successor"],
        )
        self.assertEqual(blocked.regions[0].missing_successor_rvas, (0xDEAD,))

    def test_unreachable_missing_successor_does_not_block_rooted_emission(self) -> None:
        rows = [
            _record(0x1000, {"kind": "return"}),
            _record(
                0x1020,
                {"kind": "jump", "target_rva": 0xDEAD},
                edges=[0xDEAD],
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "state-machine.jsonl"
            _write_jsonl(path, rows)
            plan = plan_interpreter_mixed_original(path, _spec())
            written = write_relational_interpreter_mixed_original(root / "out", plan)

        self.assertTrue(plan.complete)
        self.assertEqual(plan.reachable_target_ids, (0,))
        self.assertEqual(plan.reachable_missing_successors, ())
        self.assertEqual(
            [item.reason_code for item in plan.diagnostics],
            ["unreachable_missing_successor"],
        )
        self.assertTrue(any(item.suffix == ".lean" for item in written))

    def test_terminal_boundary_recovers_padding_and_cuts_only_its_continuation(
        self,
    ) -> None:
        source = _record(
            0x1000,
            {"kind": "direct_call", "target_rva": 0x1010},
            edges=[0x1010, 0x1005],
        )
        source["original"] = {
            "rva_start": 0x1000,
            "rva_end": 0x1005,
            "size": 5,
        }
        rows = [source, _record(0x1010, {"kind": "return"})]
        proposal = InterpreterMixedTerminalProposal(
            boundary_id=7,
            signature_id=3,
            source_rva=0x1000,
            source_size=5,
            instruction_rva=0x1000,
            execution_source_rva=0x1010,
            continuation_rva=0x1005,
        )
        contracts = QualifiedLeanSymbol(
            module="StageA.GeneratedTinyBoundaries",
            namespace="StageA.GeneratedRelational.TinyBoundaries",
            symbol="generatedMachineImportBoundaryContracts",
        )
        boundaries = OriginalMachineImportBoundaryBindings(
            signatures=QualifiedLeanSymbol(
                module="StageA.GeneratedTinyBoundaries",
                namespace="StageA.GeneratedRelational.TinyBoundaries",
                symbol="generatedMachineImportSignatures",
            ),
            boundaries=QualifiedLeanSymbol(
                module="StageA.GeneratedTinyBoundaries",
                namespace="StageA.GeneratedRelational.TinyBoundaries",
                symbol="generatedMachineImportBoundaries",
            ),
            inventory=QualifiedLeanSymbol(
                module="StageA.GeneratedTinyBoundaries",
                namespace="StageA.GeneratedRelational.TinyBoundaries",
                symbol="generatedMachineImportBoundaryCallContracts",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = root / "original.exe"
            pe.write_bytes(pe32_image(b"\xe8\x0b\x00\x00\x00" + b"\x90" * 11 + b"\xc3"))
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, rows)
            bindings = dataclasses.replace(
                _spec().bindings,
                machine_import_call_contracts=contracts,
                machine_import_boundaries=boundaries,
            )
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    bindings=bindings,
                    recovery_pe=OriginalPERecoveryInput(
                        pe, hashlib.sha256(pe.read_bytes()).hexdigest()
                    ),
                    terminal_boundary_proposals=(proposal,),
                    machine_import_boundary_sites=(
                        OriginalMachineImportBoundarySiteProposal(
                            boundary_id=7,
                            execution_source_rva=0x1010,
                            execution_size=1,
                            continuation_rva=0x1005,
                        ),
                    ),
                ),
            )
            written = write_relational_interpreter_mixed_original(
                root / "out", plan
            )
            bundle = next(
                item.read_text(encoding="utf-8")
                for item in written
                if item.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertTrue(plan.complete)
        self.assertEqual([region.rva for region in plan.regions], [0x1000, 0x1005, 0x1010])
        self.assertEqual(plan.regions[0].successor_ids, (2,))
        self.assertTrue(plan.regions[1].synthetic_terminal_padding)
        self.assertEqual(plan.reachable_target_ids, (0, 2))
        self.assertEqual(len(plan.terminal_successor_cuts), 1)
        self.assertEqual(plan.terminal_successor_cuts[0].continuation_target_id, 1)
        self.assertIn("generatedOriginalTerminalSuccessorCutsChecked", bundle)
        self.assertIn("originalTerminalSuccessorCutsValid", bundle)
        self.assertIn("syntheticPadding := true", bundle)

    def test_external_imports_require_contract_binding(self) -> None:
        event = {
            "kind": "external_call",
            "dll": "KERNEL32.dll",
            "symbol": "ExitProcess",
            "ordinal": None,
        }
        rows = [
            _record(
                0x1000,
                {
                    "kind": "external_jump",
                    "dll": "KERNEL32.dll",
                    "symbol": "ExitProcess",
                    "ordinal": None,
                },
                external=[event],
            )
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state-machine.jsonl"
            _write_jsonl(path, rows)
            incomplete = plan_interpreter_mixed_original(path, _spec())
            contract_binding = QualifiedLeanSymbol(
                module="StageA.GeneratedTinyMachineContracts",
                namespace="StageA.GeneratedRelational.TinyMachineContracts",
                symbol="contracts",
            )
            bound_spec = dataclasses.replace(
                _spec().bindings,
                machine_import_call_contracts=contract_binding,
            )
            complete = plan_interpreter_mixed_original(
                path, _spec(bindings=bound_spec)
            )
            written = write_relational_interpreter_mixed_original(
                Path(temporary) / "out", complete
            )
            bundle = next(
                item.read_text(encoding="utf-8")
                for item in written
                if item.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertEqual(len(incomplete.import_identities), 1)
        self.assertIn(
            "machine_import_contracts_unbound",
            {blocker.reason_code for blocker in incomplete.blockers},
        )
        self.assertTrue(complete.complete)
        self.assertIn("import StageA.GeneratedTinyMachineContracts", bundle)
        self.assertIn(
            "StageA.GeneratedRelational.TinyMachineContracts.contracts", bundle
        )
        generation_input = incomplete.to_json()["machine_contract_generation_input"]
        self.assertEqual(
            generation_input["required_import_identities"],
            [
                {
                    "dll": "KERNEL32.dll",
                    "symbol": "ExitProcess",
                    "ordinal": None,
                }
            ],
        )

    def test_boundary_indexed_contracts_project_exact_site_ids_in_lean(self) -> None:
        contracts = QualifiedLeanSymbol(
            module="StageA.GeneratedTinyBoundaries",
            namespace="StageA.GeneratedRelational.TinyBoundaries",
            symbol="generatedMachineImportBoundaryContracts",
        )
        boundaries = OriginalMachineImportBoundaryBindings(
            signatures=QualifiedLeanSymbol(
                module="StageA.GeneratedTinyBoundaries",
                namespace="StageA.GeneratedRelational.TinyBoundaries",
                symbol="generatedMachineImportSignatures",
            ),
            boundaries=QualifiedLeanSymbol(
                module="StageA.GeneratedTinyBoundaries",
                namespace="StageA.GeneratedRelational.TinyBoundaries",
                symbol="generatedMachineImportBoundaries",
            ),
            inventory=QualifiedLeanSymbol(
                module="StageA.GeneratedTinyBoundaries",
                namespace="StageA.GeneratedRelational.TinyBoundaries",
                symbol="generatedMachineImportBoundaryCallContracts",
            ),
        )
        rows = [_record(0x1000, {"kind": "return"})]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_machine = root / "state-machine.jsonl"
            _write_jsonl(state_machine, rows)
            bindings = dataclasses.replace(
                _spec().bindings,
                machine_import_call_contracts=contracts,
                machine_import_boundaries=boundaries,
            )
            plan = plan_interpreter_mixed_original(
                state_machine,
                _spec(
                    bindings=bindings,
                    machine_import_boundary_sites=(
                        OriginalMachineImportBoundarySiteProposal(
                            boundary_id=0,
                            execution_source_rva=0x1000,
                            execution_size=1,
                            continuation_rva=0x1000,
                        ),
                    ),
                ),
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                item.read_text(encoding="utf-8")
                for item in written
                if item.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )

        self.assertIn("generatedOriginalMachineImportBoundarySiteBindings", bundle)
        self.assertIn("boundaryId := 0", bundle)
        self.assertIn("sourceTargetId := 0", bundle)
        self.assertNotIn(".map fun boundary", bundle)
        self.assertIn("staticMachineImportBoundarySiteBindingsValid", bundle)
        self.assertIn("generatedOriginalExternalCallSites", bundle)
        self.assertIn(
            "generatedOriginalCarrierRegionIndex.get? targetId", bundle
        )
        self.assertNotIn("generatedOriginalCarrierRegions.get?", bundle)
        self.assertNotIn("native_decide", bundle)

    def test_iat_call_binding_requires_exact_proposal_and_machine_contracts(self) -> None:
        event = {
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1010,
            "target": {
                "op": "load",
                "width": 4,
                "address": {"op": "const", "width": 32, "value": 0x403000},
            },
        }
        rows = [
            _record(
                0x1000,
                {"kind": "fallthrough", "target_rva": 0x1010},
                ordered=[event],
            ),
            _record(0x1010, {"kind": "return"}),
        ]
        binding = QualifiedLeanSymbol(
            module="StageA.GeneratedTinyMachineContracts",
            namespace="StageA.GeneratedRelational.TinyMachineContracts",
            symbol="contracts",
        )
        imported = OriginalIATImport(
            iat_va=0x403000,
            iat_rva=0x3000,
            identity=OriginalImportIdentity("kernel32.dll", "ExitProcess"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state-machine.jsonl"
            _write_jsonl(path, rows)
            no_iat = plan_interpreter_mixed_original(
                path,
                _spec(bindings=dataclasses.replace(
                    _spec().bindings, machine_import_call_contracts=binding
                )),
            )
            bound = plan_interpreter_mixed_original(
                path,
                _spec(
                    bindings=dataclasses.replace(
                        _spec().bindings, machine_import_call_contracts=binding
                    ),
                    iat_imports=(imported,),
                ),
            )

        self.assertEqual(no_iat.indirect_sites[0].category, "static_pointer_slot")
        self.assertIn(
            "unresolved_indirect_control",
            {item.reason_code for item in no_iat.blockers},
        )
        self.assertTrue(bound.complete, bound.blockers)
        self.assertEqual(bound.indirect_sites[0].category, "iat_thunk")
        self.assertEqual(bound.import_identities, (imported.identity,))

    def test_writer_is_deterministic_sharded_and_candidate_free(self) -> None:
        rows = [
            _record(0x1000, {"kind": "fallthrough", "target_rva": 0x1010}),
            _record(0x1010, {"kind": "fallthrough", "target_rva": 0x1020}),
            _record(0x1020, {"kind": "return"}),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "state-machine.jsonl"
            _write_jsonl(path, rows)
            plan = plan_interpreter_mixed_original(path, _spec())
            first = write_relational_interpreter_mixed_original(root / "out", plan)
            first_bytes = {item.relative_to(root / "out"): item.read_bytes() for item in first}
            second = write_relational_interpreter_mixed_original(root / "out", plan)
            second_bytes = {item.relative_to(root / "out"): item.read_bytes() for item in second}

        self.assertEqual(first_bytes, second_bytes)
        lean_sources = b"\n".join(
            value for path, value in first_bytes.items() if path.suffix == ".lean"
        )
        self.assertIn(b"generatedExactOriginalDecodedAuthority", lean_sources)
        self.assertIn(b"generatedExactOriginalDecodedReachability", lean_sources)
        self.assertIn(b"generatedExactMixedProgramBinding", lean_sources)
        self.assertNotIn(b"native_decide", lean_sources)
        self.assertIn(b"decide +kernel", lean_sources)
        self.assertNotIn(b"candidate mapping", lean_sources.lower())
        self.assertEqual(
            len([path for path in first_bytes if "Shard" in path.name]), 2
        )

    def test_two_tls_callbacks_emit_two_launch_frame_inventories(self) -> None:
        rows = [
            _record(0x1000, {"kind": "return"}),
            _record(0x1010, {"kind": "return"}),
            _record(0x1020, {"kind": "return"}),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "state-machine.jsonl"
            _write_jsonl(path, rows)
            plan = plan_interpreter_mixed_original(
                path, _spec(tls_callback_rvas=(0x1010, 0x1020))
            )
            written = write_relational_interpreter_mixed_original(root / "out", plan)
            bundle = next(
                item.read_text(encoding="utf-8")
                for item in written
                if item.name == "GeneratedRelationalInterpreterMixedOriginal.lean"
            )
            base = (
                root
                / "out"
                / "StageA"
                / "GeneratedRelationalInterpreterMixedOriginalBase.lean"
            ).read_text(encoding="utf-8")

        self.assertIn(
            "frameOffsets := [ReturnSlotOffsetInventory.zero, "
            "ReturnSlotOffsetInventory.zero]",
            bundle,
        )
        self.assertIn("tlsCallbackTargetIds := [1, 2]", base)
        self.assertIn("observations := { tls := true }", base)
        self.assertIn("generatedOriginalLaunchFrameCountChecked", bundle)

    def test_current_gnu_inventory_is_parsed_without_trusting_reachable(self) -> None:
        if os.environ.get("SPAGHETTI_TEST_LIVE_GNU_ARTIFACTS") != "1":
            self.skipTest(
                "set SPAGHETTI_TEST_LIVE_GNU_ARTIFACTS=1 to inspect ignored build artifacts"
            )
        root = Path(__file__).parents[1]
        state_machine = (
            root
            / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export-v3/state-machine.jsonl"
        )
        if not state_machine.is_file():
            self.skipTest("current GNU state-machine artifact is absent")
        spec = InterpreterMixedOriginalSpec(
            bindings=OriginalModuleBindings(
                module="StageA.GeneratedGnuHelloOriginalPE",
                namespace="StageA.GeneratedRelational.GnuHelloOriginalPE",
            ),
            entry_rva=0x1420,
            tls_callback_rvas=(0xA2F0, 0xA2A0),
            iat_imports=load_original_iat_import_proposals(
                root
                / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export-v3/reference-contract.json"
            ),
            recovery_pe=load_original_pe_recovery_input(
                root
                / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export-v3/reference-contract.json"
            ),
        )
        plan = plan_interpreter_mixed_original(state_machine, spec)

        self.assertEqual(len(plan.regions), 5326)
        self.assertEqual(len(plan.reachable_target_ids), 1042)
        self.assertFalse(plan.complete)
        counts = plan.to_json()["counts"]
        self.assertEqual(counts["blockers"], 28)
        self.assertEqual(counts["diagnostics"], 40)
        self.assertEqual(counts["recovered_direct_targets"], 94)
        self.assertEqual(counts["recovered_static_indirect_controls"], 22)
        self.assertEqual(
            {
                reason: sum(item.reason_code == reason for item in plan.blockers)
                for reason in {item.reason_code for item in plan.blockers}
            },
            {
                "machine_import_contracts_unbound": 1,
                "missing_reachable_successor": 1,
                "unresolved_indirect_control": 26,
            },
        )
        self.assertEqual(
            sum(item.reason_code == "unreachable_missing_successor"
                for item in plan.diagnostics),
            0,
        )
        self.assertEqual(
            len(plan.recovered_aliases)
            + sum(
                item.reason_code == "missing_reachable_successor"
                for item in plan.blockers
            )
            + sum(
                item.reason_code == "unreachable_missing_successor"
                for item in plan.diagnostics
            ),
            95,
        )
        originally_reachable_gaps = {
            0x11C9, 0x1303, 0x1406, 0x171F, 0x1BFA, 0x1C5F, 0x1D52,
            0x65B9, 0x66AD, 0xA213, 0xA32D, 0xA459, 0xA57E, 0xA5B7,
            0xA764, 0xA91D, 0xAB6D, 0xAD44, 0xD468, 0x11308, 0x12DE9,
            0x12E64, 0x141B1, 0x14625, 0x1462D, 0x14655,
        }
        self.assertTrue(
            originally_reachable_gaps.issubset(
                {item.alias_rva for item in plan.recovered_aliases}
            )
        )
        missing = [
            item for item in plan.blockers
            if item.reason_code == "missing_reachable_successor"
        ]
        self.assertEqual(missing[0].rva, 0x1466C)
        self.assertIn("0x14671", missing[0].detail)
        self.assertIn("no following canonical transfer", missing[0].detail)
        self.assertEqual(len(plan.indirect_sites), 49)
        self.assertEqual(
            sum(item.reason_code == "unreachable_indirect_control"
                for item in plan.diagnostics),
            40,
        )
        self.assertEqual(
            plan.to_json()["indirect_frontiers_by_category"],
            {
                "bounded_table_candidate": 4,
                "constant_internal_target": 1,
                "iat_thunk": 3,
                "register_function_pointer": 18,
                "register_tail_target": 1,
                "stack_or_dynamic_pointer": 3,
                "static_pointer_slot": 19,
            },
        )
        self.assertEqual(len(plan.import_identities), 56)
        recovered_indirect = plan.to_json()["recovered_static_indirect_controls"]
        recovered_tables = [
            item
            for item in recovered_indirect
            if item["kind"] == "bounded_immutable_relocation_table"
        ]
        self.assertEqual(
            [item["upper_exclusive"] for item in recovered_tables],
            [69, 10],
        )
        self.assertEqual(
            [item["index_mask"] for item in recovered_tables],
            [None, None],
        )
        self.assertTrue(
            all(len(item["predecessor_bounds"]) == 1 for item in recovered_tables)
        )
        self.assertEqual(
            [
                item
                for item in recovered_indirect
                if item["kind"] == "fixed_code_address"
            ],
            [
                {
                    "source_rva": 0x14160,
                    "instruction_rva": 0x1416D,
                    "is_call": False,
                    "continuation_rva": None,
                    "kind": "fixed_code_address",
                    "target_id": 5196,
                    "target_rva": 0x140D0,
                    "target_va": 0x4140D0,
                }
            ],
        )
        writable_slots = [
            item
            for item in recovered_indirect
            if item["kind"] == "writable_static_word_slot"
        ]
        self.assertEqual(len(writable_slots), 17)
        self.assertEqual(
            sum(
                item["slot_rva"] == 0x200D0
                and item["target_rva"] == 0x143A0
                for item in writable_slots
            ),
            15,
        )
        self.assertEqual(
            sum(item["assembled_read"] for item in writable_slots),
            14,
        )
        unresolved_details = "\n".join(
            blocker.detail
            for blocker in plan.blockers
            if blocker.reason_code == "unresolved_indirect_control"
        )
        self.assertIn("checked stack/dynamic-range provenance", unresolved_details)
        self.assertIn("register provenance crosses an uncontracted call", unresolved_details)
        self.assertIn("cycle without an inductive witness", unresolved_details)
        self.assertIn("readable, non-writable, non-executable", unresolved_details)
        self.assertIn(
            "masked table index register is rewritten before the exact bound comparison",
            unresolved_details,
        )
        self.assertEqual(
            {
                blocker.rva
                for blocker in plan.blockers
                if "pre-call memory write lacks register-offset no-alias framing"
                in blocker.detail
            },
            {0x1810, 0x189A},
        )


if __name__ == "__main__":
    unittest.main()
