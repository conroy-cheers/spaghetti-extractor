#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--text", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.write_bytes(pe32_image(args.text.read_bytes()))
    return 0


def pe32_image(code: bytes) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw = 0x200
    text_raw_size = align(len(code), file_alignment)
    size_of_image = align(text_rva + len(code), section_alignment)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        1,
        0,
        0,
        0,
        224,
        0x010F,
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        text_raw_size,
        0,
        0,
        text_rva,
        text_rva,
        0,
        0x400000,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        len(code),
        text_rva,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + b"PE\0\0" + coff + optional + section
    return headers.ljust(headers_size, b"\0") + code.ljust(text_raw_size, b"\0")


def align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


if __name__ == "__main__":
    raise SystemExit(main())
