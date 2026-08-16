from __future__ import annotations

import struct


def coff_object(code: bytes, *, symbol: str) -> bytes:
    raw_pointer = 20 + 40
    symbol_pointer = raw_pointer + len(code)
    header = struct.pack("<HHIIIHH", 0x014C, 1, 0, symbol_pointer, 2, 0, 0)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0,
        0,
        len(code),
        raw_pointer,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    encoded_name = symbol.encode("ascii")
    if len(encoded_name) > 8:
        raise ValueError("fixture symbol must fit in the COFF short-name field")
    symbol_row = struct.pack(
        "<8sIhHBB",
        encoded_name.ljust(8, b"\0"),
        0,
        1,
        0x20,
        2,
        1,
    )
    auxiliary = bytearray(18)
    struct.pack_into("<I", auxiliary, 4, len(code))
    return (
        header
        + section
        + code
        + symbol_row
        + bytes(auxiliary)
        + struct.pack("<I", 4)
    )


def archive(name: str, body: bytes) -> bytes:
    encoded_name = (name + "/").encode("ascii")
    header = (
        encoded_name.ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + str(len(body)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    return b"!<arch>\n" + header + body + (b"\n" if len(body) & 1 else b"")


def omf_record(record_type: int, payload: bytes) -> bytes:
    length = len(payload) + 1
    prefix = bytes([record_type]) + struct.pack("<H", length) + payload
    checksum = (-sum(prefix)) & 0xFF
    return prefix + bytes([checksum])


__all__ = ["archive", "coff_object", "omf_record"]
