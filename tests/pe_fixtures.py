"""Small synthetic PE images shared by Stage A and Stage B tests."""

from __future__ import annotations

import struct


def pe32_image(code: bytes, *, virtual_size: int | None = None) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw = 0x200
    text_raw_size = align(len(code), file_alignment)
    text_virtual_size = virtual_size if virtual_size is not None else len(code)
    size_of_image = align(text_rva + text_virtual_size, section_alignment)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, 0, 0, text_rva, text_rva, 0,
        0x400000, section_alignment, file_alignment, 4, 0, 0, 0, 4, 0,
        0, size_of_image, headers_size, 0, 3, 0, 0x100000, 0x1000,
        0x100000, 0x1000, 0, 16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", text_virtual_size, text_rva, text_raw_size,
        text_raw, 0, 0, 0, 0, 0x60000020,
    )
    headers = (bytes(dos) + b"PE\0\0" + coff + optional + section).ljust(
        headers_size, b"\0"
    )
    return headers + code.ljust(text_raw_size, b"\0")


def pe32_import_image(
    code: bytes,
    *,
    symbol: str,
    dll: str = "KERNEL32.dll",
    iat_offset: int = 0x40,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    idata_rva = 0x2000
    text_raw = 0x200
    text_raw_size = align(len(code), file_alignment)
    idata_raw = text_raw + text_raw_size
    idata_raw_size = 0x200
    size_of_image = align(idata_rva + idata_raw_size, section_alignment)

    int_rva = idata_rva + 0x30
    iat_rva = idata_rva + iat_offset
    dll_name_rva = idata_rva + 0x50
    import_name_rva = idata_rva + 0x80
    idata = bytearray(idata_raw_size)
    struct.pack_into("<IIIII", idata, 0, int_rva, 0, 0, dll_name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x30, import_name_rva, 0)
    struct.pack_into("<II", idata, iat_offset, import_name_rva, 0)
    idata[0x50 : 0x50 + len(dll) + 1] = dll.encode("ascii") + b"\0"
    name = symbol.encode("ascii")
    struct.pack_into("<H", idata, 0x80, 0)
    idata[0x82 : 0x82 + len(name) + 1] = name + b"\0"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, idata_raw_size, 0, text_rva,
        text_rva, idata_rva, image_base, section_alignment, file_alignment,
        4, 0, 0, 0, 4, 0, 0, size_of_image, headers_size, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    optional = bytearray(optional_prefix + (b"\0" * (16 * 8)))
    struct.pack_into("<II", optional, len(optional_prefix) + 8, idata_rva, 40)
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", len(code), text_rva, text_raw_size, text_raw,
        0, 0, 0, 0, 0x60000020,
    )
    idata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".idata\0\0", idata_raw_size, idata_rva, idata_raw_size,
        idata_raw, 0, 0, 0, 0, 0x40000040,
    )
    headers = (
        bytes(dos) + b"PE\0\0" + coff + bytes(optional)
        + text_section + idata_section
    ).ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0") + bytes(idata)


def pe32_image_with_pointer_slot(
    code: bytes,
    *,
    target_rva: int,
    slot_rva: int = 0x2040,
    writable: bool = False,
) -> bytes:
    """Build a two-section PE with one initialized absolute code pointer."""

    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    data_rva = 0x2000
    text_raw_size = align(len(code), file_alignment)
    data_raw_size = 0x200
    data_offset = slot_rva - data_rva
    if not 0 <= data_offset <= data_raw_size - 4:
        raise ValueError("pointer slot must fit in the synthetic data section")
    data = bytearray(data_raw_size)
    struct.pack_into("<I", data, data_offset, image_base + target_rva)
    size_of_image = align(data_rva + data_raw_size, section_alignment)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, data_raw_size, 0, text_rva,
        text_rva, data_rva, image_base, section_alignment, file_alignment,
        4, 0, 0, 0, 4, 0, 0, size_of_image, headers_size, 0, 3, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", len(code), text_rva, text_raw_size, headers_size,
        0, 0, 0, 0, 0x60000020,
    )
    data_characteristics = 0xC0000040 if writable else 0x40000040
    data_section = struct.pack(
        "<8sIIIIIIHHI",
        b".data\0\0\0", data_raw_size, data_rva, data_raw_size,
        headers_size + text_raw_size, 0, 0, 0, 0, data_characteristics,
    )
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional + text_section + data_section
    ).ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0") + bytes(data)


def pe32_tls_image(callback_rvas: tuple[int, ...]) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    rdata_rva = 0x2000
    text_raw_size = 0x200
    rdata_raw_size = 0x1000
    code = bytearray(text_raw_size)
    code[0] = 0xC3
    for callback_rva in callback_rvas:
        offset = callback_rva - text_rva
        if 0 <= offset <= text_raw_size - 3:
            code[offset : offset + 3] = b"\xc2\x0c\x00"
    text_virtual_size = max(
        [1, *(rva - text_rva + 3 for rva in callback_rvas)]
    )
    rdata = bytearray(rdata_raw_size)
    callback_array_offset = 0x40
    struct.pack_into(
        "<IIIIII",
        rdata,
        0,
        image_base + rdata_rva + 0x80,
        image_base + rdata_rva + 0x84,
        image_base + rdata_rva + 0x84,
        image_base + rdata_rva + callback_array_offset,
        0,
        0,
    )
    for index, callback_rva in enumerate(callback_rvas):
        struct.pack_into(
            "<I", rdata, callback_array_offset + index * 4, image_base + callback_rva
        )
    struct.pack_into("<I", rdata, callback_array_offset + len(callback_rvas) * 4, 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, rdata_raw_size, 0, text_rva, text_rva,
        rdata_rva, image_base, section_alignment, file_alignment, 4, 0, 0, 0,
        4, 0, 0, 0x3000, headers_size, 0, 3, 0, 0x100000, 0x1000,
        0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 9 * 8, rdata_rva, 24)
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", text_virtual_size, text_rva,
            text_raw_size, headers_size, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".rdata\0\0", rdata_raw_size, rdata_rva,
            rdata_raw_size, headers_size + text_raw_size, 0, 0, 0, 0, 0x40000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return headers + bytes(code) + bytes(rdata)


def pe32_image_with_writable_data(
    code: bytes,
    *,
    relocation_offsets: list[int],
    relocation_page_rva: int = 0x1000,
    data_size: int = 4,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    data_rva = 0x2000
    reloc_rva = 0x3000
    image_base = 0x400000
    entries = [0x3000 | offset for offset in relocation_offsets]
    if len(entries) % 2:
        entries.append(0)
    relocations = (
        struct.pack("<II", relocation_page_rva, 8 + 2 * len(entries))
        + struct.pack("<" + "H" * len(entries), *entries)
    )
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x400, 0, text_rva, text_rva, data_rva,
        image_base, section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0,
        0x4000, headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000,
        0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200, 0x200, 0, 0, 0, 0, 0x60000020),
        struct.pack("<8sIIIIIIHHI", b".data\0\0\0", data_size, data_rva, 0x200, 0x400, 0, 0, 0, 0, 0xC0000040),
        struct.pack("<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200, 0x600, 0, 0, 0, 0, 0x42000040),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + code.ljust(0x200, b"\0") + bytes(data_size).ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment
