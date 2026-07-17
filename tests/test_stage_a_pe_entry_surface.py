from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image

from spaghetti_extractor.stage_binary import (
    IMAGE_FILE_DLL,
    StageAExport,
    _parse_stage_a_pe,
)


PE_OFFSET = 0x80
OPTIONAL_OFFSET = PE_OFFSET + 4 + 20
EXPORT_DIRECTORY_ENTRY_OFFSET = OPTIONAL_OFFSET + 96
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224
EDATA_RAW = 0x600


class StageAPEEntrySurfaceTests(unittest.TestCase):
    def test_absent_export_directory_has_closed_empty_surface(self) -> None:
        binary = self._parse(pe32_image(b"\xc3"))

        self.assertEqual(binary.coff_characteristics, 0x010F)
        self.assertFalse(binary.is_dll)
        self.assertEqual(binary.exports, ())
        self.assertIsNone(binary.export_parse_error)

    def test_parses_exact_eat_with_code_data_forwarder_alias_and_ordinal(self) -> None:
        binary = self._parse(_pe32_export_surface_image())

        self.assertEqual(binary.coff_characteristics, 0x210F)
        self.assertEqual(binary.coff_characteristics & IMAGE_FILE_DLL, IMAGE_FILE_DLL)
        self.assertTrue(binary.is_dll)
        self.assertIsNone(binary.export_parse_error)
        self.assertEqual(
            binary.exports,
            (
                StageAExport(7, "code_alias", 0x1000, "code", None),
                StageAExport(7, "code_export", 0x1000, "code", None),
                StageAExport(8, "data_export", 0x2000, "data", None),
                StageAExport(
                    9,
                    "forwarded",
                    0x30E0,
                    "forwarder",
                    "OTHER.target",
                ),
                StageAExport(10, None, 0x1010, "code", None),
            ),
        )

    def test_accepts_zero_initialized_data_export_but_not_code(self) -> None:
        image = bytearray(_pe32_export_surface_image())
        image = _chain(
            _set_u32(SECTION_TABLE_OFFSET + 40 + 8, 0x300),
            _set_u32(EDATA_RAW + 0x44, 0x2250),
        )(image)

        binary = self._parse(bytes(image))

        self.assertIsNone(binary.export_parse_error)
        self.assertIsNotNone(binary.exports)
        self.assertIn(
            StageAExport(8, "data_export", 0x2250, "data", None),
            binary.exports or (),
        )

    def test_malformed_export_directories_discard_partial_results(self) -> None:
        cases = {
            "half-present directory": (
                _set_u32(EXPORT_DIRECTORY_ENTRY_OFFSET, 0),
                "RVA and size must either both be zero or both be nonzero",
            ),
            "short directory": (
                _set_u32(EXPORT_DIRECTORY_ENTRY_OFFSET + 4, 39),
                "smaller than IMAGE_EXPORT_DIRECTORY",
            ),
            "EAT outside directory": (
                _set_u32(EDATA_RAW + 28, 0x30FC),
                "export address table is outside the declared export span",
            ),
            "ordinal outside EAT": (
                _set_u16(EDATA_RAW + 0x70, 5),
                "name ordinal index is outside the EAT",
            ),
            "unmapped target": (
                _set_u32(EDATA_RAW + 0x40, 0x2500),
                "export target RVA is not mapped by the image",
            ),
            "named empty EAT slot": (
                _set_u32(EDATA_RAW + 0x40, 0),
                "named export refers to an empty EAT slot",
            ),
            "target in virtual tail": (
                _chain(
                    _set_u32(SECTION_TABLE_OFFSET + 8, 0x300),
                    _set_u32(EDATA_RAW + 0x40, 0x1250),
                ),
                "export target is not backed by exact file bytes",
            ),
            "unterminated forwarder": (
                _fill(EDATA_RAW + 0xE0, EDATA_RAW + 0x100, b"A"),
                "export forwarder is not NUL terminated",
            ),
            "truncated exact bytes": (
                _truncate(EDATA_RAW + 0xF0),
                "declared span extends beyond the exact file bytes",
            ),
        }

        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                image = bytearray(_pe32_export_surface_image())
                mutated = mutate(image)
                binary = self._parse(bytes(mutated))
                self.assertIsNone(binary.exports)
                self.assertIsNotNone(binary.export_parse_error)
                self.assertIn(expected_error, binary.export_parse_error or "")

    def _parse(self, data: bytes):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "entry-surface.dll"
            path.write_bytes(data)
            return _parse_stage_a_pe(path)


def _pe32_export_surface_image() -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    data_rva = 0x2000
    edata_rva = 0x3000
    text_raw = 0x200
    data_raw = 0x400
    section_raw_size = 0x200
    size_of_image = 0x4000
    export_size = 0x100

    edata = bytearray(section_raw_size)
    eat_rva = edata_rva + 0x40
    names_rva = edata_rva + 0x60
    ordinals_rva = edata_rva + 0x70
    dll_name_rva = edata_rva + 0x80
    export_name_rvas = (
        edata_rva + 0xA0,
        edata_rva + 0xB0,
        edata_rva + 0xC0,
        edata_rva + 0xD0,
    )
    forwarder_rva = edata_rva + 0xE0
    struct.pack_into(
        "<IIHHIIIIIII",
        edata,
        0,
        0,
        0,
        0,
        0,
        dll_name_rva,
        7,
        5,
        4,
        eat_rva,
        names_rva,
        ordinals_rva,
    )
    struct.pack_into(
        "<IIIII",
        edata,
        0x40,
        text_rva,
        data_rva,
        forwarder_rva,
        text_rva + 0x10,
        0,
    )
    struct.pack_into("<IIII", edata, 0x60, *export_name_rvas)
    struct.pack_into("<HHHH", edata, 0x70, 0, 0, 1, 2)
    _put_string(edata, 0x80, "entry.dll")
    _put_string(edata, 0xA0, "code_alias")
    _put_string(edata, 0xB0, "code_export")
    _put_string(edata, 0xC0, "data_export")
    _put_string(edata, 0xD0, "forwarded")
    _put_string(edata, 0xE0, "OTHER.target")

    dos = bytearray(PE_OFFSET)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, PE_OFFSET)
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        3,
        0,
        0,
        0,
        224,
        0x210F,
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        section_raw_size,
        section_raw_size * 2,
        0,
        text_rva,
        text_rva,
        data_rva,
        image_base,
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
    optional = bytearray(optional_prefix + b"\0" * (16 * 8))
    struct.pack_into("<II", optional, len(optional_prefix), edata_rva, export_size)
    text_section = _section_header(
        b".text", text_rva, text_raw, section_raw_size, 0x60000020
    )
    data_section = _section_header(
        b".data", data_rva, data_raw, section_raw_size, 0xC0000040
    )
    edata_section = _section_header(
        b".edata", edata_rva, EDATA_RAW, section_raw_size, 0x40000040
    )
    headers = (
        bytes(dos)
        + b"PE\0\0"
        + coff
        + bytes(optional)
        + text_section
        + data_section
        + edata_section
    ).ljust(headers_size, b"\0")
    text = (b"\xC3" + b"\x90" * 0x0F + b"\xC3").ljust(
        section_raw_size, b"\0"
    )
    return headers + text + bytes(section_raw_size) + bytes(edata)


def _section_header(
    name: bytes, rva: int, raw_pointer: int, raw_size: int, characteristics: int
) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\0"),
        raw_size,
        rva,
        raw_size,
        raw_pointer,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _put_string(data: bytearray, offset: int, value: str) -> None:
    encoded = value.encode("ascii") + b"\0"
    data[offset : offset + len(encoded)] = encoded


def _set_u32(offset: int, value: int):
    def mutate(data: bytearray) -> bytearray:
        struct.pack_into("<I", data, offset, value)
        return data

    return mutate


def _set_u16(offset: int, value: int):
    def mutate(data: bytearray) -> bytearray:
        struct.pack_into("<H", data, offset, value)
        return data

    return mutate


def _fill(start: int, end: int, value: bytes):
    def mutate(data: bytearray) -> bytearray:
        data[start:end] = value * (end - start)
        return data

    return mutate


def _truncate(size: int):
    def mutate(data: bytearray) -> bytearray:
        del data[size:]
        return data

    return mutate


def _chain(*mutations):
    def mutate(data: bytearray) -> bytearray:
        for mutation in mutations:
            data = mutation(data)
        return data

    return mutate


if __name__ == "__main__":
    unittest.main()
