from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_image, pe32_import_image

from spaghetti_extractor.stage_binary import (
    PE32_CONSOLE_PREFERRED_BASE_POLICY,
    StageALoaderDiagnosticSeverity,
    StageALoaderDiagnosticStatus,
    _parse_stage_a_pe,
    diagnose_pe32_loader_image,
)


PE_OFFSET = 0x80
COFF_OFFSET = PE_OFFSET + 4
OPTIONAL_OFFSET = COFF_OFFSET + 20
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224


class StageALoaderImageDiagnosticTests(unittest.TestCase):
    def test_valid_console_image_is_diagnostic_only(self) -> None:
        image = pe32_image(b"\xc3")

        first = diagnose_pe32_loader_image(image)
        second = diagnose_pe32_loader_image(image)

        self.assertEqual(first, second)
        self.assertEqual(first.policy, PE32_CONSOLE_PREFERRED_BASE_POLICY)
        self.assertEqual(
            first.status, StageALoaderDiagnosticStatus.DIAGNOSTIC_CLEAN
        )
        self.assertEqual(first.diagnostics, ())
        self.assertEqual(first.hard_diagnostics, ())
        self.assertEqual(first.conditional_warnings, ())
        self.assertFalse(first.authorizes_stage_a)

        binary = self._parse(image)
        self.assertEqual(binary.loader_diagnostics, first)
        self.assertFalse(binary.loader_diagnostics.authorizes_stage_a)
        self.assertEqual(first.as_payload(), {
            "policy": PE32_CONSOLE_PREFERRED_BASE_POLICY,
            "status": "diagnostic-clean",
            "authorizes_stage_a": False,
            "diagnostics": [],
        })

    def test_aligned_header_reservation_may_exceed_minimum(self) -> None:
        image = bytearray(pe32_image(b"\xc3"))
        image[0x200:0x200] = bytes(0x200)
        struct.pack_into("<I", image, OPTIONAL_OFFSET + 60, 0x400)
        struct.pack_into("<I", image, SECTION_TABLE_OFFSET + 20, 0x400)

        result = diagnose_pe32_loader_image(bytes(image))

        self.assertEqual(
            result.status, StageALoaderDiagnosticStatus.DIAGNOSTIC_CLEAN
        )
        self.assertEqual(result.diagnostics, ())

    def test_dynamic_base_is_a_conditional_launch_warning(self) -> None:
        image = _set_u16(
            pe32_image(b"\xc3"),
            OPTIONAL_OFFSET + 70,
            0x0040,
        )

        result = diagnose_pe32_loader_image(image)

        self.assertEqual(
            result.status, StageALoaderDiagnosticStatus.CONDITIONAL_LAUNCH
        )
        self.assertEqual(result.hard_diagnostics, ())
        self.assertEqual(
            tuple(
                (diagnostic.severity, diagnostic.code)
                for diagnostic in result.conditional_warnings
            ),
            ((
                StageALoaderDiagnosticSeverity.WARNING,
                "dynamic_base_requires_preferred_base",
            ),),
        )
        self.assertFalse(result.authorizes_stage_a)
        self.assertEqual(
            result.as_payload()["diagnostics"][0]["code"],
            "dynamic_base_requires_preferred_base",
        )

    def test_malformed_and_unknown_headers_are_hard_diagnostics(self) -> None:
        cases = {
            "short DOS header": (
                pe32_image(b"\xc3")[:0x3F],
                "dos_header_bounds",
            ),
            "PE header outside file": (
                _set_u32(pe32_image(b"\xc3"), 0x3C, 0x10000),
                "coff_header_bounds",
            ),
            "truncated section table": (
                pe32_image(b"\xc3")[: SECTION_TABLE_OFFSET + 39],
                "section_table_bounds",
            ),
            "unknown machine": (
                _set_u16(pe32_image(b"\xc3"), COFF_OFFSET, 0x01C0),
                "machine_not_i386",
            ),
            "non-PE32 magic": (
                _set_u16(pe32_image(b"\xc3"), OPTIONAL_OFFSET, 0x020B),
                "optional_header_not_pe32",
            ),
            "non-console subsystem": (
                _set_u16(pe32_image(b"\xc3"), OPTIONAL_OFFSET + 68, 2),
                "subsystem_not_console",
            ),
            "short PE32 optional header": (
                _set_u16(pe32_image(b"\xc3"), COFF_OFFSET + 16, 223),
                "optional_header_pe32_bounds",
            ),
        }

        for name, (image, expected_code) in cases.items():
            with self.subTest(name=name):
                result = diagnose_pe32_loader_image(image)
                self.assertEqual(
                    result.status, StageALoaderDiagnosticStatus.INVALID
                )
                self.assertIn(expected_code, _hard_codes(result))
                self.assertFalse(result.authorizes_stage_a)

    def test_image_bounds_alignments_and_exact_sizes_are_checked(self) -> None:
        cases = {
            "32-bit image overflow": (
                _chain(
                    _set_u32_at(OPTIONAL_OFFSET + 28, 0xFFFF0000),
                    _set_u32_at(OPTIONAL_OFFSET + 56, 0x20000),
                )(pe32_image(b"\xc3")),
                "image_address_space_overflow",
            ),
            "bad section alignment": (
                _set_u32(pe32_image(b"\xc3"), OPTIONAL_OFFSET + 32, 0x1800),
                "section_alignment",
            ),
            "bad file alignment": (
                _set_u32(pe32_image(b"\xc3"), OPTIONAL_OFFSET + 36, 0x180),
                "file_alignment",
            ),
            "misaligned section RVA": (
                _set_u32(
                    pe32_image(b"\xc3"),
                    SECTION_TABLE_OFFSET + 12,
                    0x1100,
                ),
                "section_virtual_alignment",
            ),
            "raw bytes outside file": (
                _set_u32(
                    pe32_image(b"\xc3"),
                    SECTION_TABLE_OFFSET + 20,
                    0x400,
                ),
                "section_raw_file_bounds",
            ),
            "inexact SizeOfHeaders": (
                _set_u32(pe32_image(b"\xc3"), OPTIONAL_OFFSET + 60, 0x400),
                "section_raw_overlaps_headers",
            ),
            "inexact SizeOfImage": (
                _set_u32(pe32_image(b"\xc3"), OPTIONAL_OFFSET + 56, 0x3000),
                "size_of_image_exact",
            ),
            "entrypoint outside executable section": (
                _set_u32(pe32_image(b"\xc3"), OPTIONAL_OFFSET + 16, 0x1800),
                "entrypoint_not_executable",
            ),
        }

        for name, (image, expected_code) in cases.items():
            with self.subTest(name=name):
                result = diagnose_pe32_loader_image(image)
                self.assertEqual(
                    result.status, StageALoaderDiagnosticStatus.INVALID
                )
                self.assertIn(expected_code, _hard_codes(result))

    def test_section_order_and_disjointness_use_raw_header_order(self) -> None:
        image = pe32_import_image(b"\xc3", symbol="ExitProcess")
        first = image[SECTION_TABLE_OFFSET : SECTION_TABLE_OFFSET + 40]
        second = image[SECTION_TABLE_OFFSET + 40 : SECTION_TABLE_OFFSET + 80]
        swapped = bytearray(image)
        swapped[SECTION_TABLE_OFFSET : SECTION_TABLE_OFFSET + 40] = second
        swapped[SECTION_TABLE_OFFSET + 40 : SECTION_TABLE_OFFSET + 80] = first

        result = diagnose_pe32_loader_image(bytes(swapped))
        binary = self._parse(bytes(swapped))

        self.assertIn("section_virtual_order", _hard_codes(result))
        self.assertEqual(
            tuple(section.name for section in binary.sections),
            (".idata", ".text"),
        )
        self.assertEqual(binary.loader_diagnostics, result)

        virtual_overlap = _set_u32(
            image,
            SECTION_TABLE_OFFSET + 40 + 12,
            0x1000,
        )
        self.assertIn(
            "section_virtual_overlap",
            _hard_codes(diagnose_pe32_loader_image(virtual_overlap)),
        )

        raw_overlap = _set_u32(
            image,
            SECTION_TABLE_OFFSET + 40 + 20,
            0x200,
        )
        self.assertIn(
            "section_raw_overlap",
            _hard_codes(diagnose_pe32_loader_image(raw_overlap)),
        )

        raw_out_of_order = _chain(
            _set_u32_at(SECTION_TABLE_OFFSET + 20, 0x400),
            _set_u32_at(SECTION_TABLE_OFFSET + 40 + 20, 0x200),
        )(image)
        self.assertIn(
            "section_raw_order",
            _hard_codes(diagnose_pe32_loader_image(raw_out_of_order)),
        )

    def test_directory_count_and_presence_are_coherent(self) -> None:
        directory_offset = OPTIONAL_OFFSET + 96
        cases = {
            "count beyond table": (
                _set_u32(pe32_image(b"\xc3"), OPTIONAL_OFFSET + 92, 17),
                "directory_count_bounds",
            ),
            "undeclared nonzero slot": (
                _chain(
                    _set_u32_at(OPTIONAL_OFFSET + 92, 0),
                    _set_u32_at(directory_offset, 0x1000),
                    _set_u32_at(directory_offset + 4, 1),
                )(pe32_image(b"\xc3")),
                "directory_undeclared_present",
            ),
            "half-present slot": (
                _set_u32(pe32_image(b"\xc3"), directory_offset, 0x1000),
                "directory_presence_incoherent",
            ),
            "directory outside image": (
                _chain(
                    _set_u32_at(directory_offset, 0x1FFF),
                    _set_u32_at(directory_offset + 4, 2),
                )(pe32_image(b"\xc3")),
                "directory_mapped_span",
            ),
            "directory in unmapped image gap": (
                _chain(
                    _set_u32_at(directory_offset + 8, 0x1800),
                    _set_u32_at(directory_offset + 12, 0x20),
                )(pe32_image(b"\xc3")),
                "directory_mapped_span",
            ),
        }

        for name, (image, expected_code) in cases.items():
            with self.subTest(name=name):
                result = diagnose_pe32_loader_image(image)
                self.assertEqual(
                    result.status, StageALoaderDiagnosticStatus.INVALID
                )
                self.assertIn(expected_code, _hard_codes(result))

    def _parse(self, data: bytes):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "loader-diagnostic.exe"
            path.write_bytes(data)
            return _parse_stage_a_pe(path)


def _hard_codes(result) -> tuple[str, ...]:
    return tuple(diagnostic.code for diagnostic in result.hard_diagnostics)


def _set_u16(data: bytes, offset: int, value: int) -> bytes:
    mutated = bytearray(data)
    struct.pack_into("<H", mutated, offset, value)
    return bytes(mutated)


def _set_u32(data: bytes, offset: int, value: int) -> bytes:
    mutated = bytearray(data)
    struct.pack_into("<I", mutated, offset, value)
    return bytes(mutated)


def _set_u32_at(offset: int, value: int):
    return lambda data: _set_u32(data, offset, value)


def _chain(*mutations):
    def mutate(data: bytes) -> bytes:
        for mutation in mutations:
            data = mutation(data)
        return data

    return mutate


if __name__ == "__main__":
    unittest.main()
