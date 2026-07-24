from __future__ import annotations

import json
import math
import re
import struct
import tempfile
import time
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.pe_byte_packs import (
    PE_BYTE_PACK_FORMAT,
    PE_BYTE_PACK_SCHEDULE_FORMAT,
    PEBytePackGenerationError,
    PEBytePackSpan,
    generate_pe_byte_pack_bundle,
    generate_pe_byte_pack_schedule,
    render_pe_byte_pack_schedule_source,
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _pe32_image(
    code: bytes,
    *,
    virtual_size: int | None = None,
    duplicate_section: bool = False,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    raw_size = _align(len(code), file_alignment)
    mapped_size = virtual_size if virtual_size is not None else len(code)
    size_of_image = _align(text_rva + mapped_size, section_alignment)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    section_count = 2 if duplicate_section else 1
    coff = struct.pack("<HHIIIHH", 0x014C, section_count, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        raw_size,
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
        mapped_size,
        text_rva,
        raw_size,
        headers_size,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    sections = section + (section if duplicate_section else b"")
    headers = (bytes(dos) + b"PE\0\0" + coff + optional + sections).ljust(
        headers_size, b"\0"
    )
    return headers + code.ljust(raw_size, b"\0")


class StageARelationalPEBytePackGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_pe(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_large_pe_has_cacheable_packs_and_minimal_schedule_imports(self) -> None:
        code = bytes((index * 17 + 3) % 256 for index in range(132 * 1024 + 37))
        pe_path = self._write_pe("large.exe", _pe32_image(code))
        first = self.root / "first"
        second = self.root / "second"

        started = time.monotonic()
        inventory = generate_pe_byte_pack_bundle(
            pe_path=pe_path,
            out_dir=first,
            module_prefix="SyntheticLarge",
            pack_size=64 * 1024,
            chunk_size=1024,
        )
        generation_seconds = time.monotonic() - started
        repeated = generate_pe_byte_pack_bundle(
            pe_path=pe_path,
            out_dir=second,
            module_prefix="SyntheticLarge",
            pack_size=64 * 1024,
            chunk_size=1024,
        )

        self.assertGreater(len(pe_path.read_bytes()), 100 * 1024)
        self.assertLess(generation_seconds, 15.0)
        self.assertEqual(inventory.payload(), repeated.payload())
        self.assertEqual(
            json.loads((first / "pe-byte-packs.json").read_text()),
            json.loads((second / "pe-byte-packs.json").read_text()),
        )
        self.assertEqual(inventory.payload()["format"], PE_BYTE_PACK_FORMAT)
        self.assertEqual(
            len(inventory.packs), math.ceil(inventory.source_size / (64 * 1024))
        )
        self.assertEqual(len(inventory.modules), len(inventory.packs) * 2 + 1)

        authoritative = (
            first / f"StageA/{inventory.authoritative_module}.lean"
        ).read_text()
        self.assertEqual(authoritative.count("MetadataParsed"), 2)
        self.assertEqual(authoritative.count("parsePEMetadataTree"), 1)
        for pack in inventory.packs:
            self.assertIn(f"import StageA.{pack.payload_module}", authoritative)
            payload = (first / f"StageA/{pack.payload_module}.lean").read_text()
            derivation = (
                first / f"StageA/{pack.certificate_module}.lean"
            ).read_text()
            self.assertIn("import StageA.Formal", payload)
            self.assertNotIn("RelationalPEBytePacks", payload)
            self.assertIn("ByteTreePackAt", derivation)
            self.assertIn("WholeExact", derivation)
            self.assertNotIn("parsePE32Tree", derivation)
            self.assertNotIn("native_decide", payload + derivation)
            self.assertLess(len(payload.encode()), 400_000)

        pack_boundary = 64 * 1024
        crossing_rva = 0x1000 + (pack_boundary - 0x200) - 8
        schedule = generate_pe_byte_pack_schedule(
            inventory,
            out_dir=first,
            module_name="SyntheticCrossingSchedule",
            spans=[PEBytePackSpan("crossing", crossing_rva, 16)],
        )
        schedule_source = (
            first / "StageA/SyntheticCrossingSchedule.lean"
        ).read_text()
        self.assertEqual(schedule.payload()["format"], PE_BYTE_PACK_SCHEDULE_FORMAT)
        self.assertEqual(
            schedule.imports,
            (
                inventory.packs[0].certificate_module,
                inventory.packs[1].certificate_module,
            ),
        )
        self.assertNotIn(inventory.packs[2].certificate_module, schedule_source)
        self.assertIn("PEBytePackSliceChain", schedule_source)
        self.assertIn("crossingExactRvaBytes", schedule_source)
        self.assertNotIn("parsePE32Tree", schedule_source)
        self.assertNotIn("native_decide", schedule_source)
        self.assertLess(schedule.source_bytes, 8_000)

    def test_generation_is_fail_closed_for_invalid_spans_and_changed_pe(self) -> None:
        pe_path = self._write_pe("normal.exe", _pe32_image(bytes(range(64))))
        inventory = generate_pe_byte_pack_bundle(
            pe_path=pe_path,
            out_dir=self.root / "normal",
            module_prefix="Normal",
            pack_size=512,
            chunk_size=128,
        )

        for span, message in (
            (PEBytePackSpan("header", 16, 4), "headers"),
            (PEBytePackSpan("empty", 0x1000, 0), "positive size"),
            (PEBytePackSpan("outside", inventory.size_of_image, 1), "SizeOfImage"),
        ):
            with self.subTest(span=span.name):
                with self.assertRaisesRegex(PEBytePackGenerationError, message):
                    render_pe_byte_pack_schedule_source(
                        inventory, module_name="Rejected", spans=[span]
                    )

        changed = bytearray(pe_path.read_bytes())
        changed[-1] ^= 0xFF
        pe_path.write_bytes(changed)
        with self.assertRaisesRegex(PEBytePackGenerationError, "changed"):
            render_pe_byte_pack_schedule_source(
                inventory,
                module_name="Changed",
                spans=[PEBytePackSpan("code", 0x1000, 1)],
            )

    def test_zero_fill_and_ambiguous_section_mappings_are_rejected(self) -> None:
        zero_fill = self._write_pe(
            "zero-fill.exe", _pe32_image(b"\x90" * 16, virtual_size=1024)
        )
        zero_inventory = generate_pe_byte_pack_bundle(
            pe_path=zero_fill,
            out_dir=self.root / "zero-fill",
            module_prefix="ZeroFill",
            pack_size=512,
            chunk_size=128,
        )
        with self.assertRaisesRegex(PEBytePackGenerationError, "zero-fill"):
            render_pe_byte_pack_schedule_source(
                zero_inventory,
                module_name="ZeroFillRejected",
                spans=[PEBytePackSpan("tail", 0x1000 + 600, 4)],
            )

        ambiguous = self._write_pe(
            "ambiguous.exe",
            _pe32_image(b"\x90" * 64, duplicate_section=True),
        )
        ambiguous_inventory = generate_pe_byte_pack_bundle(
            pe_path=ambiguous,
            out_dir=self.root / "ambiguous",
            module_prefix="Ambiguous",
            pack_size=512,
            chunk_size=128,
        )
        with self.assertRaisesRegex(PEBytePackGenerationError, "2 containing"):
            render_pe_byte_pack_schedule_source(
                ambiguous_inventory,
                module_name="AmbiguousRejected",
                spans=[PEBytePackSpan("code", 0x1000, 4)],
            )

    def test_sources_have_no_unchecked_escape_hatches(self) -> None:
        paths = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalPEBytePacks.lean",
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/relational/lean/pe_byte_packs.py",
        )
        for path in paths:
            source = path.read_text(encoding="utf-8")
            for marker in ("native_decide", "sorry", "axiom", "unsafe"):
                self.assertIsNone(re.search(rf"\b{marker}\b", source), (path, marker))


if __name__ == "__main__":
    unittest.main()
