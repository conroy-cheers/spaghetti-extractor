from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path

import pefile

from tests.pe_fixtures import (
    pe32_image,
    pe32_image_with_writable_data,
    pe32_import_image,
    pe32_tls_image,
)

from spaghetti_extractor.roundtrip_fuzz.image_contract import (
    build_stage_a_load_image_contract,
    write_stage_a_load_image_contract,
)
from spaghetti_extractor.stage_b_pe_composer import (
    COMPOSITION_MANIFEST_FILENAME,
    EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
    PAYLOAD_RELOCATION_INVENTORY_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
    StageBPECompositionError,
    compose_stage_b_pe,
    plan_stage_b_pe_composition,
)
from spaghetti_extractor.util import sha256_bytes


PE_OFFSET = 0x80
FILE_HEADER_OFFSET = PE_OFFSET + 4
OPTIONAL_OFFSET = FILE_HEADER_OFFSET + 20
SECTION_TABLE_OFFSET = OPTIONAL_OFFSET + 224
DIRECTORY_OFFSET = OPTIONAL_OFFSET + 96


def _high_rva_payload(*, rva: int = 0x4000, code: bytes | None = None) -> bytes:
    payload = bytearray(pe32_image(code or b"\xb8\x2a\x00\x00\x00\xc3"))
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 16, rva)
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 20, rva)
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 56, rva + 0x1000)
    struct.pack_into("<I", payload, SECTION_TABLE_OFFSET + 12, rva)
    return bytes(payload)


def _empty_relocation_inventory(payload: bytes) -> dict:
    return {
        "format": PAYLOAD_RELOCATION_INVENTORY_FORMAT,
        "complete": True,
        "payload_sha256": sha256_bytes(payload),
        "image_base": 0x400000,
        "relocations": [],
    }


def _high_rva_payload_with_highlow(
    *, text_rva: int = 0x5000, relocation_type: int = 3
) -> bytes:
    preferred = 0x400000 + text_rva
    payload = bytearray(
        _high_rva_payload(
            rva=text_rva,
            code=b"\xb8" + struct.pack("<I", preferred) + b"\xc3",
        )
    )
    reloc_rva = text_rva + 0x1000
    relocation_data = struct.pack(
        "<IIHH",
        text_rva,
        12,
        (relocation_type << 12) | 1,
        0,
    )
    struct.pack_into("<H", payload, FILE_HEADER_OFFSET + 2, 2)
    characteristics = struct.unpack_from("<H", payload, FILE_HEADER_OFFSET + 18)[0]
    struct.pack_into("<H", payload, FILE_HEADER_OFFSET + 18, characteristics & ~1)
    struct.pack_into("<H", payload, OPTIONAL_OFFSET + 70, 0x40)
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 56, reloc_rva + 0x1000)
    struct.pack_into(
        "<II",
        payload,
        DIRECTORY_OFFSET + 5 * 8,
        reloc_rva,
        len(relocation_data),
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        payload,
        SECTION_TABLE_OFFSET + 40,
        b".reloc\0\0",
        len(relocation_data),
        reloc_rva,
        0x200,
        0x400,
        0,
        0,
        0,
        0,
        0x42000040,
    )
    payload.extend(relocation_data.ljust(0x200, b"\0"))
    return bytes(payload)


def _high_rva_payload_with_cross_page_highlow(*, text_rva: int = 0x5000) -> bytes:
    preferred = 0x400000 + text_rva
    payload = bytearray(_high_rva_payload(rva=text_rva))
    text_raw_pointer = 0x200
    text_raw_size = 0x1200
    relocation_offset = 0xFFF
    reloc_rva = text_rva + 0x2000
    reloc_raw_pointer = text_raw_pointer + text_raw_size
    relocation_data = struct.pack(
        "<IIHH",
        text_rva,
        12,
        (3 << 12) | relocation_offset,
        0,
    )
    payload.extend(bytes(reloc_raw_pointer + 0x200 - len(payload)))
    struct.pack_into("<I", payload, text_raw_pointer + relocation_offset, preferred)
    struct.pack_into("<I", payload, SECTION_TABLE_OFFSET + 8, text_raw_size)
    struct.pack_into("<I", payload, SECTION_TABLE_OFFSET + 16, text_raw_size)
    struct.pack_into("<H", payload, FILE_HEADER_OFFSET + 2, 2)
    characteristics = struct.unpack_from("<H", payload, FILE_HEADER_OFFSET + 18)[0]
    struct.pack_into("<H", payload, FILE_HEADER_OFFSET + 18, characteristics & ~1)
    struct.pack_into("<H", payload, OPTIONAL_OFFSET + 70, 0x40)
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 56, reloc_rva + 0x1000)
    struct.pack_into(
        "<II",
        payload,
        DIRECTORY_OFFSET + 5 * 8,
        reloc_rva,
        len(relocation_data),
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        payload,
        SECTION_TABLE_OFFSET + 40,
        b".reloc\0\0",
        len(relocation_data),
        reloc_rva,
        0x200,
        reloc_raw_pointer,
        0,
        0,
        0,
        0,
        0x42000040,
    )
    payload[reloc_raw_pointer : reloc_raw_pointer + len(relocation_data)] = (
        relocation_data
    )
    return bytes(payload)


def _high_rva_payload_with_cross_page_highlow(
    *, text_rva: int = 0x5000
) -> bytes:
    preferred = 0x400000 + text_rva
    code = bytearray(0x1003)
    code[0] = 0xC3
    struct.pack_into("<I", code, 0xFFF, preferred)
    payload = bytearray(_high_rva_payload(rva=text_rva, code=bytes(code)))
    reloc_rva = text_rva + 0x2000
    relocation_data = struct.pack("<IIHH", text_rva, 12, 0x3FFF, 0)
    text_raw_size = struct.unpack_from(
        "<I", payload, SECTION_TABLE_OFFSET + 16
    )[0]
    reloc_raw = 0x200 + text_raw_size

    struct.pack_into("<H", payload, FILE_HEADER_OFFSET + 2, 2)
    characteristics = struct.unpack_from("<H", payload, FILE_HEADER_OFFSET + 18)[0]
    struct.pack_into("<H", payload, FILE_HEADER_OFFSET + 18, characteristics & ~1)
    struct.pack_into("<H", payload, OPTIONAL_OFFSET + 70, 0x40)
    struct.pack_into("<I", payload, OPTIONAL_OFFSET + 56, reloc_rva + 0x1000)
    struct.pack_into(
        "<II",
        payload,
        DIRECTORY_OFFSET + 5 * 8,
        reloc_rva,
        len(relocation_data),
    )
    struct.pack_into(
        "<8sIIIIIIHHI",
        payload,
        SECTION_TABLE_OFFSET + 40,
        b".reloc\0\0",
        len(relocation_data),
        reloc_rva,
        0x200,
        reloc_raw,
        0,
        0,
        0,
        0,
        0x42000040,
    )
    payload.extend(relocation_data.ljust(0x200, b"\0"))
    return bytes(payload)


def _with_larger_headers(image: bytes) -> bytes:
    result = bytearray(image[:0x200] + bytes(0x200) + image[0x200:])
    section_count = struct.unpack_from("<H", result, FILE_HEADER_OFFSET + 2)[0]
    struct.pack_into("<I", result, OPTIONAL_OFFSET + 60, 0x400)
    for index in range(section_count):
        pointer_offset = SECTION_TABLE_OFFSET + index * 40 + 20
        pointer = struct.unpack_from("<I", result, pointer_offset)[0]
        if pointer:
            struct.pack_into("<I", result, pointer_offset, pointer + 0x200)
    return bytes(result)


def _anchor_manifest(
    *,
    entry_rva: int = 0x1000,
    tls_callback_rvas: tuple[int, ...] = (),
    callback_rvas: tuple[int, ...] = (),
    anchors: tuple[tuple[int, bytes], ...] | None = None,
) -> dict:
    if anchors is None:
        anchors = ((entry_rva, bytes.fromhex("e9fb2f0000")),)
    return {
        "format": EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
        "image_base": 0x400000,
        "entry_anchor_rva": entry_rva,
        "tls_callback_anchor_rvas": list(tls_callback_rvas),
        "callback_anchor_rvas": list(callback_rvas),
        "anchors": [
            {"rva": rva, "bytes_hex": stub.hex()} for rva, stub in anchors
        ],
    }


def _three_section_original() -> bytes:
    image = bytearray(pe32_import_image(b"\xc3", symbol="ExitProcess"))
    struct.pack_into("<H", image, FILE_HEADER_OFFSET + 2, 3)
    struct.pack_into("<I", image, OPTIONAL_OFFSET + 56, 0x4000)
    struct.pack_into(
        "<8sIIIIIIHHI",
        image,
        SECTION_TABLE_OFFSET + 2 * 40,
        b".bss\0\0\0\0",
        0x100,
        0x3000,
        0,
        0,
        0,
        0,
        0,
        0,
        0xC0000080,
    )
    return bytes(image)


def _directories(pe: pefile.PE) -> list[tuple[int, int]]:
    return [
        (int(item.VirtualAddress), int(item.Size))
        for item in pe.OPTIONAL_HEADER.DATA_DIRECTORY[:16]
    ]


class StageBPEComposerTests(unittest.TestCase):
    def test_accepts_highlow_fixup_crossing_a_four_kib_page(self) -> None:
        original = _with_larger_headers(
            pe32_import_image(b"\xc3", symbol="ExitProcess")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_path = root / "original.exe"
            original_path.write_bytes(original)
            plan = plan_stage_b_pe_composition(
                load_image_contract=build_stage_a_load_image_contract(original_path),
                payload_pe=_high_rva_payload_with_cross_page_highlow(),
                anchor_manifest=_anchor_manifest(
                    anchors=((0x1000, bytes.fromhex("e9fb3f0000")),)
                ),
            )

        self.assertEqual(
            [item.rva for item in plan.relocation_inventory.relocations],
            [0x5FFF],
        )

    def test_composes_without_original_and_preserves_import_runtime_layout(self) -> None:
        original_bytes = pe32_import_image(
            b"\x90\x90\x90\x90\x90\xc3", symbol="ExitProcess"
        )
        payload_bytes = _high_rva_payload()
        anchors = _anchor_manifest()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "must-not-be-consumed.exe"
            contract_path = root / "load-image-contract.json"
            payload_path = root / "payload.exe"
            anchor_path = root / "anchors.json"
            original.write_bytes(original_bytes)
            contract = write_stage_a_load_image_contract(
                original_pe=original, out=contract_path
            )
            payload_path.write_bytes(payload_bytes)
            anchor_path.write_text(
                json.dumps(anchors, sort_keys=True), encoding="ascii"
            )
            original.unlink()

            first = compose_stage_b_pe(
                load_image_contract=contract_path,
                payload_pe=payload_path,
                anchor_manifest=anchor_path,
                payload_relocation_inventory=_empty_relocation_inventory(
                    payload_bytes
                ),
                out_dir=root / "first",
            )
            second = compose_stage_b_pe(
                load_image_contract=contract_path,
                payload_pe=payload_path,
                anchor_manifest=anchor_path,
                payload_relocation_inventory=_empty_relocation_inventory(
                    payload_bytes
                ),
                out_dir=root / "second",
            )
            candidate_path = root / "first" / "candidate.exe"
            candidate_bytes = candidate_path.read_bytes()
            candidate = pefile.PE(data=candidate_bytes)
            original_headers = pefile.PE(
                data=contract.runtime_headers.data, fast_load=True
            )

            self.assertEqual(
                candidate_bytes, (root / "second" / "candidate.exe").read_bytes()
            )
            self.assertEqual(
                (root / "first" / COMPOSITION_MANIFEST_FILENAME).read_bytes(),
                (root / "second" / COMPOSITION_MANIFEST_FILENAME).read_bytes(),
            )
            self.assertEqual(first, second)
            self.assertEqual(first["format"], PE_COMPOSITION_MANIFEST_FORMAT)
            self.assertEqual(first["acceptance_authority"], "none")
            self.assertNotIn(str(original), json.dumps(first))
            self.assertEqual(first["candidate"]["sha256"], sha256_bytes(candidate_bytes))

            self.assertEqual(int(candidate.FILE_HEADER.Machine), 0x14C)
            self.assertEqual(int(candidate.OPTIONAL_HEADER.Magic), 0x10B)
            self.assertEqual(int(candidate.FILE_HEADER.NumberOfSections), 3)
            self.assertEqual(int(candidate.OPTIONAL_HEADER.ImageBase), 0x400000)
            self.assertEqual(int(candidate.OPTIONAL_HEADER.AddressOfEntryPoint), 0x1000)
            self.assertEqual(int(candidate.OPTIONAL_HEADER.SizeOfImage), 0x5000)
            self.assertTrue(candidate.verify_checksum())
            self.assertFalse(int(candidate.FILE_HEADER.Characteristics) & 0x0001)
            self.assertTrue(int(candidate.OPTIONAL_HEADER.DllCharacteristics) & 0x0040)
            self.assertEqual(_directories(candidate), _directories(original_headers))
            self.assertEqual(candidate.DIRECTORY_ENTRY_IMPORT[0].dll, b"KERNEL32.dll")
            self.assertEqual(
                int(candidate.DIRECTORY_ENTRY_IMPORT[0].imports[0].address),
                0x402040,
            )

            payload_section = candidate.sections[2]
            self.assertEqual(int(payload_section.VirtualAddress), 0x4000)
            self.assertEqual(int(payload_section.PointerToRawData), 0x600)
            self.assertEqual(
                candidate_bytes[0x600:0x800], payload_bytes[0x200:0x400]
            )
            self.assertEqual(
                candidate_bytes[0x400:0x600], original_bytes[0x400:0x600]
            )
            self.assertEqual(candidate_bytes[0x200:0x205], bytes.fromhex("e9fb2f0000"))
            self.assertEqual(candidate_bytes[0x205], 0xCC)
            self.assertEqual(candidate_bytes[0x206:0x400], bytes(0x1FA))

            classifications = first["executable_byte_classification"]
            self.assertEqual(sum(row["size"] for row in classifications), 0x200)
            self.assertEqual(
                [row["kind"] for row in classifications],
                ["anchor", "trap", "padding"],
            )
            candidate.close()
            original_headers.close()

    def test_entry_tls_and_other_callback_roots_are_explicit_and_ordered(self) -> None:
        original_bytes = pe32_tls_image((0x1020, 0x1010))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "tls.exe"
            original.write_bytes(original_bytes)
            contract = build_stage_a_load_image_contract(original)
            anchors = _anchor_manifest(
                tls_callback_rvas=(0x1020, 0x1010),
                callback_rvas=(0x1030,),
                anchors=(
                    (0x1000, bytes.fromhex("e9fb2f0000")),
                    (0x1010, b"\xc3"),
                    (0x1020, b"\xc3"),
                    (0x1030, b"\xc3"),
                ),
            )

            result = compose_stage_b_pe(
                load_image_contract=contract,
                payload_pe=(payload := _high_rva_payload()),
                anchor_manifest=anchors,
                payload_relocation_inventory=_empty_relocation_inventory(payload),
                out_dir=root / "out",
            )
            candidate = pefile.PE(str(root / "out" / "candidate.exe"))
            candidate.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]]
            )

            self.assertEqual(result["anchors"]["tls_callback_rvas"], [0x1020, 0x1010])
            self.assertEqual(result["anchors"]["callback_rvas"], [0x1030])
            callback_array_offset = candidate.get_offset_from_rva(0x2040)
            self.assertEqual(
                struct.unpack_from("<III", candidate.__data__, callback_array_offset),
                (0x401020, 0x401010, 0),
            )

            wrong_order = copy.deepcopy(anchors)
            wrong_order["tls_callback_anchor_rvas"] = [0x1010, 0x1020]
            with self.assertRaisesRegex(
                StageBPECompositionError, "TLS callback order"
            ):
                plan_stage_b_pe_composition(
                    load_image_contract=contract,
                    payload_pe=(payload := _high_rva_payload()),
                    anchor_manifest=wrong_order,
                    payload_relocation_inventory=_empty_relocation_inventory(payload),
                )
            candidate.close()

    def test_payload_and_anchor_mutations_fail_closed(self) -> None:
        original_bytes = pe32_import_image(b"\xc3", symbol="ExitProcess")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(original_bytes)
            contract = build_stage_a_load_image_contract(original)

            payload_mutations: list[tuple[str, bytes, str]] = []
            for directory_index, label in ((1, "imports"), (9, "TLS"), (13, "delay imports")):
                mutated = bytearray(_high_rva_payload())
                struct.pack_into(
                    "<II",
                    mutated,
                    DIRECTORY_OFFSET + directory_index * 8,
                    0x4000,
                    4,
                )
                payload_mutations.append((label, bytes(mutated), f"forbidden {label}"))

            relocations = bytearray(_high_rva_payload())
            struct.pack_into(
                "<II", relocations, DIRECTORY_OFFSET + 5 * 8, 0x4000, 4
            )
            payload_mutations.append(
                (
                    "relocations",
                    bytes(relocations),
                    "relocation directory disagrees with RELOCS_STRIPPED",
                )
            )
            wrong_base = bytearray(_high_rva_payload())
            struct.pack_into("<I", wrong_base, OPTIONAL_OFFSET + 28, 0x500000)
            payload_mutations.append(("image-base", bytes(wrong_base), "image base"))
            payload_mutations.append(
                ("low-rva-overlap", _high_rva_payload(rva=0x2000), "not at a high RVA")
            )

            for name, payload, error in payload_mutations:
                with self.subTest(name=name), self.assertRaisesRegex(
                    StageBPECompositionError, error
                ):
                    plan_stage_b_pe_composition(
                        load_image_contract=contract,
                        payload_pe=payload,
                        anchor_manifest=_anchor_manifest(),
                        payload_relocation_inventory=_empty_relocation_inventory(
                            payload
                        ),
                    )

            anchor_mutations = (
                (
                    "duplicate",
                    _anchor_manifest(
                        anchors=((0x1000, b"\xc3"), (0x1000, b"\xcc"))
                    ),
                    "not unique",
                ),
                (
                    "overlap",
                    _anchor_manifest(
                        anchors=((0x1000, b"\x90\x90"), (0x1001, b"\xc3"))
                    ),
                    "overlap",
                ),
                (
                    "out-of-bounds",
                    _anchor_manifest(
                        entry_rva=0x11FF, anchors=((0x11FF, b"\x90\xc3"),)
                    ),
                    "not bounded",
                ),
                (
                    "missing-entry",
                    _anchor_manifest(anchors=((0x1010, b"\xc3"),)),
                    "entry RVA.*exact supplied anchor",
                ),
            )
            for name, anchors, error in anchor_mutations:
                with self.subTest(name=name), self.assertRaisesRegex(
                    StageBPECompositionError, error
                ):
                    plan_stage_b_pe_composition(
                        load_image_contract=contract,
                        payload_pe=(payload := _high_rva_payload()),
                        anchor_manifest=anchors,
                        payload_relocation_inventory=_empty_relocation_inventory(
                            payload
                        ),
                    )

    def test_merges_original_and_payload_highlow_relocations_canonically(self) -> None:
        original_bytes = _with_larger_headers(
            pe32_image_with_writable_data(
                b"\x90" * 8 + struct.pack("<I", 0x402000) + b"\xc3",
                relocation_offsets=[8],
            )
        )
        payload_bytes = _high_rva_payload_with_highlow()
        anchors = _anchor_manifest(
            anchors=((0x1000, bytes.fromhex("e9fb3f0000")),)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(original_bytes)
            contract = build_stage_a_load_image_contract(original)
            manifest = compose_stage_b_pe(
                load_image_contract=contract,
                payload_pe=payload_bytes,
                anchor_manifest=anchors,
                out_dir=root / "out",
            )
            candidate = pefile.PE(str(root / "out" / "candidate.exe"))
            candidate.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY[
                        "IMAGE_DIRECTORY_ENTRY_BASERELOC"
                    ]
                ]
            )

            relocations = [
                (int(entry.rva), int(entry.type))
                for block in candidate.DIRECTORY_ENTRY_BASERELOC
                for entry in block.entries
                if int(entry.type) != 0
            ]
            self.assertEqual(relocations, [(0x1008, 3), (0x5001, 3)])
            self.assertEqual(
                (
                    int(
                        candidate.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress
                    ),
                    int(candidate.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size),
                ),
                (0x7000, 24),
            )
            self.assertEqual(candidate.sections[-1].Name.rstrip(b"\0"), b".sreloc")
            self.assertFalse(int(candidate.FILE_HEADER.Characteristics) & 1)
            self.assertTrue(
                int(candidate.OPTIONAL_HEADER.DllCharacteristics) & 0x40
            )
            self.assertTrue(candidate.verify_checksum())
            self.assertEqual(
                [(row["source"], row["target_rva"]) for row in manifest["merged_relocations"]],
                [("original", 0x1008), ("payload", 0x5001)],
            )
            payload_target_offset = candidate.get_offset_from_rva(0x5001)
            self.assertEqual(
                struct.unpack_from("<I", candidate.__data__, payload_target_offset)[0],
                0x405000,
            )
            candidate.relocate_image(0x500000)
            self.assertEqual(
                struct.unpack_from("<I", candidate.__data__, payload_target_offset)[0],
                0x505000,
            )
            candidate.close()

    def test_highlow_relocation_may_cross_its_block_page(self) -> None:
        original_bytes = _with_larger_headers(
            pe32_image_with_writable_data(b"\xc3", relocation_offsets=[])
        )
        payload_bytes = _high_rva_payload_with_cross_page_highlow()
        anchors = _anchor_manifest(
            anchors=((0x1000, bytes.fromhex("e9fb3f0000")),)
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(original_bytes)
            contract = build_stage_a_load_image_contract(original)
            manifest = compose_stage_b_pe(
                load_image_contract=contract,
                payload_pe=payload_bytes,
                anchor_manifest=anchors,
                out_dir=root / "out",
            )
            candidate = pefile.PE(str(root / "out" / "candidate.exe"))
            candidate.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY[
                        "IMAGE_DIRECTORY_ENTRY_BASERELOC"
                    ]
                ]
            )
            cross_page = [
                (int(block.struct.VirtualAddress), int(entry.rva), int(entry.type))
                for block in candidate.DIRECTORY_ENTRY_BASERELOC
                for entry in block.entries
                if int(entry.type) != 0 and int(entry.rva) & 0xFFF == 0xFFF
            ]
            self.assertEqual(cross_page, [(0x5000, 0x5FFF, 3)])
            self.assertIn(
                ("payload", 0x5FFF),
                [
                    (row["source"], row["target_rva"])
                    for row in manifest["merged_relocations"]
                ],
            )
            target_offset = candidate.get_offset_from_rva(0x5FFF)
            self.assertEqual(
                struct.unpack_from("<I", candidate.__data__, target_offset)[0],
                0x405000,
            )
            candidate.relocate_image(0x500000)
            self.assertEqual(
                struct.unpack_from("<I", candidate.__data__, target_offset)[0],
                0x505000,
            )
            candidate.close()

    def test_complete_inventory_supplies_stripped_payload_relocations(self) -> None:
        payload = _high_rva_payload(
            code=b"\xb8" + struct.pack("<I", 0x404000) + b"\xc3"
        )
        inventory = {
            "format": PAYLOAD_RELOCATION_INVENTORY_FORMAT,
            "complete": True,
            "payload_sha256": sha256_bytes(payload),
            "image_base": 0x400000,
            "relocations": [
                {
                    "rva": 0x4001,
                    "type": 3,
                    "kind": "highlow",
                    "width": 4,
                    "preferred_value": 0x404000,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(
                _with_larger_headers(
                    pe32_import_image(b"\xc3", symbol="ExitProcess")
                )
            )
            contract = build_stage_a_load_image_contract(original)
            with self.assertRaisesRegex(
                StageBPECompositionError,
                "requires a complete payload relocation inventory",
            ):
                plan_stage_b_pe_composition(
                    load_image_contract=contract,
                    payload_pe=payload,
                    anchor_manifest=_anchor_manifest(),
                )
            result = compose_stage_b_pe(
                load_image_contract=contract,
                payload_pe=payload,
                payload_relocation_inventory=inventory,
                anchor_manifest=_anchor_manifest(),
                out_dir=root / "out",
            )
            self.assertEqual(
                [(row["source"], row["target_rva"]) for row in result["merged_relocations"]],
                [("payload", 0x4001)],
            )

    def test_malformed_payload_relocations_and_inventories_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(
                _with_larger_headers(
                    pe32_import_image(b"\xc3", symbol="ExitProcess")
                )
            )
            contract = build_stage_a_load_image_contract(original)

            unsupported = _high_rva_payload_with_highlow(
                text_rva=0x4000, relocation_type=5
            )
            invalid_size = bytearray(
                _high_rva_payload_with_highlow(text_rva=0x4000)
            )
            struct.pack_into("<I", invalid_size, 0x400 + 4, 10)
            duplicate = bytearray(
                _high_rva_payload_with_highlow(text_rva=0x4000)
            )
            struct.pack_into("<HH", duplicate, 0x400 + 8, 0x3001, 0x3001)
            malformed = (
                ("unsupported", unsupported, "unsupported PE32 relocation type 5"),
                ("invalid-size", bytes(invalid_size), "invalid size"),
                ("duplicate", bytes(duplicate), "target is duplicated"),
            )
            for name, payload, error in malformed:
                with self.subTest(name=name), self.assertRaisesRegex(
                    StageBPECompositionError, error
                ):
                    plan_stage_b_pe_composition(
                        load_image_contract=contract,
                        payload_pe=payload,
                        anchor_manifest=_anchor_manifest(),
                    )

            payload = _high_rva_payload(
                code=b"\xb8" + struct.pack("<I", 0x404000) + b"\xc3"
            )
            common = {
                "format": PAYLOAD_RELOCATION_INVENTORY_FORMAT,
                "complete": True,
                "payload_sha256": sha256_bytes(payload),
                "image_base": 0x400000,
            }
            target_bytes = payload[0x200:0x400]
            overlapping_inventory = {
                **common,
                "relocations": [
                    {
                        "rva": rva,
                        "type": 3,
                        "kind": "highlow",
                        "width": 4,
                        "preferred_value": int.from_bytes(
                            target_bytes[rva - 0x4000 : rva - 0x4000 + 4],
                            "little",
                        ),
                    }
                    for rva in (0x4001, 0x4003)
                ],
            }
            wrong_hash_inventory = {
                **common,
                "payload_sha256": "0" * 64,
                "relocations": [],
            }
            for name, inventory, error in (
                ("overlap", overlapping_inventory, "ranges .* overlap"),
                ("wrong-hash", wrong_hash_inventory, "hash does not bind"),
            ):
                with self.subTest(name=name), self.assertRaisesRegex(
                    StageBPECompositionError, error
                ):
                    plan_stage_b_pe_composition(
                        load_image_contract=contract,
                        payload_pe=payload,
                        payload_relocation_inventory=inventory,
                        anchor_manifest=_anchor_manifest(),
                    )

    def test_contract_corruption_and_crowded_header_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(pe32_import_image(b"\xc3", symbol="ExitProcess"))
            contract = build_stage_a_load_image_contract(original)
            corrupted = copy.deepcopy(contract.to_payload())
            headers = bytearray.fromhex(corrupted["runtime_headers"]["data_hex"])
            struct.pack_into("<I", headers, SECTION_TABLE_OFFSET + 20, 0)
            corrupted["runtime_headers"]["data_hex"] = headers.hex()

            with self.assertRaisesRegex(ValueError, "header byte hash changed"):
                plan_stage_b_pe_composition(
                    load_image_contract=corrupted,
                    payload_pe=(payload := _high_rva_payload()),
                    anchor_manifest=_anchor_manifest(),
                    payload_relocation_inventory=_empty_relocation_inventory(payload),
                )

            crowded_original = root / "crowded.exe"
            crowded_original.write_bytes(_three_section_original())
            crowded_contract = build_stage_a_load_image_contract(crowded_original)
            payload = _high_rva_payload(rva=0x5000)
            anchors = _anchor_manifest(
                anchors=((0x1000, bytes.fromhex("e9fb3f0000")),)
            )
            first = compose_stage_b_pe(
                load_image_contract=crowded_contract,
                payload_pe=payload,
                anchor_manifest=anchors,
                payload_relocation_inventory=_empty_relocation_inventory(payload),
                out_dir=root / "crowded-first",
            )
            second = compose_stage_b_pe(
                load_image_contract=crowded_contract,
                payload_pe=payload,
                anchor_manifest=anchors,
                payload_relocation_inventory=_empty_relocation_inventory(payload),
                out_dir=root / "crowded-second",
            )
            self.assertEqual(first, second)
            self.assertEqual(
                (root / "crowded-first" / "candidate.exe").read_bytes(),
                (root / "crowded-second" / "candidate.exe").read_bytes(),
            )
            self.assertEqual(
                first["header_layout"],
                {
                    "section_table_offset": SECTION_TABLE_OFFSET,
                    "original_size_of_headers": 0x200,
                    "new_size_of_headers": 0x400,
                    "original_raw_pointer_shift": 0x200,
                    "coff_symbol_table_stripped": False,
                    "file_offset_rewrites": [],
                },
            )

            source = pefile.PE(str(crowded_original))
            candidate = pefile.PE(
                str(root / "crowded-first" / "candidate.exe")
            )
            self.assertEqual(int(candidate.OPTIONAL_HEADER.SizeOfHeaders), 0x400)
            self.assertEqual(len(candidate.sections), 4)
            for original_section, candidate_section in zip(
                source.sections, candidate.sections[:3]
            ):
                self.assertEqual(
                    int(candidate_section.VirtualAddress),
                    int(original_section.VirtualAddress),
                )
                self.assertEqual(
                    int(candidate_section.PointerToRawData),
                    (
                        int(original_section.PointerToRawData) + 0x200
                        if int(original_section.SizeOfRawData)
                        else 0
                    ),
                )
            self.assertEqual(
                _directories(candidate),
                _directories(source),
            )
            candidate.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
                ]
            )
            self.assertEqual(
                candidate.DIRECTORY_ENTRY_IMPORT[0].imports[0].name,
                b"ExitProcess",
            )
            source.close()
            candidate.close()


if __name__ == "__main__":
    unittest.main()
