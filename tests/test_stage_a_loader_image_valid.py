from __future__ import annotations

import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.executor import _run_lean_relational


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _generic_pe32_image() -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_size = 1
    text_raw_size = _align(text_size, file_alignment)
    size_of_image = _align(text_rva + text_size, section_alignment)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)
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
    optional = optional_prefix + bytes(16 * 8)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        text_size,
        text_rva,
        text_raw_size,
        headers_size,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional + section
    ).ljust(headers_size, b"\0")
    return headers + bytes(text_raw_size)


def _expanded_headers_pe32_image() -> bytes:
    image = bytearray(_generic_pe32_image())
    image[0x200:0x200] = bytes(0x200)
    optional_offset = 0x80 + 24
    section_table_offset = optional_offset + 224
    struct.pack_into("<I", image, optional_offset + 60, 0x400)
    struct.pack_into("<I", image, section_table_offset + 20, 0x400)
    return bytes(image)


def _jq_layout_pe32_image() -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x400
    file_size = 0xF400
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 8, 0, 0, 0, 224, 0x0306)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        2,
        46,
        0xB600,
        0x3A00,
        0xC00,
        0x1420,
        0x1000,
        0xD000,
        0x400000,
        section_alignment,
        file_alignment,
        4,
        0,
        1,
        0,
        4,
        0,
        0,
        0x15000,
        headers_size,
        0,
        3,
        0x140,
        0x200000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 0 * 8, 0x11000, 0x2F)
    struct.pack_into("<II", directories, 1 * 8, 0x12000, 0xDC0)
    struct.pack_into("<II", directories, 5 * 8, 0x14000, 0x5A0)
    struct.pack_into("<II", directories, 12 * 8, 0x12254, 0x1F0)
    section_rows = (
        (b".text\0\0\0", 0xB500, 0x1000, 0xB600, 0x400, 0x60000020),
        (b".data\0\0\0", 0x5C, 0xD000, 0x200, 0xBA00, 0xC0000040),
        (b".rdata\0\0", 0x1F6C, 0xE000, 0x2000, 0xBC00, 0x40000040),
        (b".bss\0\0\0\0", 0xA54, 0x10000, 0, 0, 0xC0000080),
        (b".edata\0\0", 0x2F, 0x11000, 0x200, 0xDC00, 0x40000040),
        (b".idata\0\0", 0xDC0, 0x12000, 0xE00, 0xDE00, 0xC0000040),
        (b".tls\0\0\0\0", 0x8, 0x13000, 0x200, 0xEC00, 0xC0000040),
        (b".reloc\0\0", 0x5A0, 0x14000, 0x600, 0xEE00, 0x42000040),
    )
    sections = b"".join(
        struct.pack(
            "<8sIIIIIIHHI",
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            0,
            0,
            0,
            0,
            characteristics,
        )
        for (
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            characteristics,
        ) in section_rows
    )
    headers = (
        bytes(dos)
        + b"PE\0\0"
        + coff
        + optional_prefix
        + bytes(directories)
        + sections
    ).ljust(headers_size, b"\0")
    return headers + bytes(file_size - headers_size)


def _mutate_u32(image: bytes, offset: int, value: int) -> bytes:
    mutated = bytearray(image)
    struct.pack_into("<I", mutated, offset, value)
    return bytes(mutated)


def _lean_tree(name: str, image: bytes, *, cached_size: int | None = None) -> str:
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0] if len(image) >= 0x40 else 0
    if len(image) >= pe_offset + 24 + 64:
        header_size = min(
            len(image), struct.unpack_from("<I", image, pe_offset + 24 + 60)[0]
        )
    else:
        header_size = len(image)
    header = image[:header_size]
    tail_size = len(image) - len(header)
    values = ", ".join(str(byte) for byte in header)
    node_size = len(image) if cached_size is None else cached_size
    return f"""def {name} : ByteTree :=
  .node {node_size} {len(header)} (.leaf [{values}])
    (.leaf (List.replicate {tail_size} 0))
"""


class StageALoaderImageValidTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel proofs")
    def test_preferred_base_loader_accepts_valid_images_and_rejects_mutants(
        self,
    ) -> None:
        generic = _generic_pe32_image()
        expanded_headers = _expanded_headers_pe32_image()
        jq_layout = _jq_layout_pe32_image()
        pe_offset = 0x80
        optional_offset = pe_offset + 24
        section_table_offset = optional_offset + 224

        mutants = {
            "truncatedHeaderTree": generic[: section_table_offset + 40 - 1],
            "overflowingImageTree": _mutate_u32(
                _mutate_u32(generic, optional_offset + 28, 0xFFFF0000),
                optional_offset + 56,
                0x20000,
            ),
            "badFileAlignmentTree": _mutate_u32(
                generic, optional_offset + 36, 0x300
            ),
            "badSectionAlignmentTree": _mutate_u32(
                generic, optional_offset + 32, 0x1800
            ),
            "badHeadersSizeTree": _mutate_u32(
                generic, optional_offset + 60, 0x400
            ),
            "badImageSizeTree": _mutate_u32(
                generic, optional_offset + 56, 0x3000
            ),
            "mappedOverlapTree": _mutate_u32(
                jq_layout, section_table_offset + 40 + 12, 0x1000
            ),
            "rawOverlapTree": _mutate_u32(
                jq_layout, section_table_offset + 40 + 20, 0x400
            ),
            "rawOutOfBoundsTree": _mutate_u32(
                jq_layout, section_table_offset + 7 * 40 + 20, 0xF200
            ),
            "shortDirectoryCountTree": _mutate_u32(
                jq_layout, optional_offset + 92, 1
            ),
            "halfImportDirectoryTree": _mutate_u32(
                jq_layout, optional_offset + 96 + 1 * 8 + 4, 0
            ),
        }

        tree_definitions = [
            _lean_tree("genericTree", generic),
            _lean_tree("expandedHeadersTree", expanded_headers),
            _lean_tree("jqLayoutTree", jq_layout),
            *(_lean_tree(name, image) for name, image in mutants.items()),
            _lean_tree("badCachedSizeTree", generic, cached_size=len(generic) + 1),
        ]
        rejected = [*mutants, "badCachedSizeTree"]
        rejected_examples = "\n".join(
            f"example : loaderChecked {name} = false := by native_decide"
            for name in rejected
        )

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            for module in (
                "Formal",
                "RelationalDecode",
                "RelationalLoader",
                "RelationalMachine",
            ):
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )

            (stage_a / "LoaderImageValidKernel.lean").write_text(
                f"""import StageA.RelationalMachine

namespace StageA.LoaderImageValidKernel

open StageA.Formal StageA.Relational

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def loaderChecked (bytes : ByteTree) : Bool :=
  match parsePE32Tree bytes with
  | some pe => preferredBaseLoaderImageValid pe
  | none => false

{"".join(tree_definitions)}
example : loaderChecked genericTree = true := by native_decide
example : loaderChecked expandedHeadersTree = true := by native_decide
example : loaderChecked jqLayoutTree = true := by native_decide

{rejected_examples}

def nonPreferredPolicy : PE32LoaderPolicy := {{ preferredBaseOnly := false }}

example :
    (match parsePE32Tree genericTree with
    | some pe => pe32LoaderImageValid nonPreferredPolicy pe
    | none => true) = false := by native_decide

end StageA.LoaderImageValidKernel
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="LoaderImageValidKernel"
            )
            self.assertEqual(result["status"], "checked", result)


if __name__ == "__main__":
    unittest.main()
