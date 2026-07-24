from __future__ import annotations

import dataclasses
import re
import struct
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.nullable_code_pointer_table import (
    CodeTargetProposal,
    DispatchEdgeProposal,
    LoopFactsProposal,
    NullableCodePointerTableCertificateSpec,
    NullableCodePointerTableGenerationError,
    RvaRangeProposal,
    TableAliasProposal,
    TableWriterProposal,
    nullable_code_pointer_table_source,
)


IMAGE_BASE = 0x18000000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
RELOC_RVA = 0x3000
TEXT_RAW = 0x200
DATA_RAW = 0x400
RELOC_RAW = 0x600


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _nullable_table_pe(
    *,
    words: tuple[int, ...],
    table_offset: int = 0,
    relocation_offsets: tuple[int, ...] = (),
    writable_table: bool = False,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    raw_size = 0x200
    image = bytearray(RELOC_RAW + raw_size)

    dos = bytearray(0x80)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    image[: len(dos)] = dos
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", image, 0x84, 0x14C, 3, 0, 0, 0, 224, 0x010F
    )
    optional_offset = 0x98
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        raw_size,
        raw_size * 2,
        0,
        TEXT_RVA,
        TEXT_RVA,
        DATA_RVA,
        IMAGE_BASE,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        _align(RELOC_RVA + raw_size, section_alignment),
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

    relocation_entries = [0x3000 | offset for offset in relocation_offsets]
    if len(relocation_entries) % 2 == 1:
        relocation_entries.append(0)
    relocation_block = b""
    if relocation_entries:
        block_size = 8 + len(relocation_entries) * 2
        relocation_block = struct.pack("<II", DATA_RVA, block_size) + b"".join(
            struct.pack("<H", entry) for entry in relocation_entries
        )
        struct.pack_into(
            "<II", optional, len(optional_prefix) + 5 * 8,
            RELOC_RVA, len(relocation_block)
        )
    image[optional_offset : optional_offset + 224] = optional

    section_offset = optional_offset + 224
    data_characteristics = 0xC0000040 if writable_table else 0x40000040
    sections = (
        (b".text\0\0\0", TEXT_RVA, TEXT_RAW, 0x60000020),
        (b".rdata\0\0", DATA_RVA, DATA_RAW, data_characteristics),
        (b".reloc\0\0", RELOC_RVA, RELOC_RAW, 0x42000040),
    )
    for index, (name, rva, raw, characteristics) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            image,
            section_offset + index * 40,
            name,
            raw_size,
            rva,
            raw_size,
            raw,
            0,
            0,
            0,
            0,
            characteristics,
        )

    image[TEXT_RAW : TEXT_RAW + raw_size] = b"\x90" * raw_size
    for index, word in enumerate(words):
        struct.pack_into("<I", image, DATA_RAW + table_offset + index * 4, word)
    image[RELOC_RAW : RELOC_RAW + len(relocation_block)] = relocation_block
    return bytes(image)


def sentinel_empty_spec() -> NullableCodePointerTableCertificateSpec:
    start = DATA_RVA + 4
    return NullableCodePointerTableCertificateSpec(
        definition_name="sentinelEmptyCertificate",
        pe_bytes=_nullable_table_pe(words=(0xFFFFFFFF, 0)),
        context_id=11,
        dispatch_rva=TEXT_RVA + 0x10,
        table_rva=DATA_RVA,
        header_words=(0xFFFFFFFF,),
        caller_range=RvaRangeProposal(start, start + 4),
        code_map=(),
        non_null_target_ids=(),
        edges=(),
        writers=(),
        aliases=(),
        loop=LoopFactsProposal(0, 1, 1, start),
        guard="nonzero",
    )


def one_zero_spec() -> NullableCodePointerTableCertificateSpec:
    start = DATA_RVA + 0x20
    return NullableCodePointerTableCertificateSpec(
        definition_name="oneZeroCertificate",
        pe_bytes=_nullable_table_pe(words=(0,), table_offset=0x20),
        context_id=12,
        dispatch_rva=TEXT_RVA + 0x20,
        table_rva=start,
        header_words=(),
        caller_range=RvaRangeProposal(start, start + 4),
        code_map=(),
        non_null_target_ids=(),
        edges=(),
        writers=(),
        aliases=(),
        loop=LoopFactsProposal(4, 5, 1, start),
        guard="nonzero",
    )


def nonzero_spec() -> NullableCodePointerTableCertificateSpec:
    table_offset = 0x40
    table_rva = DATA_RVA + table_offset
    target_id = 7
    context_id = 13
    return NullableCodePointerTableCertificateSpec(
        definition_name="nonzeroCertificate",
        pe_bytes=_nullable_table_pe(
            words=(IMAGE_BASE + TEXT_RVA,),
            table_offset=table_offset,
            relocation_offsets=(table_offset,),
        ),
        context_id=context_id,
        dispatch_rva=TEXT_RVA + 0x30,
        table_rva=table_rva,
        header_words=(),
        caller_range=RvaRangeProposal(table_rva, table_rva + 4),
        code_map=(CodeTargetProposal(target_id, TEXT_RVA),),
        non_null_target_ids=(target_id,),
        edges=(DispatchEdgeProposal(context_id, target_id),),
        writers=(),
        aliases=(),
        loop=LoopFactsProposal(0, 1, 1, table_rva),
        guard="nonzero",
    )


class StageANullableCodePointerTableTests(unittest.TestCase):
    def test_emits_exact_bytes_and_unreachable_kernel_obligations(self) -> None:
        source = nullable_code_pointer_table_source(sentinel_empty_spec())

        self.assertIn("headerWords := [4294967295]", source)
        self.assertIn(".exact []", source)
        self.assertIn(".nonzero", source)
        self.assertIn("indirectDispatchUnreachable = true", source)
        self.assertIn("NoIndirectDispatch", source)
        self.assertNotIn("native_decide", source)

    def test_unknown_facts_are_serialized_for_lean_to_reject(self) -> None:
        spec = dataclasses.replace(
            one_zero_spec(),
            definition_name="unknownCertificate",
            caller_range=None,
            non_null_target_ids=None,
        )
        source = nullable_code_pointer_table_source(
            spec, expectation="rejected"
        )

        self.assertGreaterEqual(source.count(".unknown"), 2)
        self.assertIn("unknownCertificate.checked = false", source)
        self.assertNotIn("IndirectDispatchUnreachable = true", source)

    def test_writers_and_aliases_are_explicit_finite_proposals(self) -> None:
        spec = one_zero_spec()
        writer = TableWriterProposal(
            TEXT_RVA + 4, RvaRangeProposal(DATA_RVA + 0x20, DATA_RVA + 0x24)
        )
        alias = TableAliasProposal(DATA_RVA + 0x60, DATA_RVA + 0x20)
        source = nullable_code_pointer_table_source(
            dataclasses.replace(
                spec,
                definition_name="blockedCertificate",
                writers=(writer,),
                aliases=(alias,),
            ),
            expectation="rejected",
        )

        self.assertIn("sourceRva", source)
        self.assertIn("aliasRva", source)
        self.assertIn("blockedCertificate.checked = false", source)

    def test_nonzero_fixture_emits_relocation_backed_target_and_edge(self) -> None:
        source = nullable_code_pointer_table_source(
            nonzero_spec(), expectation="accepted"
        )

        self.assertIn("targetId := 7", source)
        self.assertIn("sourceContextId := 13", source)
        self.assertIn("nonzeroCertificate.checked = true", source)
        self.assertNotIn("NoIndirectDispatch", source)

    def test_rejects_invalid_lean_names_and_non_words(self) -> None:
        with self.assertRaises(NullableCodePointerTableGenerationError):
            nullable_code_pointer_table_source(
                dataclasses.replace(one_zero_spec(), definition_name="bad-name")
            )
        with self.assertRaises(NullableCodePointerTableGenerationError):
            nullable_code_pointer_table_source(
                dataclasses.replace(one_zero_spec(), header_words=(1 << 32,))
            )

    def test_reviewed_lean_checker_has_no_escape_markers(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalNullableCodePointerTable.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for required in (
            "parsePE32 certificate.peBytes",
            "parseRelocations pe",
            "readImmutableExactRvaU32",
            "relocationCount relocations rva != 1",
            "noIndirectDispatch_of_unreachable",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
