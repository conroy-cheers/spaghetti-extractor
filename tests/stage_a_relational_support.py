import json
import os
import shutil
import struct
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from threading import Event, Timer
from types import SimpleNamespace
from unittest.mock import patch

from wincr.stage_a_relational import (
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_ENVIRONMENT_ID,
    RELATIONAL_KERNEL_MODULES,
    RELATIONAL_OBSERVATIONS,
    RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
    _attach_import_register_analysis,
    _attach_import_seed_address_separations,
    _attach_dynamic_indirect_call_analysis,
    _attach_external_call_site_analysis,
    _attach_return_write_address_separations,
    _attach_return_slot_contracts,
    _attach_stack_window_invariants,
    _attach_register_relation_analysis,
    _assembled_iat_read_candidates,
    _cached_behavior_affected_by_machine_contracts,
    _compact_acceptance_blockers,
    _composition_progress,
    _direct_call_push_claim,
    _direct_call_stack_amount,
    _dynamic_range_indirect_call_candidates,
    _dynamic_pointer_traversal_diagnostic,
    _dynamic_range_register_output_claims,
    _dynamic_range_relations,
    _dynamic_range_transfer_claims,
    _external_argument_relation_claims,
    _external_call_site_candidates,
    _external_register_policy_replay_candidate,
    _finalize_nix_proof_ir,
    _immutable_indirect_call_candidates,
    _iat_import_register_seed_candidates,
    _import_register_transfer_claims,
    _infer_import_register_invariants,
    _iat_read_classification,
    _lean_identical_state_only_write_registers,
    _lean_identical_state_only_writes_component,
    _lower_stack_register_relations,
    _machine_import_call_contract_analysis,
    _machine_import_call_contracts,
    _mapped_relocation_offsets,
    _normalize_contract,
    _normalized_behavior_fast_path,
    _nonzero_word_guard,
    _partition_proof_shards,
    _persistent_olean_path,
    _paired_stack_guard_claim,
    _paired_stack_word_write_claim,
    _paired_stack_word_writes_claim,
    _relational_nix_build_command,
    _relational_cache_dir,
    _return_pop_claim,
    _relational_extraction_semantics_sha256,
    _related_word_zero_guard_claim,
    _relational_product_graph,
    _run_lean_relational,
    _semantic_affine_word_read,
    _semantic_memory_pullback_support,
    _semantic_read32_after_writes,
    _semantic_constant_bool,
    _semantic_x87_load_pullback_supported,
    _stack_read32_sub_output_claim,
    _stack_window_transfer_claims,
    _static_dynamic_pointer_slots,
    _static_dynamic_pointer_slot_guard_claim,
    _static_dynamic_pointer_seed_diagnostic,
    _synthesize_register_relations,
    _synthesize_relational_invariants,
    _validate_relational_module_graph,
    _validate_prepared_relational,
    _write_reachable_product_local_certificate,
    stage_a_build_relational,
    stage_a_check_relational_proof,
    stage_a_generate_relation_contract,
    stage_a_prepare_relational,
    stage_a_prove_relational,
)
from wincr.stage_binary import StageAImport, StageAInputError, _parse_stage_a_pe




class StageARelationalTestBase(unittest.TestCase):
    def _write_contract(
        self,
        path: Path,
        *,
        region_size: int = 4,
        candidate_region_size: int | None = None,
        target_rva: int = 0x1000,
    ) -> Path:
        candidate_region_size = candidate_region_size or region_size
        pairs = [{"original": register, "candidate": register} for register in (
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
        )]
        payload = {
            "format": "stage-a-relation-contract-v1",
            "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
            "observations": RELATIONAL_OBSERVATIONS,
            "code_targets": [{"id": 0, "original_rva": target_rva, "candidate_rva": target_rva}],
            "regions": [{
                "id": "entry-loop",
                "root": True,
                "original": {"rva": 0x1000, "size": region_size},
                "candidate": {"rva": 0x1000, "size": candidate_region_size},
                "inputs": pairs,
                "outputs": pairs,
            }],
            "padding": [],
            "memory_relation": {"mode": "identity"},
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def _write_pe(path: Path, code: bytes) -> Path:
        path.write_bytes(_pe32_image(code))
        return path



def _pe32_image(code: bytes) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw_size = _align(len(code), file_alignment)
    size_of_image = _align(text_rva + len(code), section_alignment)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, 0, 0, text_rva, text_rva, 0, 0x400000,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, size_of_image,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, text_raw_size,
        headers_size, 0, 0, 0, 0, 0x60000020,
    )
    headers = (bytes(dos) + b"PE\0\0" + coff + optional + section).ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0")


def _pe32_import_image(
    code: bytes, *, symbol: str, dll: str = "KERNEL32.dll", iat_offset: int = 0x40,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    idata_rva = 0x2000
    text_raw = 0x200
    text_raw_size = _align(len(code), file_alignment)
    idata_raw = text_raw + text_raw_size
    idata_raw_size = 0x200
    size_of_image = _align(idata_rva + idata_raw_size, section_alignment)

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
        0x10B, 0, 0, text_raw_size, idata_raw_size, 0, text_rva, text_rva,
        idata_rva, image_base, section_alignment, file_alignment, 4, 0, 0, 0,
        4, 0, 0, size_of_image, headers_size, 0, 3, 0, 0x100000, 0x1000,
        0x100000, 0x1000, 0, 16,
    )
    optional = bytearray(optional_prefix + (b"\0" * (16 * 8)))
    struct.pack_into("<II", optional, len(optional_prefix) + 8, idata_rva, 40)
    text_section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, text_raw_size,
        text_raw, 0, 0, 0, 0, 0x60000020,
    )
    idata_section = struct.pack(
        "<8sIIIIIIHHI", b".idata\0\0", idata_raw_size, idata_rva,
        idata_raw_size, idata_raw, 0, 0, 0, 0, 0x40000040,
    )
    headers = (
        bytes(dos) + b"PE\0\0" + coff + bytes(optional)
        + text_section + idata_section
    ).ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0") + bytes(idata)


def _pe32_representative_control_image(
    data_rva: int, *, terminal_rva: int = 0x1020,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x400
    image_base = 0x400000
    text_rva = 0x1000
    idata_rva = 0x2000
    reloc_rva = 0x5000
    text_raw = headers_size
    idata_raw = text_raw + 0x200
    data_raw = idata_raw + 0x200
    reloc_raw = data_raw + 0x200
    iat_rva = idata_rva + 0x40

    code = bytearray()
    code += b"\xe8\x10\x00\x00\x00"
    code += b"\xff\x15" + struct.pack("<I", image_base + iat_rva)
    code += b"\x85\xc0\x75\xfc"
    code += b"\xff\x25" + struct.pack("<I", image_base + data_rva)
    code += b"\xc3"
    code += b"\x90" * (terminal_rva - 0x1016)
    code += b"\xc3"

    int_rva = idata_rva + 0x30
    dll_name_rva = idata_rva + 0x50
    import_name_rva = idata_rva + 0x80
    idata = bytearray(0x200)
    struct.pack_into("<IIIII", idata, 0, int_rva, 0, 0, dll_name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x30, import_name_rva, 0)
    struct.pack_into("<II", idata, 0x40, import_name_rva, 0)
    idata[0x50:0x5D] = b"KERNEL32.dll\0"
    struct.pack_into("<H", idata, 0x80, 0)
    idata[0x82:0x8F] = b"GetTickCount\0"
    data = struct.pack("<I", image_base + terminal_rva)

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        return (
            struct.pack("<II", page_rva, 8 + 2 * len(entries))
            + struct.pack("<" + "H" * len(entries), *entries)
        )

    relocations = (
        relocation_block(text_rva, [7, 17])
        + relocation_block(data_rva, [0])
    )
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 4, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x600, 0, text_rva, text_rva, idata_rva,
        image_base, section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0,
        0x6000, headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000,
        0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 1 * 8, idata_rva, 40)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200,
            text_raw, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".idata\0\0", len(idata), idata_rva, 0x200,
            idata_raw, 0, 0, 0, 0, 0x40000040,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".rdata\0\0", len(data), data_rva, 0x200,
            data_raw, 0, 0, 0, 0, 0x40000040,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200,
            reloc_raw, 0, 0, 0, 0, 0x42000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories)
        + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + bytes(code).ljust(0x200, b"\0")
        + bytes(idata) + data.ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _pe32_image_with_relocated_data(data_rva: int, *, writable: bool = True) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x4000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    code = b"\xdd\x05" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf8"
    data = struct.pack("<d", 1.5)
    relocations = struct.pack("<IIHH", text_rva, 12, 0x3002, 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x400, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x5000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200, text_raw, 0, 0, 0, 0, 0x60000020),
        struct.pack(
            "<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200, data_raw,
            0, 0, 0, 0, 0xC0000040 if writable else 0x40000040,
        ),
        struct.pack("<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200, reloc_raw, 0, 0, 0, 0, 0x42000040),
    ))
    headers = (bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections).ljust(headers_size, b"\0")
    return headers + code.ljust(0x200, b"\0") + data.ljust(0x200, b"\0") + relocations.ljust(0x200, b"\0")


def _pe32_image_with_relocation_pointer_table(
    data_rva: int,
    *,
    mask_index: bool = False,
    duplicate_data_entry: bool = False,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x5000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    if mask_index:
        code = b"\x83\xe2\xff\x8b\x1c\x95" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf4"
        relocation_offset = 6
    else:
        code = b"\x8b\x1c\x95" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf7"
        relocation_offset = 3
    data = bytearray(0x40)
    struct.pack_into("<II", data, 0, image_base + data_rva + 0x20, image_base + data_rva + 0x30)
    data[0x20:0x26] = b"first\0"
    data[0x30:0x37] = b"second\0"

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        size = 8 + 2 * len(entries)
        return struct.pack("<II", page_rva, size) + struct.pack("<" + "H" * len(entries), *entries)

    data_relocations = [0, 0, 4] if duplicate_data_entry else [0, 4]
    relocations = relocation_block(text_rva, [relocation_offset]) + relocation_block(
        data_rva, data_relocations
    )
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x400, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x6000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200, text_raw, 0, 0, 0, 0, 0x60000020),
        struct.pack("<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200, data_raw, 0, 0, 0, 0, 0xC0000040),
        struct.pack("<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200, reloc_raw, 0, 0, 0, 0, 0x42000040),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + code.ljust(0x200, b"\0") + bytes(data).ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _pe32_image_with_immutable_indirect_call(
    data_rva: int, *, callee_rva: int = 0x1030, writable: bool = False,
    jump: bool = False,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x5000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    source = (
        b"\xff\x25" + struct.pack("<I", image_base + data_rva)
        if jump else
        b"\xc7\x44\x24\x08\x00\x00\x00\x00"
        b"\xc7\x44\x24\x04\x02\x00\x00\x00"
        b"\xc7\x04\x24\x00\x00\x00\x00"
        b"\xff\x15" + struct.pack("<I", image_base + data_rva)
    )
    code = bytearray(b"\x90" * (callee_rva - text_rva + 1))
    code[:len(source)] = source
    if not jump:
        code[0x1D:0x1F] = b"\xeb\xfe"
    code[callee_rva - text_rva] = 0xC3
    data = struct.pack("<I", image_base + callee_rva)

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        return (
            struct.pack("<II", page_rva, 8 + 2 * len(entries))
            + struct.pack("<" + "H" * len(entries), *entries)
        )

    relocations = (
        relocation_block(text_rva, [2 if jump else 25])
        + relocation_block(data_rva, [0])
    )
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x200, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x6000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    data_characteristics = 0xC0000040 if writable else 0x40000040
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200,
            text_raw, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".rdata\0\0", len(data), data_rva, 0x200,
            data_raw, 0, 0, 0, 0, data_characteristics,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200,
            reloc_raw, 0, 0, 0, 0, 0x42000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + bytes(code).ljust(0x200, b"\0") + data.ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _pe32_image_with_stack_write_and_relocated_read(data_rva: int) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x4000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    code = b"\xc7\x44\x24\x08\x00\x00\x00\x00\xa1" + struct.pack(
        "<I", image_base + data_rva
    ) + b"\xeb\xf1"
    data = struct.pack("<I", 0x12345678)
    relocations = struct.pack("<IIHH", text_rva, 12, 0x3009, 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x200, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x5000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200,
            text_raw, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200,
            data_raw, 0, 0, 0, 0, 0xC0000040,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200,
            reloc_raw, 0, 0, 0, 0, 0x42000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + code.ljust(0x200, b"\0") + data.ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment

__all__ = [name for name in globals() if not name.startswith("__")]
