"""Plan, render, and validate a deterministic PE32 candidate image."""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import (
    PAYLOAD_RELOCATION_INVENTORY_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
)
from ..pe32.recovered_executable_data import RecoveredExecutableDataContract
from ..roundtrip_fuzz.image_model import (
    StageALoadImageContract,
)
from ..util import sha256_bytes
from .pe_model import (
    CANDIDATE_FILENAME,
    COMPOSITION_MANIFEST_FILENAME,
    EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
    ByteClassification,
    ExecutableAnchor,
    ExecutableAnchorManifest,
    PECompositionPlan,
    PayloadRelocation,
    PayloadRelocationInventory,
    StageBPECompositionError,
    _DIRECTORY_BASE_RELOCATION,
    _DIRECTORY_NAMES,
    _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    _IMAGE_FILE_RELOCS_STRIPPED,
    _IMAGE_REL_BASED_ABSOLUTE,
    _IMAGE_REL_BASED_HIGHLOW,
    _IMAGE_SCN_CNT_CODE,
    _IMAGE_SCN_CNT_INITIALIZED_DATA,
    _IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    _MergedRelocation,
    _PADDING_BYTE,
    _RELOCATION_SECTION_CHARACTERISTICS,
    _Section,
    _TRAP_BYTE,
    _UINT16_MAX,
    _UINT32_MAX,
    _align_up,
    _canonical_bytes,
    _classify_executable_bytes,
    _directories,
    _load_anchor_manifest,
    _load_contract,
    _load_payload,
    _load_recovered_executable_data,
    _load_relocation_inventory,
    _merge_relocations,
    _parse_payload_relocation_directory,
    _pe_from_bytes,
    _plan_file_offset_rewrites,
    _section_containing_rva,
    _sections_from_pe,
    _shift_original_raw_pointers,
    _validate_anchors,
    _validate_original_layout,
    _validate_payload,
    _validate_payload_relocation_inventory,
    _validate_pe32_identity,
    _validate_recovered_executable_data,
)


def _encode_relocation_directory(
    relocations: tuple[_MergedRelocation, ...],
) -> bytes:
    pages: dict[int, list[int]] = {}
    for relocation in relocations:
        if relocation.type != _IMAGE_REL_BASED_HIGHLOW or relocation.width != 4:
            raise StageBPECompositionError(
                "only PE32 HIGHLOW relocations can be encoded"
            )
        page_rva = relocation.target_rva & ~0xFFF
        offset = relocation.target_rva - page_rva
        pages.setdefault(page_rva, []).append(
            (_IMAGE_REL_BASED_HIGHLOW << 12) | offset
        )

    result = bytearray()
    for page_rva in sorted(pages):
        slots = sorted(pages[page_rva])
        if len(set(slots)) != len(slots):
            raise StageBPECompositionError(
                "merged relocation directory contains a duplicate slot"
            )
        if len(slots) % 2:
            slots.append(_IMAGE_REL_BASED_ABSOLUTE)
        block_size = 8 + 2 * len(slots)
        result.extend(struct.pack("<II", page_rva, block_size))
        result.extend(struct.pack("<" + "H" * len(slots), *slots))
    return bytes(result)


def plan_stage_b_pe_composition(
    *,
    load_image_contract: Path | str | Mapping[str, Any] | StageALoadImageContract,
    payload_pe: Path | str | bytes | bytearray,
    anchor_manifest: Path | str | Mapping[str, Any] | ExecutableAnchorManifest,
    payload_relocation_inventory: (
        Path | str | Mapping[str, Any] | PayloadRelocationInventory | None
    ) = None,
    recovered_executable_data: (
        Path
        | str
        | Mapping[str, Any]
        | RecoveredExecutableDataContract
        | None
    ) = None,
) -> PECompositionPlan:
    """Validate all inputs and return a deterministic, write-free plan."""

    contract = _load_contract(load_image_contract)
    anchors = _load_anchor_manifest(anchor_manifest)
    recovered = _load_recovered_executable_data(recovered_executable_data)
    payload = _load_payload(payload_pe)
    (
        original_pe,
        contract_original_sections,
        section_table_offset,
        file_alignment,
        section_alignment,
        original_directories,
    ) = _validate_original_layout(contract)
    dynamic_base = bool(
        int(original_pe.OPTIONAL_HEADER.DllCharacteristics)
        & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    )
    runtime_relocations = (
        original_directories[_DIRECTORY_BASE_RELOCATION] != (0, 0)
    )
    payload_header, payload_sections, payload_directories = _validate_payload(
        payload,
        contract=contract,
        original_sections=contract_original_sections,
        file_alignment=file_alignment,
        section_alignment=section_alignment,
    )
    indexed_anchors = _validate_anchors(
        anchors, contract=contract, sections=contract_original_sections
    )
    recovered_ranges = _validate_recovered_executable_data(
        recovered,
        contract=contract,
        sections=contract_original_sections,
        indexed_anchors=indexed_anchors,
    )

    parsed_payload_inventory = _parse_payload_relocation_directory(
        payload,
        payload_sections,
        payload_directories[_DIRECTORY_BASE_RELOCATION],
        image_base=int(payload_header.OPTIONAL_HEADER.ImageBase),
    )
    payload_relocation_directory_present = (
        payload_directories[_DIRECTORY_BASE_RELOCATION] != (0, 0)
    )
    if payload_relocation_inventory is None:
        if not payload_relocation_directory_present:
            raise StageBPECompositionError(
                "payload without a base-relocation directory requires a complete "
                "payload relocation inventory"
            )
        relocation_inventory = parsed_payload_inventory
    else:
        relocation_inventory = _load_relocation_inventory(
            payload_relocation_inventory
        )
        if (
            payload_relocation_directory_present
            and relocation_inventory.relocations
            != parsed_payload_inventory.relocations
        ):
            raise StageBPECompositionError(
                "payload relocation inventory disagrees with the PE directory"
            )
    _validate_payload_relocation_inventory(
        relocation_inventory,
        payload=payload,
        payload_sections=payload_sections,
        image_base=int(payload_header.OPTIONAL_HEADER.ImageBase),
    )

    classifications = _classify_executable_bytes(
        contract_original_sections, indexed_anchors, recovered_ranges
    )
    provisional_payload_sections = tuple(
        _Section(
            index=len(contract_original_sections) + section.index,
            name_bytes=section.name_bytes,
            virtual_size=section.virtual_size,
            rva=section.rva,
            raw_size=section.raw_size,
            raw_pointer=section.raw_pointer,
            characteristics=section.characteristics,
        )
        for section in payload_sections
    )
    merged_relocations = _merge_relocations(
        contract=contract,
        anchor_manifest=anchors,
        original_sections=contract_original_sections,
        payload_inventory=relocation_inventory,
        payload_sections=payload_sections,
        output_payload_sections=provisional_payload_sections,
    )
    relocation_data = (
        _encode_relocation_directory(merged_relocations)
        if runtime_relocations
        else b""
    )

    total_sections = (
        len(contract_original_sections)
        + len(payload_sections)
        + bool(relocation_data)
    )
    if total_sections > _UINT16_MAX:
        raise StageBPECompositionError("composed PE section count exceeds 16 bits")
    new_table_end = section_table_offset + total_sections * 40
    original_size_of_headers = contract.identity.size_of_headers
    new_size_of_headers = max(
        original_size_of_headers,
        _align_up(new_table_end, file_alignment),
    )
    if new_size_of_headers > _UINT32_MAX:
        raise StageBPECompositionError("expanded PE headers exceed PE32 file offsets")
    original_raw_pointer_shift = new_size_of_headers - original_size_of_headers
    original_sections = _shift_original_raw_pointers(
        contract_original_sections, original_raw_pointer_shift
    )
    file_offset_rewrites = _plan_file_offset_rewrites(
        contract,
        contract_original_sections,
        original_directories,
        raw_pointer_shift=original_raw_pointer_shift,
    )
    coff_symbol_table_stripped = bool(
        int(original_pe.FILE_HEADER.PointerToSymbolTable)
        or int(original_pe.FILE_HEADER.NumberOfSymbols)
    )

    raw_cursor = _align_up(
        max(
            new_size_of_headers,
            *(section.raw_end for section in original_sections if section.raw_size),
        ),
        file_alignment,
    )
    output_payload_sections: list[_Section] = []
    for section in payload_sections:
        raw_pointer = raw_cursor if section.raw_size else 0
        output_payload_sections.append(
            _Section(
                index=len(original_sections) + section.index,
                name_bytes=section.name_bytes,
                virtual_size=section.virtual_size,
                rva=section.rva,
                raw_size=section.raw_size,
                raw_pointer=raw_pointer,
                characteristics=section.characteristics,
            )
        )
        raw_cursor += section.raw_size
    output_payload_sections_tuple = tuple(output_payload_sections)

    relocation_section: _Section | None = None
    if relocation_data:
        relocation_rva = _align_up(
            max(
                new_size_of_headers,
                *(section.mapped_end for section in original_sections),
                *(section.mapped_end for section in output_payload_sections_tuple),
            ),
            section_alignment,
        )
        relocation_raw_size = _align_up(len(relocation_data), file_alignment)
        if relocation_rva > _UINT32_MAX - relocation_raw_size:
            raise StageBPECompositionError(
                "merged relocation section exceeds PE32 RVA space"
            )
        relocation_section = _Section(
            index=len(original_sections) + len(output_payload_sections_tuple),
            name_bytes=b".sreloc\0",
            virtual_size=len(relocation_data),
            rva=relocation_rva,
            raw_size=relocation_raw_size,
            raw_pointer=raw_cursor,
            characteristics=_RELOCATION_SECTION_CHARACTERISTICS,
        )
        relocation_directory = (relocation_rva, len(relocation_data))
    else:
        relocation_directory = (0, 0)

    new_size_of_image = _align_up(
        max(
            new_size_of_headers,
            *(section.mapped_end for section in original_sections),
            *(section.mapped_end for section in output_payload_sections_tuple),
            *(() if relocation_section is None else (relocation_section.mapped_end,)),
        ),
        section_alignment,
    )
    payload_header.close()
    original_pe.close()
    return PECompositionPlan(
        contract=contract,
        anchor_manifest=anchors,
        recovered_executable_data=recovered,
        relocation_inventory=relocation_inventory,
        payload_bytes=payload,
        contract_original_sections=contract_original_sections,
        original_sections=original_sections,
        payload_sections=payload_sections,
        output_payload_sections=output_payload_sections_tuple,
        classifications=classifications,
        merged_relocations=merged_relocations,
        relocation_data=relocation_data,
        relocation_section=relocation_section,
        relocation_directory=relocation_directory,
        dynamic_base=dynamic_base,
        runtime_relocations=runtime_relocations,
        section_table_offset=section_table_offset,
        file_alignment=file_alignment,
        section_alignment=section_alignment,
        original_size_of_headers=original_size_of_headers,
        new_size_of_headers=new_size_of_headers,
        original_raw_pointer_shift=original_raw_pointer_shift,
        file_offset_rewrites=file_offset_rewrites,
        coff_symbol_table_stripped=coff_symbol_table_stripped,
        new_size_of_image=new_size_of_image,
        original_directories=original_directories,
    )


def _original_section_bytes(
    plan: PECompositionPlan, section: _Section
) -> bytes:
    typed_sections = {section.index: section for section in plan.contract.sections}
    if not section.raw_size:
        return b""
    if section.executable:
        logical_size = (
            min(section.virtual_size, section.raw_size)
            if section.virtual_size
            else section.raw_size
        )
        result = bytearray(bytes([_TRAP_BYTE]) * logical_size)
        result.extend(bytes([_PADDING_BYTE]) * (section.raw_size - logical_size))
        if plan.recovered_executable_data is not None:
            for item in plan.recovered_executable_data.ranges:
                if item.section_index != section.index:
                    continue
                offset = item.rva_start - section.rva
                result[offset : offset + item.size] = item.data
    else:
        typed = typed_sections[section.index]
        if len(typed.initialized) != 1:
            raise StageBPECompositionError(
                f"non-executable section {section.index} lost initialized bytes"
            )
        result = bytearray(typed.initialized[0].data)
        if len(result) != section.raw_size:
            raise StageBPECompositionError(
                f"non-executable section {section.index} changed raw size"
            )

    for anchor in plan.anchor_manifest.anchors:
        if section.rva <= anchor.rva and anchor.end_rva <= section.rva + section.raw_size:
            offset = anchor.rva - section.rva
            result[offset : offset + len(anchor.bytes)] = anchor.bytes
    for rewrite in plan.file_offset_rewrites:
        if section.rva <= rewrite.field_rva and rewrite.field_rva + 4 <= section.rva + section.raw_size:
            offset = rewrite.field_rva - section.rva
            observed = struct.unpack_from("<I", result, offset)[0]
            if observed != rewrite.old_value:
                raise StageBPECompositionError(
                    f"{rewrite.kind} {rewrite.index} changed before header growth"
                )
            struct.pack_into("<I", result, offset, rewrite.new_value)
    return bytes(result)


def _fill_original_sections(image: bytearray, plan: PECompositionPlan) -> None:
    for section in plan.original_sections:
        if not section.raw_size:
            continue
        image[section.raw_pointer : section.raw_end] = _original_section_bytes(
            plan, section
        )


def _append_payload_sections(image: bytearray, plan: PECompositionPlan) -> None:
    for source, output in zip(plan.payload_sections, plan.output_payload_sections):
        if not source.raw_size:
            continue
        data = plan.payload_bytes[source.raw_pointer : source.raw_end]
        if len(data) != source.raw_size:
            raise StageBPECompositionError(
                f"payload section {source.index} raw bytes changed after planning"
            )
        image[output.raw_pointer : output.raw_end] = data
    for relocation in plan.merged_relocations:
        if relocation.source != "payload":
            continue
        section = _section_containing_rva(
            plan.output_payload_sections,
            relocation.target_rva,
            relocation.width,
            context="composed payload HIGHLOW relocation target",
            require_raw=True,
        )
        offset = section.raw_pointer + relocation.target_rva - section.rva
        image[offset : offset + relocation.width] = relocation.preferred_value.to_bytes(
            relocation.width, "little"
        )


def _write_relocation_section(image: bytearray, plan: PECompositionPlan) -> None:
    section = plan.relocation_section
    if section is None:
        if plan.relocation_data:
            raise StageBPECompositionError(
                "merged relocations have no output section"
            )
        return
    if len(plan.relocation_data) > section.raw_size:
        raise StageBPECompositionError(
            "merged relocation directory exceeds its output section"
        )
    image[section.raw_pointer : section.raw_end] = plan.relocation_data.ljust(
        section.raw_size, b"\0"
    )


def _write_section_headers(image: bytearray, plan: PECompositionPlan) -> None:
    sections = plan.original_sections + plan.output_payload_sections + (
        () if plan.relocation_section is None else (plan.relocation_section,)
    )
    for section in sections:
        offset = plan.section_table_offset + section.index * 40
        struct.pack_into(
            "<8sIIIIIIHHI",
            image,
            offset,
            section.name_bytes,
            section.virtual_size,
            section.rva,
            section.raw_size,
            section.raw_pointer,
            0,
            0,
            0,
            0,
            section.characteristics,
        )


def _update_headers(image: bytearray, plan: PECompositionPlan) -> int:
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    file_header_offset = pe_offset + 4
    optional_offset = file_header_offset + 20
    all_sections = plan.original_sections + plan.output_payload_sections + (
        () if plan.relocation_section is None else (plan.relocation_section,)
    )

    struct.pack_into("<H", image, file_header_offset + 2, len(all_sections))
    struct.pack_into("<II", image, file_header_offset + 8, 0, 0)
    characteristics = struct.unpack_from("<H", image, file_header_offset + 18)[0]
    characteristics = (
        characteristics & ~_IMAGE_FILE_RELOCS_STRIPPED
        if plan.runtime_relocations
        else characteristics | _IMAGE_FILE_RELOCS_STRIPPED
    )
    struct.pack_into("<H", image, file_header_offset + 18, characteristics)
    size_of_code = sum(
        section.raw_size
        for section in all_sections
        if section.characteristics & _IMAGE_SCN_CNT_CODE
    )
    size_of_initialized = sum(
        section.raw_size
        for section in all_sections
        if section.characteristics & _IMAGE_SCN_CNT_INITIALIZED_DATA
    )
    size_of_uninitialized = sum(
        _align_up(section.virtual_size, plan.file_alignment)
        for section in all_sections
        if section.characteristics & _IMAGE_SCN_CNT_UNINITIALIZED_DATA
    )
    struct.pack_into("<I", image, optional_offset + 4, size_of_code)
    struct.pack_into("<I", image, optional_offset + 8, size_of_initialized)
    struct.pack_into("<I", image, optional_offset + 12, size_of_uninitialized)
    struct.pack_into(
        "<I", image, optional_offset + 16, plan.anchor_manifest.entry_anchor_rva
    )
    struct.pack_into("<I", image, optional_offset + 56, plan.new_size_of_image)
    struct.pack_into("<I", image, optional_offset + 60, plan.new_size_of_headers)
    struct.pack_into("<I", image, optional_offset + 64, 0)
    struct.pack_into(
        "<II",
        image,
        optional_offset + 96 + _DIRECTORY_BASE_RELOCATION * 8,
        *plan.relocation_directory,
    )
    dll_characteristics = struct.unpack_from("<H", image, optional_offset + 70)[0]
    dll_characteristics = (
        dll_characteristics | _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        if plan.dynamic_base
        else dll_characteristics & ~_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    )
    struct.pack_into("<H", image, optional_offset + 70, dll_characteristics)
    checksum_pe = _pe_from_bytes(bytes(image), context="checksum candidate")
    checksum = int(checksum_pe.generate_checksum())
    checksum_pe.close()
    struct.pack_into("<I", image, optional_offset + 64, checksum)
    return checksum


def _validate_candidate(image: bytes, plan: PECompositionPlan, checksum: int) -> None:
    pe = _pe_from_bytes(image, context="composed candidate")
    _validate_pe32_identity(pe, context="composed candidate")
    sections = _sections_from_pe(pe)
    expected_sections = plan.original_sections + plan.output_payload_sections + (
        () if plan.relocation_section is None else (plan.relocation_section,)
    )
    if sections != expected_sections:
        raise StageBPECompositionError("composed candidate section table changed unexpectedly")
    if int(pe.FILE_HEADER.NumberOfSections) != len(expected_sections):
        raise StageBPECompositionError("composed candidate section count did not update")
    if int(pe.OPTIONAL_HEADER.ImageBase) != plan.contract.identity.preferred_base:
        raise StageBPECompositionError("composed candidate image base changed")
    if int(pe.OPTIONAL_HEADER.SizeOfImage) != plan.new_size_of_image:
        raise StageBPECompositionError("composed candidate SizeOfImage did not update")
    if int(pe.OPTIONAL_HEADER.SizeOfHeaders) != plan.new_size_of_headers:
        raise StageBPECompositionError("composed candidate SizeOfHeaders did not update")
    if int(pe.FILE_HEADER.PointerToSymbolTable) or int(pe.FILE_HEADER.NumberOfSymbols):
        raise StageBPECompositionError(
            "composed candidate retains an unavailable COFF symbol table"
        )
    if int(pe.OPTIONAL_HEADER.AddressOfEntryPoint) != plan.anchor_manifest.entry_anchor_rva:
        raise StageBPECompositionError("composed candidate entry point did not update")
    if int(pe.OPTIONAL_HEADER.CheckSum) != checksum or not pe.verify_checksum():
        raise StageBPECompositionError("composed candidate checksum is invalid")
    relocations_stripped = bool(
        int(pe.FILE_HEADER.Characteristics) & _IMAGE_FILE_RELOCS_STRIPPED
    )
    if relocations_stripped == plan.runtime_relocations:
        raise StageBPECompositionError(
            "composed candidate relocation availability changed"
        )
    dynamic_base = bool(
        int(pe.OPTIONAL_HEADER.DllCharacteristics)
        & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    )
    if dynamic_base != plan.dynamic_base:
        raise StageBPECompositionError(
            "composed candidate dynamic-base policy changed"
        )
    expected_directories = list(plan.original_directories)
    expected_directories[_DIRECTORY_BASE_RELOCATION] = plan.relocation_directory
    if _directories(pe, context="composed candidate") != tuple(expected_directories):
        raise StageBPECompositionError(
            "composed candidate changed a non-relocation data directory"
        )
    for source, output in zip(
        plan.contract_original_sections, plan.original_sections
    ):
        if (
            source.index,
            source.name_bytes,
            source.virtual_size,
            source.rva,
            source.raw_size,
            source.characteristics,
        ) != (
            output.index,
            output.name_bytes,
            output.virtual_size,
            output.rva,
            output.raw_size,
            output.characteristics,
        ):
            raise StageBPECompositionError(
                f"composed original section {source.index} changed its runtime layout"
            )
        expected_pointer = (
            source.raw_pointer + plan.original_raw_pointer_shift
            if source.raw_size
            else 0
        )
        if output.raw_pointer != expected_pointer:
            raise StageBPECompositionError(
                f"composed original section {source.index} has a noncanonical raw shift"
            )
        if output.raw_size and image[output.raw_pointer : output.raw_end] != _original_section_bytes(
            plan, output
        ):
            raise StageBPECompositionError(
                f"composed original section {source.index} bytes changed"
            )
    for source, output in zip(plan.payload_sections, plan.output_payload_sections):
        expected = bytearray(
            plan.payload_bytes[source.raw_pointer : source.raw_end]
        )
        for relocation in plan.merged_relocations:
            if (
                relocation.source == "payload"
                and output.rva <= relocation.target_rva
                and relocation.target_rva + relocation.width
                <= output.rva + output.raw_size
            ):
                relative = relocation.target_rva - output.rva
                expected[relative : relative + relocation.width] = (
                    relocation.preferred_value.to_bytes(relocation.width, "little")
                )
        if image[output.raw_pointer : output.raw_end] != expected:
            raise StageBPECompositionError(
                f"composed payload section {source.index} bytes changed"
            )
    if plan.runtime_relocations:
        parsed_relocations = _parse_payload_relocation_directory(
            image,
            sections,
            plan.relocation_directory,
            image_base=plan.contract.identity.preferred_base,
        )
        if tuple(item.rva for item in parsed_relocations.relocations) != tuple(
            item.target_rva for item in plan.merged_relocations
        ):
            raise StageBPECompositionError(
                "composed candidate relocation targets differ from the merge plan"
            )
    pe.close()


def _section_manifest_row(section: _Section) -> dict[str, Any]:
    return {
        "index": section.index,
        "name": section.name,
        "rva": section.rva,
        "virtual_size": section.virtual_size,
        "mapped_size": section.mapped_size,
        "raw_size": section.raw_size,
        "raw_pointer": section.raw_pointer,
        "characteristics": section.characteristics,
        "executable": section.executable,
    }


def _composition_manifest(
    plan: PECompositionPlan, *, candidate: bytes, checksum: int
) -> dict[str, Any]:
    contract_payload = plan.contract.to_payload()
    anchor_payload = plan.anchor_manifest.to_payload()
    relocation_inventory_payload = plan.relocation_inventory.to_payload()
    recovered_payload = (
        None
        if plan.recovered_executable_data is None
        else plan.recovered_executable_data.to_payload()
    )
    core: dict[str, Any] = {
        "format": PE_COMPOSITION_MANIFEST_FORMAT,
        "status": "composed",
        "acceptance_authority": "none",
        "acceptance": (
            "structural composition only; candidate static assurance and "
            "candidate-only behavior suites remain required"
        ),
        "inputs": {
            "load_image_contract": {
                "format": plan.contract.format,
                "artifact_sha256": sha256_bytes(_canonical_bytes(contract_payload)),
                "contract_sha256": plan.contract.hashes.contract_sha256,
                "bound_original_pe_sha256": plan.contract.identity.pe_sha256,
            },
            "payload_pe": {"sha256": sha256_bytes(plan.payload_bytes)},
            "payload_relocation_inventory": {
                "format": plan.relocation_inventory.format,
                "sha256": sha256_bytes(
                    _canonical_bytes(relocation_inventory_payload)
                ),
                "complete": True,
            },
            "executable_anchor_manifest": {
                "format": plan.anchor_manifest.format,
                "sha256": sha256_bytes(_canonical_bytes(anchor_payload)),
            },
            "recovered_executable_data": (
                None
                if recovered_payload is None
                else {
                    "format": recovered_payload["format"],
                    "sha256": sha256_bytes(_canonical_bytes(recovered_payload)),
                    "contract_sha256": recovered_payload["hashes"][
                        "contract_sha256"
                    ],
                    "ranges": len(plan.recovered_executable_data.ranges),
                    "bytes": sum(
                        item.size for item in plan.recovered_executable_data.ranges
                    ),
                }
            ),
        },
        "policy": {
            "executable_default_trap_byte_hex": bytes([_TRAP_BYTE]).hex(),
            "executable_raw_padding_byte_hex": bytes([_PADDING_BYTE]).hex(),
            "payload_layout": "append-raw-preserve-linked-rva",
            "fixed_base": not plan.dynamic_base,
            "dynamic_base": plan.dynamic_base,
            "runtime_relocations": plan.runtime_relocations,
            "relocation_merge": (
                "canonical-pe32-highlow"
                if plan.runtime_relocations
                else "preferred-address-materialization-only"
            ),
            "header_growth": "file-aligned-shift-original-raw-data",
            "coff_symbol_table": "stripped-not-present-in-load-image-contract",
            "non_relocation_data_directories_preserved": True,
        },
        "header_layout": {
            "section_table_offset": plan.section_table_offset,
            "original_size_of_headers": plan.original_size_of_headers,
            "new_size_of_headers": plan.new_size_of_headers,
            "original_raw_pointer_shift": plan.original_raw_pointer_shift,
            "coff_symbol_table_stripped": plan.coff_symbol_table_stripped,
            "file_offset_rewrites": [
                item.to_payload() for item in plan.file_offset_rewrites
            ],
        },
        "candidate": {
            "path": CANDIDATE_FILENAME,
            "sha256": sha256_bytes(candidate),
            "file_size": len(candidate),
            "image_base": plan.contract.identity.preferred_base,
            "entry_rva": plan.anchor_manifest.entry_anchor_rva,
            "size_of_image": plan.new_size_of_image,
            "checksum": checksum,
            "section_count": len(plan.original_sections)
            + len(plan.output_payload_sections)
            + (plan.relocation_section is not None),
            "base_relocation_directory": {
                "rva": plan.relocation_directory[0],
                "size": plan.relocation_directory[1],
            },
        },
        "anchors": {
            "entry_rva": plan.anchor_manifest.entry_anchor_rva,
            "tls_callback_rvas": list(plan.anchor_manifest.tls_callback_anchor_rvas),
            "callback_rvas": list(plan.anchor_manifest.callback_anchor_rvas),
            "stubs": [
                {
                    **anchor.to_payload(),
                    "size": len(anchor.bytes),
                    "bytes_sha256": sha256_bytes(anchor.bytes),
                }
                for anchor in plan.anchor_manifest.anchors
            ],
        },
        "executable_byte_classification": [
            item.to_payload() for item in plan.classifications
        ],
        "sections": {
            "original": [
                {
                    **_section_manifest_row(output),
                    "contract_raw_pointer": source.raw_pointer,
                }
                for source, output in zip(
                    plan.contract_original_sections, plan.original_sections
                )
            ],
            "payload": [
                _section_manifest_row(item) for item in plan.output_payload_sections
            ],
            "relocation": (
                None
                if plan.relocation_section is None
                else _section_manifest_row(plan.relocation_section)
            ),
        },
        "data_directories": [
            {
                "index": index,
                "name": _DIRECTORY_NAMES[index],
                "rva": (
                    plan.relocation_directory[0]
                    if index == _DIRECTORY_BASE_RELOCATION
                    else rva
                ),
                "size": (
                    plan.relocation_directory[1]
                    if index == _DIRECTORY_BASE_RELOCATION
                    else size
                ),
                "source": "merged" if index == _DIRECTORY_BASE_RELOCATION else "original",
            }
            for index, (rva, size) in enumerate(plan.original_directories)
        ],
        "merged_relocations": [
            item.to_payload() for item in plan.merged_relocations
        ],
    }
    return {
        **core,
        "hashes": {
            "algorithm": "sha256",
            "manifest_core_sha256": sha256_bytes(_canonical_bytes(core)),
        },
    }


def compose_stage_b_pe(
    *,
    load_image_contract: Path | str | Mapping[str, Any] | StageALoadImageContract,
    payload_pe: Path | str | bytes | bytearray,
    anchor_manifest: Path | str | Mapping[str, Any] | ExecutableAnchorManifest,
    payload_relocation_inventory: (
        Path | str | Mapping[str, Any] | PayloadRelocationInventory | None
    ) = None,
    recovered_executable_data: (
        Path
        | str
        | Mapping[str, Any]
        | RecoveredExecutableDataContract
        | None
    ) = None,
    out_dir: Path | str,
) -> dict[str, Any]:
    """Compose and emit ``candidate.exe`` and a non-authoritative manifest."""

    plan = plan_stage_b_pe_composition(
        load_image_contract=load_image_contract,
        payload_pe=payload_pe,
        anchor_manifest=anchor_manifest,
        payload_relocation_inventory=payload_relocation_inventory,
        recovered_executable_data=recovered_executable_data,
    )
    original_raw_end = max(
        plan.new_size_of_headers,
        *(section.raw_end for section in plan.original_sections if section.raw_size),
    )
    candidate_size = max(
        original_raw_end,
        *(section.raw_end for section in plan.output_payload_sections if section.raw_size),
        *(
            ()
            if plan.relocation_section is None
            else (plan.relocation_section.raw_end,)
        ),
    )
    image = bytearray(candidate_size)
    image[: plan.original_size_of_headers] = plan.contract.runtime_headers.data
    _fill_original_sections(image, plan)
    _append_payload_sections(image, plan)
    _write_relocation_section(image, plan)
    _write_section_headers(image, plan)
    checksum = _update_headers(image, plan)
    candidate = bytes(image)
    _validate_candidate(candidate, plan, checksum)
    manifest = _composition_manifest(plan, candidate=candidate, checksum=checksum)

    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    candidate_path = output / CANDIDATE_FILENAME
    manifest_path = output / COMPOSITION_MANIFEST_FILENAME
    candidate_temporary = output / f".{CANDIDATE_FILENAME}.tmp"
    manifest_temporary = output / f".{COMPOSITION_MANIFEST_FILENAME}.tmp"
    try:
        candidate_temporary.write_bytes(candidate)
        manifest_temporary.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(candidate_temporary, candidate_path)
        os.replace(manifest_temporary, manifest_path)
    except OSError as exc:
        for temporary in (candidate_temporary, manifest_temporary):
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        raise StageBPECompositionError(f"cannot emit PE composition: {exc}") from exc
    return manifest


__all__ = [
    "CANDIDATE_FILENAME",
    "COMPOSITION_MANIFEST_FILENAME",
    "EXECUTABLE_ANCHOR_MANIFEST_FORMAT",
    "PAYLOAD_RELOCATION_INVENTORY_FORMAT",
    "PE_COMPOSITION_MANIFEST_FORMAT",
    "ByteClassification",
    "ExecutableAnchor",
    "ExecutableAnchorManifest",
    "PECompositionPlan",
    "PayloadRelocation",
    "PayloadRelocationInventory",
    "StageBPECompositionError",
    "compose_stage_b_pe",
    "plan_stage_b_pe_composition",
]
