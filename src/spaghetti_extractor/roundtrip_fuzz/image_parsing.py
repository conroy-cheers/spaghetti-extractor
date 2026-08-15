"""Round-trip image parsing."""


from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..errors import ToolkitInputError
from ..util import sha256_bytes, sha256_file, write_json


from .image_model import (
    BaseRelocation,
    CompletenessInventory,
    ContractHashes,
    ImportDescriptor,
    ImportIATCell,
    InitializedRange,
    RelocationBlock,
    RuntimePEHeaders,
    SectionInitialization,
    TLSCallback,
    TLSInitialization,
    ZeroFillRange,
    _COVERAGE_KINDS,
    _DIRECTORY_BASE_RELOCATION,
    _DIRECTORY_DELAY_IMPORT,
    _DIRECTORY_IAT,
    _DIRECTORY_IMPORT,
    _DIRECTORY_NAMES,
    _DIRECTORY_TLS,
    _HASH_ALGORITHM,
    _IMAGE_SCN_MEM_EXECUTE,
    _payload_sha256,
)

@dataclass(frozen=True)
class _SectionHeader:
    index: int
    name: str
    rva: int
    virtual_size: int
    mapped_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)


@dataclass(frozen=True)
class _PEHeaders:
    machine: str
    bitness: int
    pointer_width: int
    preferred_base: int
    image_size: int
    entry_rva: int
    size_of_headers: int
    section_alignment: int
    file_alignment: int
    directories: tuple[tuple[int, int], ...]
    sections: tuple[_SectionHeader, ...]


class _ImageReader:
    def __init__(self, data: bytes, headers: _PEHeaders):
        self.data = data
        self.headers = headers

    def read(self, rva: int, size: int, *, context: str) -> bytes:
        if size < 0 or rva < 0 or rva + size > self.headers.image_size:
            raise ToolkitInputError(f"{context} is outside SizeOfImage")
        if size == 0:
            return b""
        if rva < self.headers.size_of_headers and rva + size <= self.headers.size_of_headers:
            if rva + size > len(self.data):
                raise ToolkitInputError(f"{context} is not backed by exact header bytes")
            return self.data[rva : rva + size]
        matches = [
            section
            for section in self.headers.sections
            if section.rva <= rva and rva + size <= section.rva + section.mapped_size
        ]
        if len(matches) != 1:
            raise ToolkitInputError(f"{context} is not in exactly one mapped section")
        section = matches[0]
        offset = rva - section.rva
        raw_count = max(0, min(size, section.raw_size - offset))
        result = bytearray()
        if raw_count:
            file_offset = section.raw_pointer + offset
            if file_offset + raw_count > len(self.data):
                raise ToolkitInputError(f"{context} is not backed by exact file bytes")
            result.extend(self.data[file_offset : file_offset + raw_count])
        result.extend(bytes(size - raw_count))
        return bytes(result)

    def c_string(self, rva: int, *, context: str) -> str:
        encoded = bytearray()
        for offset in range(4096):
            byte = self.read(rva + offset, 1, context=context)[0]
            if byte == 0:
                if not encoded:
                    raise ToolkitInputError(f"{context} is empty")
                try:
                    return encoded.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ToolkitInputError(f"{context} is not ASCII") from exc
            encoded.append(byte)
        raise ToolkitInputError(f"{context} is not NUL terminated within 4096 bytes")


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _parse_pe_headers(data: bytes, *, exact_file_size: int) -> _PEHeaders:
    if exact_file_size < len(data) or len(data) < 0x40 or data[:2] != b"MZ":
        raise ToolkitInputError("original is not a bounded MZ image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ToolkitInputError("PE signature or COFF header is outside the header bytes")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ToolkitInputError("original does not contain a PE signature")
    coff_offset = pe_offset + 4
    machine_value, section_count = struct.unpack_from("<HH", data, coff_offset)
    optional_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if section_count == 0 or section_count > 96:
        raise ToolkitInputError("PE section count is outside the supported bound")
    if optional_end > len(data) or optional_size < 2:
        raise ToolkitInputError("PE optional header is truncated")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if machine_value == 0x014C and magic == 0x10B:
        machine, bitness, pointer_width = "i386", 32, 4
        required_optional_size = 96
        directory_count_offset = 92
        directory_offset = 96
        preferred_base = struct.unpack_from("<I", data, optional_offset + 28)[0]
    elif machine_value == 0x8664 and magic == 0x20B:
        machine, bitness, pointer_width = "x86_64", 64, 8
        required_optional_size = 112
        directory_count_offset = 108
        directory_offset = 112
        preferred_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
    else:
        raise ToolkitInputError(
            "load-image contracts support only x86 PE32 and x86_64 PE32+"
        )
    if optional_size < required_optional_size:
        raise ToolkitInputError("PE optional header is too small for its declared bitness")
    entry_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
    section_alignment = struct.unpack_from("<I", data, optional_offset + 32)[0]
    file_alignment = struct.unpack_from("<I", data, optional_offset + 36)[0]
    image_size = struct.unpack_from("<I", data, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    if not _is_power_of_two(section_alignment) or not _is_power_of_two(file_alignment):
        raise ToolkitInputError("PE section and file alignments must be powers of two")
    if section_alignment < file_alignment:
        raise ToolkitInputError("PE SectionAlignment is smaller than FileAlignment")
    if size_of_headers == 0 or size_of_headers > exact_file_size:
        raise ToolkitInputError("PE SizeOfHeaders is outside the exact file")
    if size_of_headers > len(data):
        raise ToolkitInputError("required runtime PE header bytes are unavailable")
    if image_size == 0 or image_size % section_alignment:
        raise ToolkitInputError("PE SizeOfImage is zero or misaligned")
    address_limit = 1 << bitness
    if preferred_base + image_size > address_limit:
        raise ToolkitInputError("preferred PE image exceeds its address space")

    directory_count = struct.unpack_from(
        "<I", data, optional_offset + directory_count_offset
    )[0]
    directory_capacity = (optional_size - directory_offset) // 8
    if directory_count > min(directory_capacity, 16):
        raise ToolkitInputError("PE data-directory count is outside the supported bound")
    directories: list[tuple[int, int]] = []
    for index in range(16):
        if index < directory_count:
            rva, size = struct.unpack_from(
                "<II", data, optional_offset + directory_offset + index * 8
            )
            if (rva == 0) != (size == 0):
                raise ToolkitInputError(
                    f"PE {_DIRECTORY_NAMES[index]} directory has incoherent presence"
                )
            directories.append((rva, size))
        else:
            if index < directory_capacity:
                undeclared_rva, undeclared_size = struct.unpack_from(
                    "<II", data, optional_offset + directory_offset + index * 8
                )
                if undeclared_rva != 0 or undeclared_size != 0:
                    raise ToolkitInputError(
                        f"PE {_DIRECTORY_NAMES[index]} directory is present but undeclared"
                    )
            directories.append((0, 0))

    section_table_offset = optional_end
    section_table_end = section_table_offset + section_count * 40
    if section_table_end > size_of_headers or section_table_end > len(data):
        raise ToolkitInputError("PE section table is outside SizeOfHeaders")
    minimum_headers = _align_up(section_table_end, file_alignment)
    if size_of_headers < minimum_headers or size_of_headers % file_alignment:
        raise ToolkitInputError("PE SizeOfHeaders does not cover its aligned section table")

    sections: list[_SectionHeader] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        (
            encoded_name,
            virtual_size,
            rva,
            raw_size,
            raw_pointer,
            _relocation_pointer,
            _line_pointer,
            _relocation_count,
            _line_count,
            characteristics,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, offset)
        mapped_size = max(virtual_size, raw_size)
        if mapped_size == 0:
            raise ToolkitInputError(f"PE section {index} has no mapped extent")
        if rva % section_alignment or rva < size_of_headers:
            raise ToolkitInputError(f"PE section {index} has an invalid RVA")
        if rva + mapped_size > image_size:
            raise ToolkitInputError(f"PE section {index} exceeds SizeOfImage")
        if raw_size:
            if raw_pointer < size_of_headers or raw_pointer % file_alignment:
                raise ToolkitInputError(f"PE section {index} has an invalid raw pointer")
            if raw_size % file_alignment or raw_pointer + raw_size > exact_file_size:
                raise ToolkitInputError(f"PE section {index} raw bytes exceed the file")
        elif raw_pointer != 0:
            raise ToolkitInputError(f"PE section {index} has a pointer without raw bytes")
        sections.append(_SectionHeader(
            index=index,
            name=encoded_name.rstrip(b"\0").decode("latin-1"),
            rva=rva,
            virtual_size=virtual_size,
            mapped_size=mapped_size,
            raw_pointer=raw_pointer,
            raw_size=raw_size,
            characteristics=characteristics,
        ))
    _require_disjoint(
        [(item.rva, item.rva + item.mapped_size, item.index) for item in sections],
        "mapped section",
    )
    _require_disjoint(
        [
            (item.raw_pointer, item.raw_pointer + item.raw_size, item.index)
            for item in sections
            if item.raw_size
        ],
        "raw section",
    )
    highest = max(size_of_headers, *(item.rva + item.mapped_size for item in sections))
    if image_size != _align_up(highest, section_alignment):
        raise ToolkitInputError("PE SizeOfImage does not exactly cover its sections")
    if entry_rva:
        matches = [
            item
            for item in sections
            if item.executable and item.rva <= entry_rva < item.rva + item.mapped_size
        ]
        if len(matches) != 1:
            raise ToolkitInputError("PE entry RVA is not in exactly one executable section")
    return _PEHeaders(
        machine=machine,
        bitness=bitness,
        pointer_width=pointer_width,
        preferred_base=preferred_base,
        image_size=image_size,
        entry_rva=entry_rva,
        size_of_headers=size_of_headers,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        directories=tuple(directories),
        sections=tuple(sections),
    )


def _require_disjoint(ranges: Sequence[tuple[int, int, int]], label: str) -> None:
    ordered = sorted(ranges)
    for (_, previous_end, previous_index), (start, _end, index) in zip(
        ordered, ordered[1:]
    ):
        if start < previous_end:
            raise ToolkitInputError(
                f"PE {label}s {previous_index} and {index} overlap"
            )


def _directory_bytes(
    reader: _ImageReader, index: int, *, required_minimum: int = 1
) -> tuple[int, bytes]:
    rva, size = reader.headers.directories[index]
    if rva == 0:
        return 0, b""
    if size < required_minimum:
        raise ToolkitInputError(
            f"PE {_DIRECTORY_NAMES[index]} directory is smaller than its header"
        )
    return rva, reader.read(
        rva, size, context=f"PE {_DIRECTORY_NAMES[index]} directory"
    )


def _extract_sections(data: bytes, headers: _PEHeaders) -> tuple[SectionInitialization, ...]:
    result: list[SectionInitialization] = []
    for section in headers.sections:
        initialized: tuple[InitializedRange, ...] = ()
        zero_fill: tuple[ZeroFillRange, ...] = ()
        if not section.executable:
            if section.raw_size:
                raw = data[
                    section.raw_pointer : section.raw_pointer + section.raw_size
                ]
                if len(raw) != section.raw_size:
                    raise ToolkitInputError(
                        f"PE section {section.index} initialized bytes are truncated"
                    )
                initialized = (
                    InitializedRange(
                        rva=section.rva,
                        data=raw,
                        data_sha256=sha256_bytes(raw),
                    ),
                )
            if section.mapped_size > section.raw_size:
                zero_fill = (
                    ZeroFillRange(
                        rva=section.rva + section.raw_size,
                        size=section.mapped_size - section.raw_size,
                    ),
                )
        result.append(SectionInitialization(
            index=section.index,
            name=section.name,
            rva=section.rva,
            virtual_size=section.virtual_size,
            mapped_size=section.mapped_size,
            raw_size=section.raw_size,
            characteristics=section.characteristics,
            executable=section.executable,
            initialized=initialized,
            zero_fill=zero_fill,
        ))
    return tuple(result)


def _extract_imports(reader: _ImageReader) -> tuple[ImportDescriptor, ...]:
    if reader.headers.directories[_DIRECTORY_DELAY_IMPORT] != (0, 0):
        raise ToolkitInputError(
            "delay-import IAT cells are unsupported by this load-image contract"
        )
    directory_rva, directory = _directory_bytes(
        reader, _DIRECTORY_IMPORT, required_minimum=20
    )
    if not directory:
        if reader.headers.directories[_DIRECTORY_IAT] != (0, 0):
            raise ToolkitInputError("PE declares an IAT without a typed import directory")
        return ()
    descriptors: list[ImportDescriptor] = []
    terminated_at: int | None = None
    seen_iat_rvas: set[int] = set()
    pointer_width = reader.headers.pointer_width
    pointer_format = "<I" if pointer_width == 4 else "<Q"
    ordinal_mask = 1 << (reader.headers.bitness - 1)
    for descriptor_offset in range(0, len(directory) - 19, 20):
        row = struct.unpack_from("<IIIII", directory, descriptor_offset)
        if row == (0, 0, 0, 0, 0):
            terminated_at = descriptor_offset + 20
            break
        lookup_rva, _timestamp, _forwarder_chain, name_rva, iat_rva = row
        if name_rva == 0 or iat_rva == 0:
            raise ToolkitInputError("PE import descriptor omits its DLL name or IAT")
        if lookup_rva == 0:
            lookup_rva = iat_rva
        dll = reader.c_string(name_rva, context="PE import DLL name").lower()
        cells: list[ImportIATCell] = []
        maximum_cells = reader.headers.image_size // pointer_width
        for index in range(maximum_cells):
            lookup_cell_rva = lookup_rva + index * pointer_width
            iat_cell_rva = iat_rva + index * pointer_width
            lookup_value = struct.unpack(
                pointer_format,
                reader.read(
                    lookup_cell_rva,
                    pointer_width,
                    context="PE import lookup cell",
                ),
            )[0]
            initial_value = struct.unpack(
                pointer_format,
                reader.read(
                    iat_cell_rva, pointer_width, context="PE IAT cell"
                ),
            )[0]
            if lookup_value == 0:
                if initial_value != 0:
                    raise ToolkitInputError("PE IAT is not terminated with its lookup table")
                break
            if iat_cell_rva in seen_iat_rvas:
                raise ToolkitInputError("PE import descriptors contain duplicate IAT cells")
            seen_iat_rvas.add(iat_cell_rva)
            if lookup_value & ordinal_mask:
                ordinal = lookup_value & 0xFFFF
                if lookup_value & ~(ordinal_mask | 0xFFFF):
                    raise ToolkitInputError("PE ordinal import contains reserved bits")
                symbol = None
                hint = None
            else:
                if lookup_value > 0xFFFFFFFF:
                    raise ToolkitInputError("PE import-by-name RVA exceeds 32 bits")
                hint_name_rva = int(lookup_value)
                hint = struct.unpack(
                    "<H",
                    reader.read(
                        hint_name_rva, 2, context="PE import-by-name hint"
                    ),
                )[0]
                symbol = reader.c_string(
                    hint_name_rva + 2, context="PE import symbol"
                )
                ordinal = None
            cells.append(ImportIATCell(
                index=index,
                lookup_rva=lookup_cell_rva,
                iat_rva=iat_cell_rva,
                symbol=symbol,
                ordinal=ordinal,
                hint=hint,
                pointer_width=pointer_width,
                initial_value=initial_value,
            ))
        else:
            raise ToolkitInputError("PE import table is not null terminated")
        if not cells:
            raise ToolkitInputError("PE import descriptor has no IAT cells")
        descriptors.append(ImportDescriptor(
            index=len(descriptors),
            dll=dll,
            lookup_table_rva=lookup_rva,
            iat_rva=iat_rva,
            cells=tuple(cells),
        ))
    if terminated_at is None:
        raise ToolkitInputError("PE import descriptor table is not null terminated")
    # The import data-directory range is not restricted to IMAGE_IMPORT_DESCRIPTOR
    # rows.  GNU linkers commonly include the lookup tables and import names in
    # the same range, after the null descriptor.  The descriptor terminator is
    # therefore the end of the descriptor inventory, not an assertion that the
    # remainder of the declared directory is zero-filled.
    iat_directory_rva, iat_directory_size = reader.headers.directories[_DIRECTORY_IAT]
    if iat_directory_rva:
        iat_end = iat_directory_rva + iat_directory_size
        if any(
            not iat_directory_rva <= cell.iat_rva
            or cell.iat_rva + pointer_width > iat_end
            for descriptor in descriptors
            for cell in descriptor.cells
        ):
            raise ToolkitInputError("typed IAT cell is outside the declared IAT directory")
    return tuple(descriptors)


def _extract_relocations(reader: _ImageReader) -> tuple[RelocationBlock, ...]:
    _directory_rva, directory = _directory_bytes(
        reader, _DIRECTORY_BASE_RELOCATION, required_minimum=8
    )
    if not directory:
        return ()
    blocks: list[RelocationBlock] = []
    cursor = 0
    seen_targets: set[tuple[int, int]] = set()
    while cursor < len(directory):
        if len(directory) - cursor < 8:
            raise ToolkitInputError("PE base-relocation directory has a partial block")
        page_rva, block_size = struct.unpack_from("<II", directory, cursor)
        if page_rva % 0x1000:
            raise ToolkitInputError("PE base-relocation block page is not 4 KiB aligned")
        if block_size < 8 or block_size % 2 or cursor + block_size > len(directory):
            raise ToolkitInputError("PE base-relocation block has an invalid size")
        slot_count = (block_size - 8) // 2
        raw_slots = struct.unpack_from(
            "<" + "H" * slot_count, directory, cursor + 8
        )
        relocations: list[BaseRelocation] = []
        slot_index = 0
        while slot_index < slot_count:
            raw = raw_slots[slot_index]
            type_value = raw >> 12
            offset = raw & 0xFFF
            if type_value == 0:
                relocations.append(BaseRelocation(
                    slot_index=slot_index,
                    consumed_slots=1,
                    type=0,
                    kind="absolute_padding",
                    target_rva=None,
                    width=0,
                    preferred_value=None,
                    adjustment=None,
                ))
                slot_index += 1
                continue
            if reader.headers.bitness == 32:
                kinds = {
                    1: ("high", 2),
                    2: ("low", 2),
                    3: ("highlow", 4),
                    4: ("highadj", 2),
                }
            else:
                kinds = {10: ("dir64", 8)}
            if type_value not in kinds:
                raise ToolkitInputError(
                    f"unsupported PE base-relocation type {type_value} for "
                    f"{reader.headers.bitness}-bit image"
                )
            kind, width = kinds[type_value]
            adjustment: int | None = None
            consumed_slots = 1
            if type_value == 4:
                if slot_index + 1 >= slot_count:
                    raise ToolkitInputError("PE HIGHADJ relocation omits its adjustment")
                adjustment = struct.unpack("<h", struct.pack("<H", raw_slots[slot_index + 1]))[0]
                consumed_slots = 2
            target_rva = page_rva + offset
            preferred = int.from_bytes(
                reader.read(
                    target_rva, width, context="PE base-relocation target"
                ),
                "little",
            )
            target_key = (target_rva, width)
            if target_key in seen_targets:
                raise ToolkitInputError("PE base-relocation target is duplicated")
            seen_targets.add(target_key)
            relocations.append(BaseRelocation(
                slot_index=slot_index,
                consumed_slots=consumed_slots,
                type=type_value,
                kind=kind,
                target_rva=target_rva,
                width=width,
                preferred_value=preferred,
                adjustment=adjustment,
            ))
            slot_index += consumed_slots
        blocks.append(RelocationBlock(
            index=len(blocks),
            page_rva=page_rva,
            size=block_size,
            slot_count=slot_count,
            relocations=tuple(relocations),
        ))
        cursor += block_size
    return tuple(blocks)


def _va_to_rva(
    value: int, headers: _PEHeaders, *, context: str, allow_end: bool = False
) -> int:
    maximum = headers.preferred_base + headers.image_size
    if value < headers.preferred_base or value > maximum or (
        value == maximum and not allow_end
    ):
        raise ToolkitInputError(f"{context} VA is outside the preferred image")
    return value - headers.preferred_base


def _section_for_span(
    headers: _PEHeaders, rva: int, size: int
) -> _SectionHeader | None:
    matches = [
        section
        for section in headers.sections
        if section.rva <= rva and rva + size <= section.rva + section.mapped_size
    ]
    return matches[0] if len(matches) == 1 else None


def _extract_tls(reader: _ImageReader) -> TLSInitialization | None:
    directory_rva, directory = _directory_bytes(
        reader,
        _DIRECTORY_TLS,
        required_minimum=24 if reader.headers.bitness == 32 else 40,
    )
    if not directory:
        return None
    if reader.headers.bitness == 32:
        fields = struct.unpack_from("<IIIIII", directory)
    else:
        fields = struct.unpack_from("<QQQQII", directory)
    start_va, end_va, index_va, callbacks_va, zero_fill_size, characteristics = fields
    if (start_va == 0) != (end_va == 0):
        raise ToolkitInputError("PE TLS template has incoherent start/end VAs")
    template_rva: int | None = None
    template_data = b""
    if start_va:
        template_rva = _va_to_rva(
            start_va, reader.headers, context="PE TLS template start"
        )
        template_end_rva = _va_to_rva(
            end_va, reader.headers, context="PE TLS template end", allow_end=True
        )
        if template_end_rva < template_rva:
            raise ToolkitInputError("PE TLS template end precedes its start")
        template_data = reader.read(
            template_rva,
            template_end_rva - template_rva,
            context="PE TLS template",
        )
        template_section = _section_for_span(
            reader.headers, template_rva, len(template_data)
        )
        if template_data and (template_section is None or template_section.executable):
            raise ToolkitInputError("PE TLS template is not in a non-executable section")
    index_rva = (
        None
        if index_va == 0
        else _va_to_rva(index_va, reader.headers, context="PE TLS index")
    )
    if index_rva is not None:
        reader.read(
            index_rva, reader.headers.pointer_width, context="PE TLS index cell"
        )
    callback_array_rva = (
        None
        if callbacks_va == 0
        else _va_to_rva(
            callbacks_va, reader.headers, context="PE TLS callback array"
        )
    )
    callbacks: list[TLSCallback] = []
    if callback_array_rva is not None:
        width = reader.headers.pointer_width
        maximum = (reader.headers.image_size - callback_array_rva) // width
        for order in range(maximum):
            callback_va = int.from_bytes(
                reader.read(
                    callback_array_rva + order * width,
                    width,
                    context="PE TLS callback array",
                ),
                "little",
            )
            if callback_va == 0:
                break
            callback_rva = _va_to_rva(
                callback_va, reader.headers, context="PE TLS callback"
            )
            section = _section_for_span(reader.headers, callback_rva, 1)
            if section is None or not section.executable:
                raise ToolkitInputError("PE TLS callback is not executable")
            callbacks.append(TLSCallback(order=order, rva=callback_rva))
        else:
            raise ToolkitInputError("PE TLS callback array is not null terminated")
    return TLSInitialization(
        directory_rva=directory_rva,
        directory_size=len(directory),
        template_rva=template_rva,
        template_data=template_data,
        template_sha256=sha256_bytes(template_data),
        zero_fill_size=zero_fill_size,
        index_rva=index_rva,
        callback_array_rva=callback_array_rva,
        callbacks=tuple(callbacks),
        characteristics=characteristics,
    )


def _make_completeness(
    runtime_headers: RuntimePEHeaders,
    sections: tuple[SectionInitialization, ...],
    imports: tuple[ImportDescriptor, ...],
    relocations: tuple[RelocationBlock, ...],
    tls: TLSInitialization | None,
) -> CompletenessInventory:
    initialized = [item for section in sections for item in section.initialized]
    zero_fill = [item for section in sections for item in section.zero_fill]
    cells = [cell for descriptor in imports for cell in descriptor.cells]
    relocation_records = [
        item for block in relocations for item in block.relocations if item.type != 0
    ]
    return CompletenessInventory(
        complete=True,
        coverage=_COVERAGE_KINDS,
        section_count=len(sections),
        non_executable_section_indices=tuple(
            section.index for section in sections if not section.executable
        ),
        excluded_executable_section_indices=tuple(
            section.index for section in sections if section.executable
        ),
        runtime_header_bytes=len(runtime_headers.data),
        initialized_range_count=len(initialized),
        initialized_byte_count=sum(len(item.data) for item in initialized),
        zero_fill_range_count=len(zero_fill),
        zero_fill_byte_count=sum(item.size for item in zero_fill),
        import_descriptor_count=len(imports),
        import_iat_cell_count=len(cells),
        relocation_block_count=len(relocations),
        relocation_slot_count=sum(block.slot_count for block in relocations),
        base_relocation_count=len(relocation_records),
        tls_present=tls is not None,
        tls_callback_count=0 if tls is None else len(tls.callbacks),
    )


def _make_hashes(
    *,
    core_payload: Mapping[str, Any],
    runtime_headers: RuntimePEHeaders,
    sections: tuple[SectionInitialization, ...],
    imports: tuple[ImportDescriptor, ...],
    relocations: tuple[RelocationBlock, ...],
    tls: TLSInitialization | None,
    completeness: CompletenessInventory,
) -> ContractHashes:
    return ContractHashes(
        algorithm=_HASH_ALGORITHM,
        runtime_headers_sha256=sha256_bytes(runtime_headers.data),
        sections_sha256=_payload_sha256(
            [section.to_payload() for section in sections]
        ),
        imports_sha256=_payload_sha256([item.to_payload() for item in imports]),
        relocations_sha256=_payload_sha256(
            [item.to_payload() for item in relocations]
        ),
        tls_sha256=_payload_sha256(None if tls is None else tls.to_payload()),
        completeness_sha256=_payload_sha256(completeness.to_payload()),
        contract_sha256=_payload_sha256(core_payload),
    )
