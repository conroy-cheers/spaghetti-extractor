from __future__ import annotations
import re
import struct
from pathlib import Path
from typing import Any

import pefile

from .pe import (
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    mapped_section_size,
)
from ..util import sha256_bytes
from ..errors import ToolkitInputError
from .loader import inspect_pe32_loader_image
from .model import (
    IMAGE_FILE_DLL,
    BlockSide,
    PEExport,
    PEImport,
    PESection,
    ParsedPEImage,
)


class _ExportParseError(ValueError):
    pass




def parse_pe_image(path: Path) -> ParsedPEImage:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ToolkitInputError(f"cannot read PE file {path}: {exc}") from exc
    loader_diagnostics, raw_sections = inspect_pe32_loader_image(data)
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # pefile raises several non-public exception types.
        raise ToolkitInputError(f"{path} is not a parseable PE file: {exc}") from exc

    machine = pe.FILE_HEADER.Machine
    magic = pe.OPTIONAL_HEADER.Magic
    if machine == 0x014C and magic == 0x10B:
        machine_name = "i386"
        bitness = 32
    elif machine == 0x8664 and magic == 0x20B:
        machine_name = "x86_64"
        bitness = 64
    else:
        machine_name = f"0x{machine:04x}"
        magic_name = f"0x{magic:04x}"
        raise ToolkitInputError(f"{path} is out of model: expected x86 PE32 or x86_64 PE32+, got machine={machine_name} magic={magic_name}")

    if raw_sections is None:
        diagnostic_codes = ", ".join(
            diagnostic.code for diagnostic in loader_diagnostics.hard_diagnostics
        )
        raise ToolkitInputError(
            f"{path} has no bounded on-disk PE section table"
            + (f" ({diagnostic_codes})" if diagnostic_codes else "")
        )

    imports = _imports(pe)
    sections = raw_sections
    coff_characteristics, export_directory_rva, export_directory_size = (
        _raw_pe_entry_surface_header(data, path=path, expected_magic=magic)
    )
    exports, export_parse_error = _parse_exports(
        data,
        directory_rva=export_directory_rva,
        directory_size=export_directory_size,
        sections=sections,
        size_of_headers=int(pe.OPTIONAL_HEADER.SizeOfHeaders),
    )
    data_directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    tls_directory = data_directories[9] if len(data_directories) > 9 else None
    (
        tls_callback_rvas,
        tls_callback_array_rva,
        tls_callback_parse_error,
    ) = _parse_tls_callback_rvas(
        pe, tls_directory
    )
    tls_callback_array_size = (
        (len(tls_callback_rvas) + 1) * (4 if bitness == 32 else 8)
        if tls_callback_rvas is not None and tls_callback_array_rva is not None
        else 0 if tls_callback_rvas is not None else None
    )
    tls_callback_array_immutable = (
        _tls_callback_array_words_immutable(
            sections,
            size_of_headers=int(pe.OPTIONAL_HEADER.SizeOfHeaders),
            directory_pointer_rva=(
                int(tls_directory.VirtualAddress) + (12 if bitness == 32 else 24)
                if tls_callback_array_rva is not None and tls_directory is not None
                else None
            ),
            callback_array_rva=tls_callback_array_rva,
            callback_count=len(tls_callback_rvas),
            pointer_width=4 if bitness == 32 else 8,
        )
        if tls_callback_rvas is not None
        else None
    )
    return ParsedPEImage(
        path=path,
        sha256=sha256_bytes(data),
        size=len(data),
        machine=machine_name,
        bitness=bitness,
        coff_characteristics=coff_characteristics,
        is_dll=bool(coff_characteristics & IMAGE_FILE_DLL),
        image_base=int(pe.OPTIONAL_HEADER.ImageBase),
        entrypoint_rva=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        exports=exports,
        export_parse_error=export_parse_error,
        tls_directory_rva=(
            int(tls_directory.VirtualAddress) if tls_directory is not None else 0
        ),
        tls_directory_size=(
            int(tls_directory.Size) if tls_directory is not None else 0
        ),
        tls_callback_rvas=tls_callback_rvas,
        tls_callback_array_rva=tls_callback_array_rva,
        tls_callback_array_size=tls_callback_array_size,
        tls_callback_array_immutable=tls_callback_array_immutable,
        tls_callback_parse_error=tls_callback_parse_error,
        size_of_image=int(pe.OPTIONAL_HEADER.SizeOfImage),
        size_of_headers=int(pe.OPTIONAL_HEADER.SizeOfHeaders),
        subsystem=_subsystem_name(int(pe.OPTIONAL_HEADER.Subsystem)),
        loader_diagnostics=loader_diagnostics,
        sections=sections,
        imports=imports,
        pe=pe,
    )


def _raw_pe_entry_surface_header(
    data: bytes, *, path: Path, expected_magic: int
) -> tuple[int, int, int]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ToolkitInputError(f"{path} has a malformed DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    coff_offset = pe_offset + 4
    if pe_offset > len(data) - 24 or data[pe_offset:coff_offset] != b"PE\0\0":
        raise ToolkitInputError(f"{path} has a malformed PE signature or COFF header")

    optional_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    coff_characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(data) or optional_size < 2:
        raise ToolkitInputError(f"{path} has a truncated PE optional header")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic != expected_magic:
        raise ToolkitInputError(f"{path} has inconsistent PE optional-header magic")

    if magic == 0x10B:
        directory_count_offset = 92
        directory_table_offset = 96
    elif magic == 0x20B:
        directory_count_offset = 108
        directory_table_offset = 112
    else:
        raise ToolkitInputError(f"{path} has unsupported PE optional-header magic 0x{magic:04x}")
    if optional_size < directory_count_offset + 4:
        raise ToolkitInputError(f"{path} has a truncated PE data-directory count")
    directory_count = struct.unpack_from(
        "<I", data, optional_offset + directory_count_offset
    )[0]
    if directory_count == 0:
        return coff_characteristics, 0, 0
    if optional_size < directory_table_offset + 8:
        raise ToolkitInputError(f"{path} has a truncated PE export data-directory entry")
    directory_rva, directory_size = struct.unpack_from(
        "<II", data, optional_offset + directory_table_offset
    )
    return coff_characteristics, directory_rva, directory_size


def _parse_exports(
    data: bytes,
    *,
    directory_rva: int,
    directory_size: int,
    sections: tuple[PESection, ...],
    size_of_headers: int,
) -> tuple[tuple[PEExport, ...] | None, str | None]:
    if directory_rva == 0 and directory_size == 0:
        return (), None
    try:
        return (
            _parse_exports_strict(
                data,
                directory_rva=directory_rva,
                directory_size=directory_size,
                sections=sections,
                size_of_headers=size_of_headers,
            ),
            None,
        )
    except _ExportParseError as exc:
        return None, f"malformed PE export directory: {exc}"


def _parse_exports_strict(
    data: bytes,
    *,
    directory_rva: int,
    directory_size: int,
    sections: tuple[PESection, ...],
    size_of_headers: int,
) -> tuple[PEExport, ...]:
    if directory_rva == 0 or directory_size == 0:
        raise _ExportParseError("RVA and size must either both be zero or both be nonzero")
    if directory_size < 40:
        raise _ExportParseError("declared span is smaller than IMAGE_EXPORT_DIRECTORY")
    directory_end = directory_rva + directory_size
    if directory_end > 0x1_0000_0000:
        raise _ExportParseError("declared span overflows the 32-bit RVA space")
    _mapped_file_span(
        data,
        rva=directory_rva,
        size=directory_size,
        sections=sections,
        size_of_headers=size_of_headers,
        label="declared span",
    )
    directory = _export_directory_bytes(
        data,
        rva=directory_rva,
        size=40,
        directory_rva=directory_rva,
        directory_end=directory_end,
        sections=sections,
        size_of_headers=size_of_headers,
        label="IMAGE_EXPORT_DIRECTORY",
    )
    (
        _characteristics,
        _timestamp,
        _major_version,
        _minor_version,
        dll_name_rva,
        ordinal_base,
        function_count,
        name_count,
        eat_rva,
        name_pointer_rva,
        name_ordinal_rva,
    ) = struct.unpack("<IIHHIIIIIII", directory)

    if dll_name_rva == 0:
        raise _ExportParseError("DLL name RVA is zero")
    _export_directory_string(
        data,
        rva=dll_name_rva,
        directory_rva=directory_rva,
        directory_end=directory_end,
        sections=sections,
        size_of_headers=size_of_headers,
        label="DLL name",
    )
    if name_count > function_count:
        raise _ExportParseError("name count exceeds EAT entry count")
    if function_count == 0:
        if name_count != 0:
            raise _ExportParseError("names are present without EAT entries")
        return ()
    if eat_rva == 0:
        raise _ExportParseError("EAT RVA is zero for a nonempty export table")

    eat = _export_directory_bytes(
        data,
        rva=eat_rva,
        size=function_count * 4,
        directory_rva=directory_rva,
        directory_end=directory_end,
        sections=sections,
        size_of_headers=size_of_headers,
        label="export address table",
    )
    target_rvas = tuple(value[0] for value in struct.iter_unpack("<I", eat))

    names_by_index: dict[int, list[str]] = {}
    if name_count:
        if name_pointer_rva == 0 or name_ordinal_rva == 0:
            raise _ExportParseError("name table RVA is zero for named exports")
        name_pointers = _export_directory_bytes(
            data,
            rva=name_pointer_rva,
            size=name_count * 4,
            directory_rva=directory_rva,
            directory_end=directory_end,
            sections=sections,
            size_of_headers=size_of_headers,
            label="export name pointer table",
        )
        name_ordinals = _export_directory_bytes(
            data,
            rva=name_ordinal_rva,
            size=name_count * 2,
            directory_rva=directory_rva,
            directory_end=directory_end,
            sections=sections,
            size_of_headers=size_of_headers,
            label="export name ordinal table",
        )
        seen_names: set[str] = set()
        pointer_values = struct.iter_unpack("<I", name_pointers)
        ordinal_values = struct.iter_unpack("<H", name_ordinals)
        for pointer_value, ordinal_value in zip(pointer_values, ordinal_values):
            index = ordinal_value[0]
            if index >= function_count:
                raise _ExportParseError("name ordinal index is outside the EAT")
            name = _export_directory_string(
                data,
                rva=pointer_value[0],
                directory_rva=directory_rva,
                directory_end=directory_end,
                sections=sections,
                size_of_headers=size_of_headers,
                label="export name",
            )
            if name in seen_names:
                raise _ExportParseError(f"duplicate export name {name!r}")
            seen_names.add(name)
            names_by_index.setdefault(index, []).append(name)

    exports: list[PEExport] = []
    for index, target_rva in enumerate(target_rvas):
        names = tuple(sorted(names_by_index.get(index, ())))
        if target_rva == 0:
            if names:
                raise _ExportParseError("named export refers to an empty EAT slot")
            continue
        ordinal = ordinal_base + index
        if ordinal > 0xFFFFFFFF:
            raise _ExportParseError("export ordinal overflows 32 bits")
        kind, forwarder = _classify_export_target(
            data,
            target_rva=target_rva,
            directory_rva=directory_rva,
            directory_end=directory_end,
            sections=sections,
            size_of_headers=size_of_headers,
        )
        for name in names or (None,):
            exports.append(
                PEExport(
                    ordinal=ordinal,
                    name=name,
                    rva=target_rva,
                    kind=kind,
                    forwarder=forwarder,
                )
            )
    return tuple(exports)


def _classify_export_target(
    data: bytes,
    *,
    target_rva: int,
    directory_rva: int,
    directory_end: int,
    sections: tuple[PESection, ...],
    size_of_headers: int,
) -> tuple[str, str | None]:
    if directory_rva <= target_rva < directory_end:
        return (
            "forwarder",
            _export_directory_string(
                data,
                rva=target_rva,
                directory_rva=directory_rva,
                directory_end=directory_end,
                sections=sections,
                size_of_headers=size_of_headers,
                label="export forwarder",
            ),
        )
    matching_sections = [
        section
        for section in sections
        if section.rva_start <= target_rva < section.rva_end
    ]
    if len(matching_sections) > 1:
        raise _ExportParseError("export target RVA is covered by overlapping sections")
    if matching_sections:
        section = matching_sections[0]
        if section.executable or section.contains_code:
            _mapped_file_span(
                data,
                rva=target_rva,
                size=1,
                sections=sections,
                size_of_headers=size_of_headers,
                label="export target",
            )
            return "code", None
        return "data", None
    if target_rva < size_of_headers:
        _mapped_file_span(
            data,
            rva=target_rva,
            size=1,
            sections=sections,
            size_of_headers=size_of_headers,
            label="export target",
        )
        return "data", None
    raise _ExportParseError("export target RVA is not mapped by the image")


def _export_directory_bytes(
    data: bytes,
    *,
    rva: int,
    size: int,
    directory_rva: int,
    directory_end: int,
    sections: tuple[PESection, ...],
    size_of_headers: int,
    label: str,
) -> bytes:
    end = rva + size
    if rva < directory_rva or end > directory_end:
        raise _ExportParseError(f"{label} is outside the declared export span")
    offset = _mapped_file_span(
        data,
        rva=rva,
        size=size,
        sections=sections,
        size_of_headers=size_of_headers,
        label=label,
    )
    return data[offset : offset + size]


def _export_directory_string(
    data: bytes,
    *,
    rva: int,
    directory_rva: int,
    directory_end: int,
    sections: tuple[PESection, ...],
    size_of_headers: int,
    label: str,
) -> str:
    if not directory_rva <= rva < directory_end:
        raise _ExportParseError(f"{label} RVA is outside the declared export span")
    encoded = _export_directory_bytes(
        data,
        rva=rva,
        size=directory_end - rva,
        directory_rva=directory_rva,
        directory_end=directory_end,
        sections=sections,
        size_of_headers=size_of_headers,
        label=label,
    )
    terminator = encoded.find(b"\0")
    if terminator < 0:
        raise _ExportParseError(f"{label} is not NUL terminated within the declared export span")
    encoded = encoded[:terminator]
    if not encoded:
        raise _ExportParseError(f"{label} is empty")
    try:
        return encoded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _ExportParseError(f"{label} is not ASCII") from exc


def _mapped_file_span(
    data: bytes,
    *,
    rva: int,
    size: int,
    sections: tuple[PESection, ...],
    size_of_headers: int,
    label: str,
) -> int:
    if size <= 0:
        raise _ExportParseError(f"{label} has an empty span")
    end = rva + size
    if rva < 0 or end > 0x1_0000_0000:
        raise _ExportParseError(f"{label} overflows the 32-bit RVA space")

    offsets: list[int] = []
    if rva < size_of_headers and end <= size_of_headers:
        if end > len(data):
            raise _ExportParseError(f"{label} extends beyond the exact file bytes")
        offsets.append(rva)
    matching_sections = [
        section
        for section in sections
        if section.rva_start <= rva and end <= section.rva_end
    ]
    if len(matching_sections) > 1:
        raise _ExportParseError(f"{label} is covered by overlapping sections")
    if matching_sections:
        section = matching_sections[0]
        relative = rva - section.rva_start
        if relative + size > section.raw_size:
            raise _ExportParseError(f"{label} is not backed by exact file bytes")
        offset = section.raw_pointer + relative
        if offset + size > len(data):
            raise _ExportParseError(f"{label} extends beyond the exact file bytes")
        offsets.append(offset)
    if len(offsets) != 1:
        if offsets:
            raise _ExportParseError(f"{label} has an ambiguous RVA mapping")
        raise _ExportParseError(f"{label} is not fully mapped by the exact file bytes")
    return offsets[0]


def _parse_tls_callback_rvas(
    pe: pefile.PE, tls_directory: Any | None
) -> tuple[tuple[int, ...] | None, int | None, str | None]:
    """Propose the PE TLS callback inventory for later formal checking."""
    if tls_directory is None:
        return (), None, None
    directory_rva = int(tls_directory.VirtualAddress)
    directory_size = int(tls_directory.Size)
    if directory_rva == 0 and directory_size == 0:
        return (), None, None
    pe32 = int(pe.OPTIONAL_HEADER.Magic) == 0x10B
    directory_width = 24 if pe32 else 40
    pointer_width = 4 if pe32 else 8
    pointer_format = "<I" if pe32 else "<Q"
    callbacks_offset = 12 if pe32 else 24
    if directory_rva == 0 or directory_size < directory_width:
        return None, None, "malformed PE TLS directory span"
    directory = pe.get_data(directory_rva, directory_width)
    if len(directory) != directory_width:
        return None, None, "PE TLS directory is not fully mapped"
    callbacks_va = struct.unpack_from(pointer_format, directory, callbacks_offset)[0]
    if callbacks_va == 0:
        return (), None, None
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    size_of_image = int(pe.OPTIONAL_HEADER.SizeOfImage)
    image_end = image_base + size_of_image
    if not image_base <= callbacks_va < image_end:
        return None, None, "PE TLS callback array VA is outside the mapped image"
    callbacks_rva = callbacks_va - image_base
    callback_slots = (size_of_image - callbacks_rva) // pointer_width
    callbacks: list[int] = []
    for index in range(callback_slots):
        encoded = pe.get_data(
            callbacks_rva + index * pointer_width, pointer_width
        )
        if len(encoded) != pointer_width:
            return None, callbacks_rva, "PE TLS callback array is not fully mapped"
        callback_va = struct.unpack(pointer_format, encoded)[0]
        if callback_va == 0:
            return tuple(callbacks), callbacks_rva, None
        if not image_base <= callback_va < image_end:
            return None, callbacks_rva, "PE TLS callback VA is outside the mapped image"
        callbacks.append(callback_va - image_base)
    return None, callbacks_rva, "PE TLS callback array is not null terminated"


def _tls_callback_array_words_immutable(
    sections: tuple[PESection, ...],
    *,
    size_of_headers: int,
    directory_pointer_rva: int | None,
    callback_array_rva: int | None,
    callback_count: int,
    pointer_width: int,
) -> bool:
    """Mirror the formal immutable-image test for the callback inventory."""
    if callback_array_rva is None:
        return True
    word_rvas = [
        callback_array_rva + index * pointer_width
        for index in range(callback_count + 1)
    ]
    if directory_pointer_rva is not None:
        word_rvas.insert(0, directory_pointer_rva)
    for start in word_rvas:
        end = start + pointer_width
        if start < size_of_headers and end <= size_of_headers:
            continue
        matches = [
            section for section in sections
            if section.rva_start <= start and end <= section.rva_end
        ]
        if len(matches) != 1 or matches[0].writable:
            return False
    return True


def _pe_section(section: Any) -> PESection:
    name = section.Name.rstrip(b"\0").decode("utf-8", errors="replace")
    rva_start = int(section.VirtualAddress)
    rva_end = rva_start + mapped_section_size(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
    characteristics = int(section.Characteristics)
    return PESection(
        name=name,
        rva_start=rva_start,
        rva_end=rva_end,
        raw_pointer=int(section.PointerToRawData),
        raw_size=int(section.SizeOfRawData),
        characteristics=characteristics,
        executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
        readable=bool(characteristics & IMAGE_SCN_MEM_READ),
        writable=bool(characteristics & IMAGE_SCN_MEM_WRITE),
        contains_code=bool(characteristics & IMAGE_SCN_CNT_CODE),
    )


def _imports(pe: pefile.PE) -> tuple[PEImport, ...]:
    imports: list[PEImport] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        for item in entry.imports:
            symbol = item.name.decode("utf-8", errors="replace") if item.name else None
            thunk_rva = int(item.address - pe.OPTIONAL_HEADER.ImageBase) if item.address is not None else None
            imports.append(PEImport(dll=dll.lower(), symbol=symbol, ordinal=item.ordinal, thunk_rva=thunk_rva))
    return tuple(imports)


def _subsystem_name(value: int) -> str:
    names = {
        1: "native",
        2: "windows_gui",
        3: "windows_cui",
        7: "posix_cui",
        9: "windows_ce_gui",
    }
    return names.get(value, f"unknown_{value}")
