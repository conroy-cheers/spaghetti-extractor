from __future__ import annotations

import struct

from .model import (
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_FILE_DLL,
    PE32_CONSOLE_PREFERRED_BASE_POLICY,
    LoaderDiagnostic,
    LoaderDiagnosticSeverity,
    LoaderDiagnosticStatus,
    LoaderDiagnostics,
    PESection,
    RawPESection,
)
from .pe import (
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    mapped_section_size,
)


def diagnose_pe32_loader_image(data: bytes) -> LoaderDiagnostics:
    """Mirror PE32 loader checks for early diagnostics, never authorization."""
    diagnostics, _sections = inspect_pe32_loader_image(data)
    return diagnostics


def inspect_pe32_loader_image(
    data: bytes,
) -> tuple[LoaderDiagnostics, tuple[PESection, ...] | None]:
    found: list[LoaderDiagnostic] = []

    def error(code: str, message: str) -> None:
        found.append(
            LoaderDiagnostic(
                severity=LoaderDiagnosticSeverity.ERROR,
                code=code,
                message=message,
            )
        )

    def warning(code: str, message: str) -> None:
        found.append(
            LoaderDiagnostic(
                severity=LoaderDiagnosticSeverity.WARNING,
                code=code,
                message=message,
            )
        )

    def finish(
        sections: tuple[RawPESection, ...] | None = None,
    ) -> tuple[LoaderDiagnostics, tuple[PESection, ...] | None]:
        status = LoaderDiagnosticStatus.DIAGNOSTIC_CLEAN
        if any(
            diagnostic.severity is LoaderDiagnosticSeverity.ERROR
            for diagnostic in found
        ):
            status = LoaderDiagnosticStatus.INVALID
        elif found:
            status = LoaderDiagnosticStatus.CONDITIONAL_LAUNCH
        return (
            LoaderDiagnostics(
                policy=PE32_CONSOLE_PREFERRED_BASE_POLICY,
                status=status,
                diagnostics=tuple(found),
            ),
            (
                tuple(raw.section for raw in sections)
                if sections is not None
                else None
            ),
        )

    if len(data) < 0x40:
        error("dos_header_bounds", "the file does not contain a complete DOS header")
        return finish()
    if data[:2] != b"MZ":
        error("dos_signature", "the DOS signature is not MZ")
        return finish()
    if len(data) > 0x1_0000_0000:
        error("file_size_32bit", "the exact PE file exceeds the 32-bit loader bound")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40:
        error("pe_header_offset", "the PE header overlaps the bounded DOS header")
        return finish()
    if pe_offset > len(data) - 24:
        error("coff_header_bounds", "the PE signature and COFF header exceed the file")
        return finish()
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        error("pe_signature", "the PE signature is not PE\\0\\0")
        return finish()

    coff_offset = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff_offset)
    optional_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    coff_characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        error("optional_header_bounds", "the COFF optional header exceeds the file")
        return finish()

    section_table_end = optional_end + section_count * 40
    if section_table_end > len(data):
        error("section_table_bounds", "the complete section table exceeds the file")
        return finish()

    if section_count == 0:
        error("section_count_zero", "a console image must contain at least one section")
    elif section_count > 96:
        error("section_count_unknown", "the section count exceeds the supported PE loader bound of 96")

    raw_sections: list[RawPESection] = []
    for index in range(section_count):
        section_offset = optional_end + index * 40
        (
            encoded_name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            _relocation_pointer,
            _line_number_pointer,
            _relocation_count,
            _line_number_count,
            characteristics,
        ) = struct.unpack_from("<8sIIIIIIHHI", data, section_offset)
        name = encoded_name.rstrip(b"\0").decode("utf-8", errors="replace")
        mapped_size = mapped_section_size(virtual_size, raw_size)
        raw_sections.append(
            RawPESection(
                section=PESection(
                    name=name,
                    rva_start=virtual_address,
                    rva_end=virtual_address + mapped_size,
                    raw_pointer=raw_pointer,
                    raw_size=raw_size,
                    characteristics=characteristics,
                    executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
                    readable=bool(characteristics & IMAGE_SCN_MEM_READ),
                    writable=bool(characteristics & IMAGE_SCN_MEM_WRITE),
                    contains_code=bool(characteristics & IMAGE_SCN_CNT_CODE),
                ),
            )
        )
    ordered_sections = tuple(raw_sections)

    if machine != 0x014C:
        error("machine_not_i386", f"the preferred-base PE32 policy does not support machine 0x{machine:04x}")
    if optional_size < 2:
        error("optional_header_magic_bounds", "the optional header does not contain its magic")
        return finish(ordered_sections)
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic != 0x10B:
        error("optional_header_not_pe32", f"the preferred-base PE32 policy does not support magic 0x{magic:04x}")
    if machine != 0x014C or magic != 0x10B:
        return finish(ordered_sections)
    if optional_size < 224:
        error(
            "optional_header_pe32_bounds",
            "the PE32 optional header is smaller than the required 224-byte loader header",
        )
        return finish(ordered_sections)

    image_base = struct.unpack_from("<I", data, optional_offset + 28)[0]
    section_alignment = struct.unpack_from("<I", data, optional_offset + 32)[0]
    file_alignment = struct.unpack_from("<I", data, optional_offset + 36)[0]
    size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
    dll_characteristics = struct.unpack_from("<H", data, optional_offset + 70)[0]
    directory_count = struct.unpack_from("<I", data, optional_offset + 92)[0]

    if coff_characteristics & IMAGE_FILE_DLL:
        error("console_image_is_dll", "the preferred-base console policy does not admit DLL images")
    if subsystem != 3:
        error("subsystem_not_console", f"the PE subsystem is {subsystem}, not Windows console (3)")

    if size_of_image == 0:
        error("size_of_image_zero", "SizeOfImage must be nonzero")
    elif image_base + size_of_image > 0x1_0000_0000:
        error("image_address_space_overflow", "ImageBase plus SizeOfImage exceeds the 32-bit address space")
    if image_base % 0x10000 != 0:
        error("image_base_alignment", "ImageBase is not aligned to 64 KiB")

    section_alignment_valid = _is_power_of_two(section_alignment)
    file_alignment_valid = _is_power_of_two(file_alignment)
    if not section_alignment_valid:
        error("section_alignment", "SectionAlignment is not a nonzero power of two")
    if not file_alignment_valid:
        error("file_alignment", "FileAlignment is not a nonzero power of two")
    if section_alignment_valid and file_alignment_valid:
        if section_alignment < file_alignment:
            error("alignment_order", "SectionAlignment is smaller than FileAlignment")
        if section_alignment < 0x1000 and file_alignment != section_alignment:
            error("low_alignment_mismatch", "sub-page SectionAlignment must equal FileAlignment")

    if file_alignment_valid:
        minimum_headers = _align_up(section_table_end, file_alignment)
        if size_of_headers < minimum_headers:
            error(
                "size_of_headers_minimum",
                f"SizeOfHeaders is 0x{size_of_headers:x}, below the 0x{minimum_headers:x} minimum",
            )
        if size_of_headers % file_alignment != 0:
            error("size_of_headers_alignment", "SizeOfHeaders is not FileAlignment-aligned")
    if size_of_headers > len(data):
        error("headers_file_bounds", "SizeOfHeaders exceeds the file")
    if size_of_headers > size_of_image:
        error("headers_image_bounds", "SizeOfHeaders exceeds SizeOfImage")
    if size_of_headers < section_table_end:
        error("headers_table_bounds", "SizeOfHeaders does not cover the complete section table")

    _diagnose_loader_sections(
        ordered_sections,
        data_size=len(data),
        size_of_headers=size_of_headers,
        size_of_image=size_of_image,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        section_alignment_valid=section_alignment_valid,
        file_alignment_valid=file_alignment_valid,
        error=error,
    )

    if entrypoint_rva := struct.unpack_from("<I", data, optional_offset + 16)[0]:
        executable_matches = [
            raw.section
            for raw in ordered_sections
            if raw.section.executable
            and raw.section.rva_start <= entrypoint_rva < raw.section.rva_end
        ]
        if entrypoint_rva >= size_of_image or len(executable_matches) != 1:
            error(
                "entrypoint_not_executable",
                "AddressOfEntryPoint is not inside exactly one executable mapped section",
            )

    directory_bytes = optional_size - 96
    directory_capacity = directory_bytes // 8
    if directory_count > directory_capacity:
        error("directory_count_bounds", "NumberOfRvaAndSizes exceeds the optional-header directory capacity")
    if directory_count > 16:
        error("directory_count_unknown", "NumberOfRvaAndSizes exceeds the supported PE32 directory count of 16")

    for index in range(min(directory_capacity, 16)):
        directory_offset = optional_offset + 96 + index * 8
        rva, size = struct.unpack_from("<II", data, directory_offset)
        if index >= directory_count:
            if rva != 0 or size != 0:
                error(
                    "directory_undeclared_present",
                    f"data-directory slot {index} is nonzero but is excluded by NumberOfRvaAndSizes",
                )
            continue
        if (rva == 0) != (size == 0):
            error(
                "directory_presence_incoherent",
                f"data-directory slot {index} has only one of RVA and size present",
            )
            continue
        if rva == 0:
            continue
        if index == 4:
            if rva + size > len(data):
                error("security_directory_file_bounds", "the certificate table exceeds the file")
        elif not _loader_mapped_span(
            ordered_sections,
            rva=rva,
            size=size,
            size_of_headers=size_of_headers,
            size_of_image=size_of_image,
        ):
            error(
                "directory_mapped_span",
                f"data-directory slot {index} is not contained in one mapped image span",
            )

    if dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        warning(
            "dynamic_base_requires_preferred_base",
            "DYNAMIC_BASE is set; launch is covered only when the image is loaded at its preferred base",
        )
    return finish(ordered_sections)


def _diagnose_loader_sections(
    sections: tuple[RawPESection, ...],
    *,
    data_size: int,
    size_of_headers: int,
    size_of_image: int,
    section_alignment: int,
    file_alignment: int,
    section_alignment_valid: bool,
    file_alignment_valid: bool,
    error: Callable[[str, str], None],
) -> None:
    previous_virtual_address: int | None = None
    raw_cursor = size_of_headers
    virtual_ranges: list[tuple[int, int, int]] = []
    raw_ranges: list[tuple[int, int, int]] = []
    for index, raw in enumerate(sections):
        section = raw.section
        mapped_size = section.rva_end - section.rva_start
        if mapped_size == 0:
            error("section_mapped_size_zero", f"section {index} has no mapped extent")
        if previous_virtual_address is not None and section.rva_start <= previous_virtual_address:
            error("section_virtual_order", f"section {index} is not in ascending RVA order on disk")
        previous_virtual_address = section.rva_start
        if section_alignment_valid and section.rva_start % section_alignment != 0:
            error("section_virtual_alignment", f"section {index} RVA is not SectionAlignment-aligned")
        if section.rva_start < size_of_headers:
            error("section_overlaps_headers", f"section {index} starts inside SizeOfHeaders")
        if section.rva_end > 0x1_0000_0000:
            error("section_virtual_overflow", f"section {index} exceeds the 32-bit RVA space")
        if section.rva_end > size_of_image:
            error("section_image_bounds", f"section {index} exceeds SizeOfImage")
        if mapped_size:
            virtual_ranges.append((section.rva_start, section.rva_end, index))

        if section.raw_size == 0:
            if section.raw_pointer != 0:
                error("section_raw_presence", f"section {index} has a raw pointer but zero raw size")
            continue
        raw_end = section.raw_pointer + section.raw_size
        if section.raw_pointer < raw_cursor:
            error("section_raw_order", f"section {index} raw bytes are not in ascending file order")
        if file_alignment_valid and section.raw_pointer % file_alignment != 0:
            error("section_raw_pointer_alignment", f"section {index} raw pointer is not FileAlignment-aligned")
        if file_alignment_valid and section.raw_size % file_alignment != 0:
            error("section_raw_size_alignment", f"section {index} raw size is not FileAlignment-aligned")
        if section.raw_pointer < size_of_headers:
            error("section_raw_overlaps_headers", f"section {index} raw bytes overlap SizeOfHeaders")
        if raw_end > data_size:
            error("section_raw_file_bounds", f"section {index} raw bytes exceed the file")
        raw_ranges.append((section.raw_pointer, raw_end, index))
        raw_cursor = raw_end

    _diagnose_disjoint_ranges(virtual_ranges, "section_virtual_overlap", "mapped RVA", error)
    _diagnose_disjoint_ranges(raw_ranges, "section_raw_overlap", "raw file", error)

    if section_alignment_valid:
        highest_end = max(
            (section.section.rva_end for section in sections),
            default=size_of_headers,
        )
        expected_image = _align_up(max(size_of_headers, highest_end), section_alignment)
        if size_of_image != expected_image:
            error(
                "size_of_image_exact",
                f"SizeOfImage is 0x{size_of_image:x}, expected 0x{expected_image:x}",
            )
        if size_of_image % section_alignment != 0:
            error("size_of_image_alignment", "SizeOfImage is not SectionAlignment-aligned")


def _diagnose_disjoint_ranges(
    ranges: list[tuple[int, int, int]],
    code: str,
    label: str,
    error: Callable[[str, str], None],
) -> None:
    for position, (start, end, index) in enumerate(ranges):
        for other_start, other_end, other_index in ranges[position + 1 :]:
            if start < other_end and other_start < end:
                error(code, f"sections {index} and {other_index} have overlapping {label} ranges")


def _loader_mapped_span(
    sections: tuple[RawPESection, ...],
    *,
    rva: int,
    size: int,
    size_of_headers: int,
    size_of_image: int,
) -> bool:
    if size <= 0 or rva + size > size_of_image:
        return False
    if rva < size_of_headers and rva + size <= size_of_headers:
        return True
    matches = [
        raw.section
        for raw in sections
        if raw.section.rva_start <= rva
        and rva + size <= raw.section.rva_end
    ]
    return len(matches) == 1


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


__all__ = ["diagnose_pe32_loader_image", "inspect_pe32_loader_image"]
