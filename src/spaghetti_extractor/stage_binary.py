from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

from .pe import (
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    mapped_section_size,
)
from .util import sha256_bytes


STAGE_A_MODEL_ID = "x86-pe32-env-v1"
STAGE_A_X86_64_MODEL_ID = "x86_64-pe32plus-env-v1"
STAGE_A_MODEL_SPECS = {
    STAGE_A_MODEL_ID: {"architecture": "x86", "machine": "i386", "bitness": 32, "magic": 0x10B},
    STAGE_A_X86_64_MODEL_ID: {"architecture": "x86_64", "machine": "x86_64", "bitness": 64, "magic": 0x20B},
}

IMAGE_FILE_DLL = 0x2000
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
PE32_CONSOLE_PREFERRED_BASE_POLICY = "pe32-console-preferred-base-v1"


class StageALoaderDiagnosticSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


class StageALoaderDiagnosticStatus(str, Enum):
    DIAGNOSTIC_CLEAN = "diagnostic-clean"
    CONDITIONAL_LAUNCH = "conditional-launch"
    INVALID = "invalid"


@dataclass(frozen=True)
class StageALoaderDiagnostic:
    severity: StageALoaderDiagnosticSeverity
    code: str
    message: str


@dataclass(frozen=True)
class StageALoaderDiagnostics:
    policy: str
    status: StageALoaderDiagnosticStatus
    diagnostics: tuple[StageALoaderDiagnostic, ...]

    @property
    def hard_diagnostics(self) -> tuple[StageALoaderDiagnostic, ...]:
        return tuple(
            diagnostic
            for diagnostic in self.diagnostics
            if diagnostic.severity is StageALoaderDiagnosticSeverity.ERROR
        )

    @property
    def conditional_warnings(self) -> tuple[StageALoaderDiagnostic, ...]:
        return tuple(
            diagnostic
            for diagnostic in self.diagnostics
            if diagnostic.severity is StageALoaderDiagnosticSeverity.WARNING
        )

    @property
    def authorizes_stage_a(self) -> bool:
        """The Python mirror is diagnostic-only; Lean decides Stage A."""
        return False

    def as_payload(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "status": self.status.value,
            "authorizes_stage_a": False,
            "diagnostics": [
                {
                    "severity": diagnostic.severity.value,
                    "code": diagnostic.code,
                    "message": diagnostic.message,
                }
                for diagnostic in self.diagnostics
            ],
        }


@dataclass(frozen=True)
class StageASection:
    name: str
    rva_start: int
    rva_end: int
    raw_pointer: int
    raw_size: int
    characteristics: int
    executable: bool
    readable: bool
    writable: bool
    contains_code: bool


@dataclass(frozen=True)
class StageAImport:
    dll: str
    symbol: str | None
    ordinal: int | None
    thunk_rva: int | None


@dataclass(frozen=True)
class StageAExport:
    ordinal: int
    name: str | None
    rva: int
    kind: str
    forwarder: str | None


@dataclass(frozen=True)
class StageABinary:
    path: Path
    sha256: str
    size: int
    machine: str
    bitness: int
    coff_characteristics: int
    is_dll: bool
    image_base: int
    entrypoint_rva: int
    exports: tuple[StageAExport, ...] | None
    export_parse_error: str | None
    tls_directory_rva: int
    tls_directory_size: int
    tls_callback_rvas: tuple[int, ...] | None
    tls_callback_array_rva: int | None
    tls_callback_array_size: int | None
    tls_callback_array_immutable: bool | None
    tls_callback_parse_error: str | None
    size_of_image: int
    size_of_headers: int
    subsystem: str
    loader_diagnostics: StageALoaderDiagnostics
    sections: tuple[StageASection, ...]
    imports: tuple[StageAImport, ...]
    pe: pefile.PE


@dataclass(frozen=True)
class BlockSide:
    rva_start: int
    rva_end: int

    @property
    def size(self) -> int:
        return self.rva_end - self.rva_start


class StageAInputError(ValueError):
    pass


class _ExportParseError(ValueError):
    pass


@dataclass(frozen=True)
class _RawStageASection:
    section: StageASection


def diagnose_pe32_loader_image(data: bytes) -> StageALoaderDiagnostics:
    """Mirror PE32 loader checks for early diagnostics, never authorization."""
    diagnostics, _sections = _inspect_pe32_loader_image(data)
    return diagnostics


def _inspect_pe32_loader_image(
    data: bytes,
) -> tuple[StageALoaderDiagnostics, tuple[StageASection, ...] | None]:
    found: list[StageALoaderDiagnostic] = []

    def error(code: str, message: str) -> None:
        found.append(
            StageALoaderDiagnostic(
                severity=StageALoaderDiagnosticSeverity.ERROR,
                code=code,
                message=message,
            )
        )

    def warning(code: str, message: str) -> None:
        found.append(
            StageALoaderDiagnostic(
                severity=StageALoaderDiagnosticSeverity.WARNING,
                code=code,
                message=message,
            )
        )

    def finish(
        sections: tuple[_RawStageASection, ...] | None = None,
    ) -> tuple[StageALoaderDiagnostics, tuple[StageASection, ...] | None]:
        status = StageALoaderDiagnosticStatus.DIAGNOSTIC_CLEAN
        if any(
            diagnostic.severity is StageALoaderDiagnosticSeverity.ERROR
            for diagnostic in found
        ):
            status = StageALoaderDiagnosticStatus.INVALID
        elif found:
            status = StageALoaderDiagnosticStatus.CONDITIONAL_LAUNCH
        return (
            StageALoaderDiagnostics(
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

    raw_sections: list[_RawStageASection] = []
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
            _RawStageASection(
                section=StageASection(
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
    sections: tuple[_RawStageASection, ...],
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
    sections: tuple[_RawStageASection, ...],
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


def _artifact_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value).strip("-") or "artifact"


def _parse_stage_a_pe(path: Path) -> StageABinary:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise StageAInputError(f"cannot read PE file {path}: {exc}") from exc
    loader_diagnostics, raw_sections = _inspect_pe32_loader_image(data)
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # pefile raises several non-public exception types.
        raise StageAInputError(f"{path} is not a parseable PE file: {exc}") from exc

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
        raise StageAInputError(f"{path} is out of model: expected x86 PE32 or x86_64 PE32+, got machine={machine_name} magic={magic_name}")

    if raw_sections is None:
        diagnostic_codes = ", ".join(
            diagnostic.code for diagnostic in loader_diagnostics.hard_diagnostics
        )
        raise StageAInputError(
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
    return StageABinary(
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
        raise StageAInputError(f"{path} has a malformed DOS header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    coff_offset = pe_offset + 4
    if pe_offset > len(data) - 24 or data[pe_offset:coff_offset] != b"PE\0\0":
        raise StageAInputError(f"{path} has a malformed PE signature or COFF header")

    optional_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    coff_characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(data) or optional_size < 2:
        raise StageAInputError(f"{path} has a truncated PE optional header")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic != expected_magic:
        raise StageAInputError(f"{path} has inconsistent PE optional-header magic")

    if magic == 0x10B:
        directory_count_offset = 92
        directory_table_offset = 96
    elif magic == 0x20B:
        directory_count_offset = 108
        directory_table_offset = 112
    else:
        raise StageAInputError(f"{path} has unsupported PE optional-header magic 0x{magic:04x}")
    if optional_size < directory_count_offset + 4:
        raise StageAInputError(f"{path} has a truncated PE data-directory count")
    directory_count = struct.unpack_from(
        "<I", data, optional_offset + directory_count_offset
    )[0]
    if directory_count == 0:
        return coff_characteristics, 0, 0
    if optional_size < directory_table_offset + 8:
        raise StageAInputError(f"{path} has a truncated PE export data-directory entry")
    directory_rva, directory_size = struct.unpack_from(
        "<II", data, optional_offset + directory_table_offset
    )
    return coff_characteristics, directory_rva, directory_size


def _parse_exports(
    data: bytes,
    *,
    directory_rva: int,
    directory_size: int,
    sections: tuple[StageASection, ...],
    size_of_headers: int,
) -> tuple[tuple[StageAExport, ...] | None, str | None]:
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
    sections: tuple[StageASection, ...],
    size_of_headers: int,
) -> tuple[StageAExport, ...]:
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

    exports: list[StageAExport] = []
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
                StageAExport(
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
    sections: tuple[StageASection, ...],
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
    sections: tuple[StageASection, ...],
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
    sections: tuple[StageASection, ...],
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
    sections: tuple[StageASection, ...],
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
    sections: tuple[StageASection, ...],
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


def _stage_a_section(section: Any) -> StageASection:
    name = section.Name.rstrip(b"\0").decode("utf-8", errors="replace")
    rva_start = int(section.VirtualAddress)
    rva_end = rva_start + mapped_section_size(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
    characteristics = int(section.Characteristics)
    return StageASection(
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


def _imports(pe: pefile.PE) -> tuple[StageAImport, ...]:
    imports: list[StageAImport] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        for item in entry.imports:
            symbol = item.name.decode("utf-8", errors="replace") if item.name else None
            thunk_rva = int(item.address - pe.OPTIONAL_HEADER.ImageBase) if item.address is not None else None
            imports.append(StageAImport(dll=dll.lower(), symbol=symbol, ordinal=item.ordinal, thunk_rva=thunk_rva))
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


def _parse_linker_map_functions(path: Path, binary: StageABinary) -> list[dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise StageAInputError(f"cannot read linker map {path}: {exc}") from exc
    symbol_starts: dict[int, list[str]] = {}
    boundary_starts: set[int] = set()
    pending_text_section: str | None = None
    for line in text.splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is not None:
            rva, name = parsed
            if _linker_map_symbol_is_non_function_label(name):
                continue
            if _executable_section_for_rva(binary, rva) is None:
                continue
            symbol_starts.setdefault(rva, [])
            if name not in symbol_starts[rva]:
                symbol_starts[rva].append(name)
            continue
        boundary = _parse_linker_map_text_boundary_line(line, binary)
        if boundary is not None:
            boundary_starts.add(boundary)
            fragment_symbol = _linker_map_text_fragment_symbol(line)
            if fragment_symbol is not None:
                symbol_starts.setdefault(boundary, [])
                if fragment_symbol not in symbol_starts[boundary]:
                    symbol_starts[boundary].append(fragment_symbol)
            pending_text_section = None
            continue
        continuation = _parse_linker_map_text_boundary_continuation_line(line, binary)
        if continuation is not None and pending_text_section is not None:
            boundary_starts.add(continuation)
            fragment_symbol = _linker_map_section_fragment_symbol(pending_text_section)
            if fragment_symbol is not None:
                symbol_starts.setdefault(continuation, [])
                if fragment_symbol not in symbol_starts[continuation]:
                    symbol_starts[continuation].append(fragment_symbol)
            pending_text_section = None
            continue
        text_section = _parse_linker_map_text_section_only_line(line)
        if text_section is not None:
            pending_text_section = text_section
            continue
        if line.strip():
            pending_text_section = None

    functions: list[dict[str, Any]] = []
    ordered = sorted(symbol_starts)
    range_boundaries = sorted(set(ordered) | boundary_starts)
    for rva in ordered:
        section = _executable_section_for_rva(binary, rva)
        if section is None:
            continue
        next_starts = [value for value in range_boundaries if value > rva and value <= section.rva_end]
        rva_end = next_starts[0] if next_starts else section.rva_end
        if rva_end <= rva:
            continue
        primary = _primary_symbol_name(symbol_starts[rva])
        functions.append(
            {
                "name": primary,
                "aliases": symbol_starts[rva],
                "rva_start": rva,
                "rva_end": rva_end,
                "section": section.name,
            }
        )
    return functions


def _coff_symbol_aliases_by_rva(binary: StageABinary) -> dict[int, list[str]]:
    pointer = int(getattr(binary.pe.FILE_HEADER, "PointerToSymbolTable", 0) or 0)
    count = int(getattr(binary.pe.FILE_HEADER, "NumberOfSymbols", 0) or 0)
    if pointer <= 0 or count <= 0:
        return {}
    try:
        data = binary.path.read_bytes()
    except OSError:
        return {}
    symbol_table_size = count * 18
    symbol_table_end = pointer + symbol_table_size
    if symbol_table_end > len(data):
        return {}
    string_table_start = symbol_table_end
    string_table_size = 0
    if string_table_start + 4 <= len(data):
        string_table_size = int.from_bytes(data[string_table_start : string_table_start + 4], "little", signed=False)
    result: dict[int, list[str]] = {}
    index = 0
    while index < count:
        offset = pointer + index * 18
        if offset + 18 > len(data):
            break
        entry = data[offset : offset + 18]
        name = _coff_symbol_name(entry[:8], data, string_table_start, string_table_size)
        value, section_number, symbol_type, storage_class, auxiliary_count = struct.unpack("<IhHBB", entry[8:18])
        if name and section_number > 0 and section_number <= len(binary.sections):
            section = binary.sections[section_number - 1]
            rva = section.rva_start + int(value)
            if section.executable and section.rva_start <= rva < section.rva_end and _coff_symbol_is_code_like(symbol_type, storage_class):
                aliases = result.setdefault(rva, [])
                for alias in _coff_symbol_aliases(name):
                    if alias not in aliases:
                        aliases.append(alias)
        index += 1 + int(auxiliary_count)
    return result


def _coff_symbol_name(name_field: bytes, data: bytes, string_table_start: int, string_table_size: int) -> str:
    if len(name_field) != 8:
        return ""
    if name_field[:4] == b"\0\0\0\0":
        offset = int.from_bytes(name_field[4:8], "little", signed=False)
        if offset < 4 or string_table_size <= 4 or offset >= string_table_size:
            return ""
        start = string_table_start + offset
        end_limit = min(string_table_start + string_table_size, len(data))
        end = data.find(b"\0", start, end_limit)
        if end < 0:
            end = end_limit
        return data[start:end].decode("utf-8", errors="replace")
    return name_field.rstrip(b"\0").decode("utf-8", errors="replace")


def _coff_symbol_aliases(name: str) -> list[str]:
    aliases = [name]
    stripped = name.lstrip("_")
    if stripped and stripped != name:
        aliases.append(stripped)
    return aliases


def _coff_symbol_is_code_like(symbol_type: int, storage_class: int) -> bool:
    # IMAGE_SYM_DTYPE_FUNCTION is encoded in the high nibble of the COFF type.
    if symbol_type & 0x20:
        return True
    # GNU ld often leaves local/static function labels with type 0 but class
    # external/static. Section executability is the primary guard above.
    return storage_class in {2, 3}


def _parse_linker_map_text_boundary_line(line: str, binary: StageABinary) -> int | None:
    match = re.match(r"^\s*\.text\S*\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    rva = address - binary.image_base if address >= binary.image_base else address
    if _executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_boundary_continuation_line(line: str, binary: StageABinary) -> int | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    rva = address - binary.image_base if address >= binary.image_base else address
    if _executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_section_only_line(line: str) -> str | None:
    match = re.match(r"^\s*(\.text\S*)\s*$", line)
    return match.group(1) if match is not None else None


def _linker_map_symbol_is_non_function_label(name: str) -> bool:
    stripped = name.lstrip("_")
    if re.match(r"^fu\d+_+", stripped):
        return True
    return stripped.startswith("stage_b_contract_rva_")


def _linker_map_text_fragment_symbol(line: str) -> str | None:
    match = re.match(r"^\s*(\.text\S*)\b", line)
    if match is None:
        return None
    return _linker_map_section_fragment_symbol(match.group(1))


def _linker_map_section_fragment_symbol(section_name: str) -> str | None:
    if "$" not in section_name:
        return None
    fragment = section_name.split("$", 1)[1].strip()
    if not fragment or fragment.startswith("."):
        return None
    return fragment


def _parse_linker_map_symbol_line(line: str, binary: StageABinary) -> tuple[int, str] | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    name = match.group(2)
    if name.startswith(".") or name in {"PROVIDE", "CREATE_OBJECT_SYMBOLS"}:
        return None
    rva = address - binary.image_base if address >= binary.image_base else address
    return rva, name


def _primary_symbol_name(names: list[str]) -> str:
    for name in names:
        if not name.startswith("__") and not name.startswith("___"):
            return name
    return names[0]


def _executable_section_for_rva(binary: StageABinary, rva: int) -> StageASection | None:
    for section in binary.sections:
        if section.executable and section.rva_start <= rva < section.rva_end:
            return section
    return None


def _section_for_rva(binary: StageABinary, rva: int) -> StageASection | None:
    for section in binary.sections:
        if section.rva_start <= rva < section.rva_end:
            return section
    return None


def _executable_section_covering_range(binary: StageABinary, rva_start: int, rva_end: int) -> StageASection | None:
    if rva_end <= rva_start:
        return None
    for section in binary.sections:
        if section.executable and section.rva_start <= rva_start and rva_end <= section.rva_end:
            return section
    return None


def _capstone_mode(binary: StageABinary) -> int:
    return capstone.CS_MODE_64 if binary.bitness == 64 else capstone.CS_MODE_32


def _linker_function_match_key(name: str) -> str:
    value = name.strip()
    if value.startswith("@"):
        value = value[1:]
    if "@" in value:
        left, right = value.rsplit("@", 1)
        if right.isdigit():
            value = left
    return value.lstrip("_")


def _linker_function_import_thunk_evidence(binary: StageABinary, function: dict[str, Any]) -> dict[str, Any] | None:
    start = int(function["rva_start"])
    end = int(function["rva_end"])
    if end <= start:
        return None
    data = binary.pe.get_data(start, min(16, end - start))
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + start))
    if not instructions:
        return None
    first = instructions[0]
    if int(first.address - binary.image_base) != start:
        return None
    imported = _direct_import_jump_instruction(binary, first)
    if imported is None:
        return None
    thunk_end = start + int(first.size)
    if thunk_end > end:
        return None
    padding = binary.pe.get_data(thunk_end, end - thunk_end)
    if len(padding) != end - thunk_end or not _is_padding_bytes(binary, thunk_end, padding):
        return None
    return {
        "function": function,
        "block": BlockSide(start, thunk_end),
        "function_range": BlockSide(start, end),
        "import": imported,
        "signature_key": _import_thunk_match_key(imported),
        "instruction": _instruction_report(binary, first),
        "padding_sha256": sha256_bytes(padding),
    }


def _direct_cfg_edges(binary: StageABinary, side: BlockSide) -> list[dict[str, Any]]:
    data = binary.pe.get_data(side.rva_start, side.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + side.rva_start))
    if not instructions or sum(insn.size for insn in instructions) != len(data):
        return []
    last = instructions[-1]
    last_rva = int(last.address - binary.image_base)
    fallthrough_rva = last_rva + int(last.size)
    mnemonic = last.mnemonic
    if _is_conditional_jump(mnemonic):
        target = _resolved_branch_target(binary, last)
        if target is None:
            return []
        return [
            {"kind": "taken", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic},
            {"kind": "fallthrough", "target_rva": fallthrough_rva, "instruction_rva": last_rva, "mnemonic": mnemonic},
        ]
    if mnemonic in {"jmp", "ljmp"}:
        target = _resolved_branch_target(binary, last)
        return [] if target is None else [{"kind": "jump", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "call":
        target = _resolved_branch_target(binary, last)
        return [] if target is None else [{"kind": "call", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "ret":
        return []
    return [{"kind": "fallthrough", "target_rva": side.rva_end, "instruction_rva": last_rva, "mnemonic": mnemonic}]


def _is_padding_bytes(binary: StageABinary, rva_start: int, data: bytes) -> bool:
    if not data:
        return True
    if all(byte == 0 for byte in data):
        return True
    if all(byte in {0x00, 0x90, 0xCC} for byte in data):
        return True
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return False
    if all(_is_padding_instruction(insn) for insn in instructions):
        return True
    return _is_alignment_jump_over_padding(binary, BlockSide(rva_start, rva_start + len(data)), instructions)


def _is_padding_instruction(insn: Any) -> bool:
    if insn.mnemonic in {"nop", "int3"}:
        return True
    if insn.mnemonic != "lea" or len(insn.operands) != 2:
        return False
    destination, source = insn.operands
    if destination.type != X86_OP_REG or source.type != X86_OP_MEM:
        return False
    mem = source.mem
    return destination.reg == mem.base and not mem.index and mem.disp == 0


def _is_alignment_jump_over_padding(binary: StageABinary, span: BlockSide, instructions: list[Any]) -> bool:
    if not instructions:
        return False
    insn = instructions[0]
    if insn.mnemonic not in {"jmp", "ljmp"}:
        return False
    target = _resolved_branch_target(binary, insn)
    if target is None:
        return False
    insn_end = int(insn.address - binary.image_base) + int(insn.size)
    if target < insn_end:
        return False
    if target < span.rva_end and not all(_is_padding_instruction(item) for item in instructions[1:]):
        return False
    bridge_end = max(span.rva_end, target)
    section = _executable_section_covering_range(binary, span.rva_start, bridge_end)
    if section is None:
        return False
    skipped_start = insn_end
    skipped_end = target
    if skipped_start == skipped_end:
        return target == span.rva_end
    skipped = binary.pe.get_data(skipped_start, skipped_end - skipped_start)
    return len(skipped) == skipped_end - skipped_start and _is_padding_bytes(binary, skipped_start, skipped)


def _instruction_report(binary: StageABinary, insn: Any) -> dict[str, Any]:
    return {
        "rva": int(insn.address - binary.image_base),
        "size": int(insn.size),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": bytes(insn.bytes).hex(),
    }


def _import_thunk_match_key(imported: StageAImport) -> str:
    symbol = imported.symbol if imported.symbol is not None else f"ordinal-{imported.ordinal}"
    return f"{imported.dll}!{symbol}"


def _direct_branch_target(insn: Any, image_base: int) -> int | None:
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    return int(operand.imm - image_base)


def _resolved_branch_target(binary: StageABinary, insn: Any) -> int | None:
    target = _direct_branch_target(insn, binary.image_base)
    if target is not None:
        return target
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    pointer_rva = _absolute_mem_operand_rva(binary, operand)
    if pointer_rva is None:
        return None
    width = 8 if binary.bitness == 64 else 4
    data = binary.pe.get_data(pointer_rva, width)
    if len(data) != width:
        return None
    value = int.from_bytes(data, "little")
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        target_rva = value - binary.image_base
    elif 0 <= value < binary.size_of_image:
        target_rva = value
    else:
        return None
    if _executable_section_for_rva(binary, target_rva) is None:
        return None
    return target_rva


def _direct_import_jump_instruction(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)


def _import_for_absolute_memory_operand(binary: StageABinary, operand: Any) -> StageAImport | None:
    thunk_rva = _absolute_mem_operand_rva(binary, operand)
    if thunk_rva is None:
        return None
    for item in binary.imports:
        if item.thunk_rva == thunk_rva:
            return item
    return None


def _absolute_mem_operand_rva(binary: StageABinary, operand: Any) -> int | None:
    mem = operand.mem
    if mem.base or mem.index:
        return None
    address = int(mem.disp)
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None


def _is_conditional_jump(mnemonic: str) -> bool:
    return mnemonic in {
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
    }
