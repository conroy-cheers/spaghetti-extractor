"""Deterministic PE32 image composition from opaque Stage A artifacts.

This module never accepts an original PE path.  The original image layout and
all reusable runtime bytes must come from a validated
``stage-a-load-image-contract-v1`` artifact.
"""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile

from .artifact_formats import (
    PAYLOAD_RELOCATION_INVENTORY_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
)
from .roundtrip_fuzz.image_contract import (
    STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT,
    StageALoadImageContract,
    load_stage_a_load_image_contract,
)
from .util import sha256_bytes


EXECUTABLE_ANCHOR_MANIFEST_FORMAT = "stage-b-pe-executable-anchor-manifest-v1"
CANDIDATE_FILENAME = "candidate.exe"
COMPOSITION_MANIFEST_FILENAME = "composition-manifest.json"

_IMAGE_FILE_RELOCS_STRIPPED = 0x0001
_IMAGE_SCN_CNT_CODE = 0x00000020
_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
_IMAGE_REL_BASED_ABSOLUTE = 0
_IMAGE_REL_BASED_HIGHLOW = 3
_RELOCATION_SECTION_CHARACTERISTICS = 0x42000040
_DIRECTORY_SECURITY = 4
_DIRECTORY_BASE_RELOCATION = 5
_DIRECTORY_DEBUG = 6
_DIRECTORY_TLS = 9
_DIRECTORY_IAT = 12
_DIRECTORY_DELAY_IMPORT = 13
_DIRECTORY_IMPORT = 1
_DIRECTORY_NAMES = (
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "base_relocation",
    "debug",
    "architecture",
    "global_pointer",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr_runtime",
    "reserved",
)
_TRAP_BYTE = 0xCC
_PADDING_BYTE = 0x00
_UINT16_MAX = (1 << 16) - 1
_UINT32_MAX = (1 << 32) - 1


class StageBPECompositionError(ValueError):
    """The requested PE composition is malformed or structurally unsafe."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _integer(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StageBPECompositionError(
            f"{context} must be an integer greater than or equal to {minimum}"
        )
    if value > _UINT32_MAX:
        raise StageBPECompositionError(f"{context} exceeds PE32 address width")
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str
) -> None:
    if not all(isinstance(key, str) for key in payload):
        raise StageBPECompositionError(f"{context} field names must be strings")
    actual = set(payload)
    if actual == expected:
        return
    details: list[str] = []
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        details.append(f"missing fields: {', '.join(missing)}")
    if unexpected:
        details.append(f"unexpected fields: {', '.join(unexpected)}")
    raise StageBPECompositionError(f"{context} has {'; '.join(details)}")


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageBPECompositionError(f"{context} must be an object")
    return value


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageBPECompositionError(f"{context} must be a list")
    return value


def _hex_bytes(value: Any, context: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise StageBPECompositionError(f"{context} must be nonempty hexadecimal")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise StageBPECompositionError(f"{context} must be canonical hexadecimal") from exc
    if result.hex() != value:
        raise StageBPECompositionError(
            f"{context} must be lowercase canonical hexadecimal"
        )
    return result


def _sha256(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StageBPECompositionError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _unique_rva_list(value: Any, context: str) -> tuple[int, ...]:
    result = tuple(
        _integer(item, f"{context}[{index}]")
        for index, item in enumerate(_list(value, context))
    )
    if len(set(result)) != len(result):
        raise StageBPECompositionError(f"{context} contains duplicate RVAs")
    return result


@dataclass(frozen=True)
class ExecutableAnchor:
    rva: int
    bytes: bytes

    @property
    def end_rva(self) -> int:
        return self.rva + len(self.bytes)

    def to_payload(self) -> dict[str, Any]:
        return {"rva": self.rva, "bytes_hex": self.bytes.hex()}

    @classmethod
    def parse(cls, value: Mapping[str, Any], *, context: str) -> "ExecutableAnchor":
        _exact_fields(value, {"rva", "bytes_hex"}, context)
        return cls(
            rva=_integer(value["rva"], f"{context}.rva"),
            bytes=_hex_bytes(value["bytes_hex"], f"{context}.bytes_hex"),
        )


@dataclass(frozen=True)
class ExecutableAnchorManifest:
    image_base: int
    entry_anchor_rva: int
    tls_callback_anchor_rvas: tuple[int, ...]
    callback_anchor_rvas: tuple[int, ...]
    anchors: tuple[ExecutableAnchor, ...]
    format: str = EXECUTABLE_ANCHOR_MANIFEST_FORMAT

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "image_base": self.image_base,
            "entry_anchor_rva": self.entry_anchor_rva,
            "tls_callback_anchor_rvas": list(self.tls_callback_anchor_rvas),
            "callback_anchor_rvas": list(self.callback_anchor_rvas),
            "anchors": [anchor.to_payload() for anchor in self.anchors],
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "ExecutableAnchorManifest":
        context = "executable-anchor manifest"
        _exact_fields(
            value,
            {
                "format",
                "image_base",
                "entry_anchor_rva",
                "tls_callback_anchor_rvas",
                "callback_anchor_rvas",
                "anchors",
            },
            context,
        )
        if value["format"] != EXECUTABLE_ANCHOR_MANIFEST_FORMAT:
            raise StageBPECompositionError("unsupported executable-anchor manifest format")
        parsed_anchors = tuple(
            ExecutableAnchor.parse(
                _mapping(item, f"{context}.anchors[{index}]"),
                context=f"{context}.anchors[{index}]",
            )
            for index, item in enumerate(_list(value["anchors"], f"{context}.anchors"))
        )
        if not parsed_anchors:
            raise StageBPECompositionError("executable-anchor manifest has no anchors")
        anchors = tuple(sorted(parsed_anchors, key=lambda item: item.rva))
        return cls(
            image_base=_integer(value["image_base"], f"{context}.image_base"),
            entry_anchor_rva=_integer(
                value["entry_anchor_rva"], f"{context}.entry_anchor_rva", minimum=1
            ),
            tls_callback_anchor_rvas=_unique_rva_list(
                value["tls_callback_anchor_rvas"],
                f"{context}.tls_callback_anchor_rvas",
            ),
            callback_anchor_rvas=_unique_rva_list(
                value["callback_anchor_rvas"], f"{context}.callback_anchor_rvas"
            ),
            anchors=anchors,
        )


@dataclass(frozen=True)
class PayloadRelocation:
    rva: int
    preferred_value: int
    type: int = 3
    kind: str = "highlow"
    width: int = 4

    def to_payload(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "type": self.type,
            "kind": self.kind,
            "width": self.width,
            "preferred_value": self.preferred_value,
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any], *, context: str) -> "PayloadRelocation":
        _exact_fields(
            value,
            {"rva", "type", "kind", "width", "preferred_value"},
            context,
        )
        relocation = cls(
            rva=_integer(value["rva"], f"{context}.rva"),
            type=_integer(value["type"], f"{context}.type"),
            kind=value["kind"] if isinstance(value["kind"], str) else "",
            width=_integer(value["width"], f"{context}.width", minimum=1),
            preferred_value=_integer(
                value["preferred_value"], f"{context}.preferred_value"
            ),
        )
        if (relocation.type, relocation.kind, relocation.width) != (
            3,
            "highlow",
            4,
        ):
            raise StageBPECompositionError(
                f"{context} must be a PE32 HIGHLOW relocation"
            )
        return relocation


@dataclass(frozen=True)
class PayloadRelocationInventory:
    payload_sha256: str
    image_base: int
    relocations: tuple[PayloadRelocation, ...]
    complete: bool = True
    format: str = PAYLOAD_RELOCATION_INVENTORY_FORMAT

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "complete": self.complete,
            "payload_sha256": self.payload_sha256,
            "image_base": self.image_base,
            "relocations": [item.to_payload() for item in self.relocations],
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "PayloadRelocationInventory":
        context = "payload relocation inventory"
        _exact_fields(
            value,
            {
                "format",
                "complete",
                "payload_sha256",
                "image_base",
                "relocations",
            },
            context,
        )
        if value["format"] != PAYLOAD_RELOCATION_INVENTORY_FORMAT:
            raise StageBPECompositionError(
                "unsupported payload relocation inventory format"
            )
        if value["complete"] is not True:
            raise StageBPECompositionError(
                "payload relocation inventory must assert complete coverage"
            )
        parsed = tuple(
            PayloadRelocation.parse(
                _mapping(item, f"{context}.relocations[{index}]"),
                context=f"{context}.relocations[{index}]",
            )
            for index, item in enumerate(
                _list(value["relocations"], f"{context}.relocations")
            )
        )
        relocations = tuple(sorted(parsed, key=lambda item: item.rva))
        if len({item.rva for item in relocations}) != len(relocations):
            raise StageBPECompositionError(
                "payload relocation inventory contains duplicate target RVAs"
            )
        return cls(
            payload_sha256=_sha256(
                value["payload_sha256"], f"{context}.payload_sha256"
            ),
            image_base=_integer(value["image_base"], f"{context}.image_base"),
            relocations=relocations,
        )


@dataclass(frozen=True)
class _Section:
    index: int
    name_bytes: bytes
    virtual_size: int
    rva: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    @property
    def name(self) -> str:
        return self.name_bytes.rstrip(b"\0").decode("latin-1")

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)

    @property
    def mapped_end(self) -> int:
        return self.rva + self.mapped_size

    @property
    def raw_end(self) -> int:
        return self.raw_pointer + self.raw_size

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)


@dataclass(frozen=True)
class ByteClassification:
    section_index: int
    section_name: str
    kind: str
    rva: int
    size: int
    bytes_sha256: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "section_index": self.section_index,
            "section_name": self.section_name,
            "kind": self.kind,
            "rva": self.rva,
            "size": self.size,
            "bytes_sha256": self.bytes_sha256,
        }


@dataclass(frozen=True)
class _MergedRelocation:
    source_target_rva: int
    target_rva: int
    type: int
    kind: str
    width: int
    preferred_value: int
    adjustment: int | None
    source: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "source_target_rva": self.source_target_rva,
            "target_rva": self.target_rva,
            "type": self.type,
            "kind": self.kind,
            "width": self.width,
            "preferred_value": self.preferred_value,
            "adjustment": self.adjustment,
            "source": self.source,
        }


@dataclass(frozen=True)
class _FileOffsetRewrite:
    kind: str
    index: int
    field_rva: int
    old_value: int
    new_value: int

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "index": self.index,
            "field_rva": self.field_rva,
            "old_value": self.old_value,
            "new_value": self.new_value,
        }


@dataclass(frozen=True)
class PECompositionPlan:
    """A fully validated, write-free PE32 composition plan."""

    contract: StageALoadImageContract
    anchor_manifest: ExecutableAnchorManifest
    relocation_inventory: PayloadRelocationInventory
    payload_bytes: bytes
    contract_original_sections: tuple[_Section, ...]
    original_sections: tuple[_Section, ...]
    payload_sections: tuple[_Section, ...]
    output_payload_sections: tuple[_Section, ...]
    classifications: tuple[ByteClassification, ...]
    merged_relocations: tuple[_MergedRelocation, ...]
    relocation_data: bytes
    relocation_section: _Section | None
    relocation_directory: tuple[int, int]
    section_table_offset: int
    file_alignment: int
    section_alignment: int
    original_size_of_headers: int
    new_size_of_headers: int
    original_raw_pointer_shift: int
    file_offset_rewrites: tuple[_FileOffsetRewrite, ...]
    coff_symbol_table_stripped: bool
    new_size_of_image: int
    original_directories: tuple[tuple[int, int], ...]


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise StageBPECompositionError("PE alignment is not a power of two")
    return (value + alignment - 1) // alignment * alignment


def _require_disjoint(
    spans: Sequence[tuple[int, int, str]], *, context: str
) -> None:
    ordered = sorted(spans)
    for (_, previous_end, previous), (start, _end, current) in zip(
        ordered, ordered[1:]
    ):
        if start < previous_end:
            raise StageBPECompositionError(
                f"{context} ranges {previous} and {current} overlap"
            )


def _pe_from_bytes(data: bytes, *, context: str) -> pefile.PE:
    try:
        return pefile.PE(data=data, fast_load=True)
    except (pefile.PEFormatError, OSError, ValueError, struct.error) as exc:
        raise StageBPECompositionError(f"{context} is not a parseable PE: {exc}") from exc


def _sections_from_pe(pe: pefile.PE) -> tuple[_Section, ...]:
    return tuple(
        _Section(
            index=index,
            name_bytes=bytes(section.Name),
            virtual_size=int(section.Misc_VirtualSize),
            rva=int(section.VirtualAddress),
            raw_size=int(section.SizeOfRawData),
            raw_pointer=int(section.PointerToRawData),
            characteristics=int(section.Characteristics),
        )
        for index, section in enumerate(pe.sections)
    )


def _directories(pe: pefile.PE, *, context: str) -> tuple[tuple[int, int], ...]:
    count = int(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    if count < 16 or len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) < 16:
        raise StageBPECompositionError(f"{context} does not carry all 16 PE directories")
    return tuple(
        (int(item.VirtualAddress), int(item.Size))
        for item in pe.OPTIONAL_HEADER.DATA_DIRECTORY[:16]
    )


def _validate_pe32_identity(pe: pefile.PE, *, context: str) -> None:
    if int(pe.FILE_HEADER.Machine) != 0x14C:
        raise StageBPECompositionError(f"{context} is not i386")
    if int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
        raise StageBPECompositionError(f"{context} is not PE32")
    if int(pe.FILE_HEADER.SizeOfOptionalHeader) < 224:
        raise StageBPECompositionError(f"{context} PE32 optional header is truncated")


def _load_contract(
    source: Path | str | Mapping[str, Any] | StageALoadImageContract,
) -> StageALoadImageContract:
    if isinstance(source, StageALoadImageContract):
        source.validate()
        return source
    if isinstance(source, Mapping):
        return StageALoadImageContract.parse(source)
    if isinstance(source, (str, Path)):
        return load_stage_a_load_image_contract(Path(source))
    raise StageBPECompositionError(
        "load-image contract must be a path, object, or StageALoadImageContract"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StageBPECompositionError(f"JSON object contains duplicate field {key!r}")
        result[key] = value
    return result


def _load_anchor_manifest(
    source: Path | str | Mapping[str, Any] | ExecutableAnchorManifest,
) -> ExecutableAnchorManifest:
    if isinstance(source, ExecutableAnchorManifest):
        return ExecutableAnchorManifest.parse(source.to_payload())
    if isinstance(source, Mapping):
        return ExecutableAnchorManifest.parse(source)
    if not isinstance(source, (str, Path)):
        raise StageBPECompositionError(
            "anchor manifest must be a path, object, or ExecutableAnchorManifest"
        )
    path = Path(source)
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except StageBPECompositionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageBPECompositionError(f"cannot read anchor manifest {path}: {exc}") from exc
    return ExecutableAnchorManifest.parse(_mapping(payload, "executable-anchor manifest"))


def _load_relocation_inventory(
    source: Path | str | Mapping[str, Any] | PayloadRelocationInventory,
) -> PayloadRelocationInventory:
    if isinstance(source, PayloadRelocationInventory):
        return PayloadRelocationInventory.parse(source.to_payload())
    if isinstance(source, Mapping):
        return PayloadRelocationInventory.parse(source)
    if not isinstance(source, (str, Path)):
        raise StageBPECompositionError(
            "payload relocation inventory must be a path, object, or "
            "PayloadRelocationInventory"
        )
    path = Path(source)
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except StageBPECompositionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageBPECompositionError(
            f"cannot read payload relocation inventory {path}: {exc}"
        ) from exc
    return PayloadRelocationInventory.parse(
        _mapping(payload, "payload relocation inventory")
    )


def _load_payload(source: Path | str | bytes | bytearray) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    elif isinstance(source, (str, Path)):
        path = Path(source)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise StageBPECompositionError(f"cannot read payload PE {path}: {exc}") from exc
    else:
        raise StageBPECompositionError("payload PE must be a path or bytes")
    if not data:
        raise StageBPECompositionError("payload PE is empty")
    return data


def _validate_original_layout(
    contract: StageALoadImageContract,
) -> tuple[
    pefile.PE,
    tuple[_Section, ...],
    int,
    int,
    int,
    tuple[tuple[int, int], ...],
]:
    if contract.format != STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT:
        raise StageBPECompositionError("unsupported Stage A load-image contract format")
    if (
        contract.identity.machine != "i386"
        or contract.identity.bitness != 32
        or contract.identity.pointer_width != 4
    ):
        raise StageBPECompositionError("Stage B PE composition requires an i386 PE32 contract")

    header_bytes = contract.runtime_headers.data
    pe = _pe_from_bytes(header_bytes, context="contract runtime headers")
    _validate_pe32_identity(pe, context="contract runtime headers")
    sections = _sections_from_pe(pe)
    if len(sections) != len(contract.sections):
        raise StageBPECompositionError("contract raw section layout is missing or incomplete")

    symbol_pointer = int(pe.FILE_HEADER.PointerToSymbolTable)
    symbol_count = int(pe.FILE_HEADER.NumberOfSymbols)
    if bool(symbol_pointer) != bool(symbol_count):
        raise StageBPECompositionError(
            "contract COFF symbol-table pointer/count are inconsistent"
        )

    for raw_section, section, typed in zip(pe.sections, sections, contract.sections):
        if any(
            int(value)
            for value in (
                raw_section.PointerToRelocations,
                raw_section.PointerToLinenumbers,
                raw_section.NumberOfRelocations,
                raw_section.NumberOfLinenumbers,
            )
        ):
            raise StageBPECompositionError(
                f"contract section {section.index} has unsupported COFF file records"
            )
        observed = (
            section.index,
            section.name,
            section.rva,
            section.virtual_size,
            section.mapped_size,
            section.raw_size,
            section.characteristics,
            section.executable,
        )
        expected = (
            typed.index,
            typed.name,
            typed.rva,
            typed.virtual_size,
            typed.mapped_size,
            typed.raw_size,
            typed.characteristics,
            typed.executable,
        )
        if observed != expected:
            raise StageBPECompositionError(
                f"contract section {typed.index} raw layout disagrees with typed metadata"
            )
        if section.raw_size:
            if section.raw_pointer == 0:
                raise StageBPECompositionError(
                    f"contract section {section.index} is missing its raw file pointer"
                )
            if section.raw_end > contract.identity.file_size:
                raise StageBPECompositionError(
                    f"contract section {section.index} raw layout exceeds bound file size"
                )
        elif section.raw_pointer != 0:
            raise StageBPECompositionError(
                f"contract section {section.index} has a raw pointer without raw bytes"
            )
        if not section.executable and section.raw_size:
            if len(typed.initialized) != 1 or len(typed.initialized[0].data) != section.raw_size:
                raise StageBPECompositionError(
                    f"contract section {section.index} lacks exact initialized raw bytes"
                )

    _require_disjoint(
        [
            (section.raw_pointer, section.raw_end, str(section.index))
            for section in sections
            if section.raw_size
        ],
        context="contract raw section",
    )
    file_alignment = int(pe.OPTIONAL_HEADER.FileAlignment)
    section_alignment = int(pe.OPTIONAL_HEADER.SectionAlignment)
    size_of_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if size_of_headers != len(header_bytes):
        raise StageBPECompositionError("contract runtime headers do not exactly cover SizeOfHeaders")
    if size_of_headers % file_alignment:
        raise StageBPECompositionError("contract SizeOfHeaders is not file aligned")

    section_table_offset = (
        int(pe.DOS_HEADER.e_lfanew) + 4 + 20 + int(pe.FILE_HEADER.SizeOfOptionalHeader)
    )
    if section_table_offset + len(sections) * 40 > size_of_headers:
        raise StageBPECompositionError("contract section table lies outside SizeOfHeaders")
    directories = _directories(pe, context="contract runtime headers")
    if directories[_DIRECTORY_SECURITY] != (0, 0):
        raise StageBPECompositionError(
            "contract security directory needs original file bytes absent from the load-image contract"
        )
    return (
        pe,
        sections,
        section_table_offset,
        file_alignment,
        section_alignment,
        directories,
    )


def _validate_payload(
    payload: bytes,
    *,
    contract: StageALoadImageContract,
    original_sections: tuple[_Section, ...],
    file_alignment: int,
    section_alignment: int,
) -> tuple[pefile.PE, tuple[_Section, ...], tuple[tuple[int, int], ...]]:
    pe = _pe_from_bytes(payload, context="payload")
    _validate_pe32_identity(pe, context="payload")
    if int(pe.OPTIONAL_HEADER.ImageBase) != contract.identity.preferred_base:
        raise StageBPECompositionError("payload image base differs from the Stage A contract")
    if int(pe.OPTIONAL_HEADER.FileAlignment) != file_alignment:
        raise StageBPECompositionError("payload FileAlignment differs from the contract")
    if int(pe.OPTIONAL_HEADER.SectionAlignment) != section_alignment:
        raise StageBPECompositionError("payload SectionAlignment differs from the contract")
    directories = _directories(pe, context="payload")
    forbidden = (
        (_DIRECTORY_IMPORT, "imports"),
        (_DIRECTORY_TLS, "TLS"),
        (_DIRECTORY_IAT, "IAT"),
        (_DIRECTORY_DELAY_IMPORT, "delay imports"),
    )
    for index, name in forbidden:
        if directories[index] != (0, 0):
            raise StageBPECompositionError(f"payload has forbidden {name}")

    sections = _sections_from_pe(pe)
    if not sections:
        raise StageBPECompositionError("payload has no sections")
    if len(sections) != int(pe.FILE_HEADER.NumberOfSections):
        raise StageBPECompositionError("payload section table is truncated")
    for section in sections:
        if section.mapped_size == 0:
            raise StageBPECompositionError(f"payload section {section.index} has no mapped extent")
        if section.rva < contract.identity.image_size:
            raise StageBPECompositionError(
                f"payload section {section.index} is not at a high RVA"
            )
        if section.rva % section_alignment:
            raise StageBPECompositionError(
                f"payload section {section.index} RVA is not section aligned"
            )
        if section.mapped_end > _UINT32_MAX:
            raise StageBPECompositionError(
                f"payload section {section.index} exceeds PE32 RVA space"
            )
        if section.raw_size:
            if section.raw_pointer == 0 or section.raw_pointer % file_alignment:
                raise StageBPECompositionError(
                    f"payload section {section.index} has an invalid raw pointer"
                )
            if section.raw_size % file_alignment or section.raw_end > len(payload):
                raise StageBPECompositionError(
                    f"payload section {section.index} raw bytes are unavailable"
                )
        elif section.raw_pointer != 0:
            raise StageBPECompositionError(
                f"payload section {section.index} has a pointer without raw bytes"
            )

    _require_disjoint(
        [(section.rva, section.mapped_end, str(section.index)) for section in sections],
        context="payload mapped section",
    )
    _require_disjoint(
        [
            (section.raw_pointer, section.raw_end, str(section.index))
            for section in sections
            if section.raw_size
        ],
        context="payload raw section",
    )
    _require_disjoint(
        [
            (section.rva, section.mapped_end, f"payload:{section.index}")
            for section in sections
        ]
        + [
            (section.rva, section.mapped_end, f"contract:{section.index}")
            for section in original_sections
        ],
        context="composed mapped section",
    )
    expected_payload_size = _align_up(
        max(section.mapped_end for section in sections), section_alignment
    )
    if int(pe.OPTIONAL_HEADER.SizeOfImage) != expected_payload_size:
        raise StageBPECompositionError("payload SizeOfImage does not exactly cover its sections")
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    if entry_rva and len(
        [
            section
            for section in sections
            if section.executable and section.rva <= entry_rva < section.mapped_end
        ]
    ) != 1:
        raise StageBPECompositionError("payload entry point is not in one executable section")
    relocation_present = directories[_DIRECTORY_BASE_RELOCATION] != (0, 0)
    relocations_stripped = bool(
        int(pe.FILE_HEADER.Characteristics) & _IMAGE_FILE_RELOCS_STRIPPED
    )
    if relocation_present == relocations_stripped:
        raise StageBPECompositionError(
            "payload relocation directory disagrees with RELOCS_STRIPPED"
        )
    return pe, sections, directories


def _anchor_section(
    anchor: ExecutableAnchor, sections: tuple[_Section, ...]
) -> _Section:
    matches = [
        section
        for section in sections
        if section.executable
        and section.raw_size
        and section.rva <= anchor.rva
        and anchor.end_rva <= section.rva + section.raw_size
    ]
    if len(matches) != 1:
        raise StageBPECompositionError(
            f"anchor at RVA 0x{anchor.rva:x} is not bounded by exactly one executable raw section"
        )
    return matches[0]


def _validate_anchors(
    manifest: ExecutableAnchorManifest,
    *,
    contract: StageALoadImageContract,
    sections: tuple[_Section, ...],
) -> dict[int, tuple[ExecutableAnchor, _Section]]:
    if manifest.image_base != contract.identity.preferred_base:
        raise StageBPECompositionError("anchor manifest image base differs from the contract")
    starts = [anchor.rva for anchor in manifest.anchors]
    if len(set(starts)) != len(starts):
        raise StageBPECompositionError("anchor RVAs are not unique")
    _require_disjoint(
        [(anchor.rva, anchor.end_rva, f"0x{anchor.rva:x}") for anchor in manifest.anchors],
        context="executable anchor",
    )
    indexed = {
        anchor.rva: (anchor, _anchor_section(anchor, sections))
        for anchor in manifest.anchors
    }
    required_roots = (
        ((manifest.entry_anchor_rva, "entry"),)
        + tuple((rva, "TLS callback") for rva in manifest.tls_callback_anchor_rvas)
        + tuple((rva, "callback") for rva in manifest.callback_anchor_rvas)
    )
    for rva, kind in required_roots:
        if rva not in indexed:
            raise StageBPECompositionError(
                f"{kind} RVA 0x{rva:x} does not name an exact supplied anchor"
            )
    expected_tls = tuple(
        callback.rva for callback in (() if contract.tls is None else contract.tls.callbacks)
    )
    if manifest.tls_callback_anchor_rvas != expected_tls:
        raise StageBPECompositionError(
            "anchor manifest TLS callback order differs from the load-image contract"
        )
    all_roots = (
        (manifest.entry_anchor_rva,)
        + manifest.tls_callback_anchor_rvas
        + manifest.callback_anchor_rvas
    )
    if len(set(all_roots)) != len(all_roots):
        raise StageBPECompositionError("entry/TLS/callback root RVAs are not unique")
    return indexed


def _classify_executable_bytes(
    sections: tuple[_Section, ...],
    indexed_anchors: Mapping[int, tuple[ExecutableAnchor, _Section]],
) -> tuple[ByteClassification, ...]:
    result: list[ByteClassification] = []

    def append_range(
        section: _Section, kind: str, start: int, data: bytes
    ) -> None:
        if not data:
            return
        result.append(
            ByteClassification(
                section_index=section.index,
                section_name=section.name,
                kind=kind,
                rva=start,
                size=len(data),
                bytes_sha256=sha256_bytes(data),
            )
        )

    for section in sections:
        if not section.executable or not section.raw_size:
            continue
        anchors = sorted(
            (
                anchor
                for anchor, anchor_section in indexed_anchors.values()
                if anchor_section.index == section.index
            ),
            key=lambda item: item.rva,
        )
        logical_end = section.rva + (
            min(section.virtual_size, section.raw_size)
            if section.virtual_size
            else section.raw_size
        )
        raw_end = section.rva + section.raw_size

        def append_default(start: int, end: int) -> None:
            if start < min(end, logical_end):
                stop = min(end, logical_end)
                append_range(
                    section,
                    "trap",
                    start,
                    bytes([_TRAP_BYTE]) * (stop - start),
                )
                start = stop
            if start < end:
                append_range(
                    section,
                    "padding",
                    start,
                    bytes([_PADDING_BYTE]) * (end - start),
                )

        cursor = section.rva
        for anchor in anchors:
            append_default(cursor, anchor.rva)
            append_range(section, "anchor", anchor.rva, anchor.bytes)
            cursor = anchor.end_rva
        append_default(cursor, raw_end)
        classified_size = sum(
            item.size for item in result if item.section_index == section.index
        )
        if classified_size != section.raw_size:
            raise StageBPECompositionError(
                f"executable section {section.index} raw bytes are not totally classified"
            )
    expected = sum(
        section.raw_size for section in sections if section.executable
    )
    if sum(item.size for item in result) != expected:
        raise StageBPECompositionError("not all executable raw bytes are classified")
    return tuple(result)


def _section_containing_rva(
    sections: Sequence[_Section],
    rva: int,
    size: int,
    *,
    context: str,
    require_raw: bool,
) -> _Section:
    if size <= 0 or rva > _UINT32_MAX - size:
        raise StageBPECompositionError(f"{context} has an invalid RVA span")
    matches = [
        section
        for section in sections
        if section.rva <= rva
        and rva + size <= section.mapped_end
        and (
            not require_raw
            or (
                section.raw_size
                and rva + size <= section.rva + section.raw_size
            )
        )
    ]
    if len(matches) != 1:
        backing = "raw-backed " if require_raw else "mapped "
        raise StageBPECompositionError(
            f"{context} is not contained by exactly one {backing}section"
        )
    return matches[0]


def _read_payload_rva(
    payload: bytes,
    sections: Sequence[_Section],
    rva: int,
    size: int,
    *,
    context: str,
) -> bytes:
    section = _section_containing_rva(
        sections, rva, size, context=context, require_raw=True
    )
    offset = section.raw_pointer + rva - section.rva
    result = payload[offset : offset + size]
    if len(result) != size:
        raise StageBPECompositionError(f"{context} raw bytes are truncated")
    return result


def _shift_original_raw_pointers(
    sections: tuple[_Section, ...], delta: int
) -> tuple[_Section, ...]:
    if delta < 0:
        raise StageBPECompositionError("original raw-pointer shift is negative")
    shifted: list[_Section] = []
    for section in sections:
        raw_pointer = 0
        if section.raw_size:
            raw_pointer = section.raw_pointer + delta
            if raw_pointer > _UINT32_MAX - section.raw_size:
                raise StageBPECompositionError(
                    f"shifted original section {section.index} exceeds PE32 file offsets"
                )
        shifted.append(
            _Section(
                index=section.index,
                name_bytes=section.name_bytes,
                virtual_size=section.virtual_size,
                rva=section.rva,
                raw_size=section.raw_size,
                raw_pointer=raw_pointer,
                characteristics=section.characteristics,
            )
        )
    return tuple(shifted)


def _read_contract_rva(
    contract: StageALoadImageContract,
    sections: tuple[_Section, ...],
    rva: int,
    size: int,
    *,
    context: str,
) -> bytes:
    if rva < 0 or size < 0 or rva > _UINT32_MAX - size:
        raise StageBPECompositionError(f"{context} exceeds PE32 RVA space")
    headers = contract.runtime_headers.data
    if rva + size <= len(headers):
        return headers[rva : rva + size]
    matches = [
        (section, contract.sections[section.index])
        for section in sections
        if section.raw_size
        and section.rva <= rva
        and rva + size <= section.rva + section.raw_size
    ]
    if len(matches) != 1:
        raise StageBPECompositionError(
            f"{context} is not contained by exactly one contracted raw section"
        )
    section, typed = matches[0]
    if section.executable or len(typed.initialized) != 1:
        raise StageBPECompositionError(
            f"{context} bytes are unavailable from the load-image contract"
        )
    initialized = typed.initialized[0]
    offset = rva - initialized.rva
    result = initialized.data[offset : offset + size]
    if offset < 0 or len(result) != size:
        raise StageBPECompositionError(f"{context} contracted bytes are truncated")
    return result


def _plan_file_offset_rewrites(
    contract: StageALoadImageContract,
    sections: tuple[_Section, ...],
    directories: tuple[tuple[int, int], ...],
    *,
    raw_pointer_shift: int,
) -> tuple[_FileOffsetRewrite, ...]:
    debug_rva, debug_size = directories[_DIRECTORY_DEBUG]
    if (debug_rva, debug_size) == (0, 0):
        return ()
    if not debug_rva or not debug_size or debug_size % 28:
        raise StageBPECompositionError(
            "contract debug directory is partial or has an invalid size"
        )
    raw = _read_contract_rva(
        contract,
        sections,
        debug_rva,
        debug_size,
        context="contract debug directory",
    )
    rewrites: list[_FileOffsetRewrite] = []
    for index in range(debug_size // 28):
        entry_offset = index * 28
        size_of_data, address_of_raw_data, pointer_to_raw_data = struct.unpack_from(
            "<III", raw, entry_offset + 16
        )
        if pointer_to_raw_data == 0:
            continue
        if address_of_raw_data == 0 or size_of_data == 0:
            raise StageBPECompositionError(
                f"contract debug entry {index} has unbound file-only data"
            )
        section = _section_containing_rva(
            sections,
            address_of_raw_data,
            size_of_data,
            context=f"contract debug entry {index} data",
            require_raw=True,
        )
        expected_pointer = (
            section.raw_pointer + address_of_raw_data - section.rva
        )
        if pointer_to_raw_data != expected_pointer:
            raise StageBPECompositionError(
                f"contract debug entry {index} file pointer disagrees with its RVA"
            )
        new_pointer = pointer_to_raw_data + raw_pointer_shift
        if new_pointer > _UINT32_MAX:
            raise StageBPECompositionError(
                f"shifted debug entry {index} exceeds PE32 file offsets"
            )
        field_rva = debug_rva + entry_offset + 24
        _section_containing_rva(
            sections,
            field_rva,
            4,
            context=f"contract debug entry {index} file-pointer field",
            require_raw=True,
        )
        rewrites.append(
            _FileOffsetRewrite(
                kind="debug_pointer_to_raw_data",
                index=index,
                field_rva=field_rva,
                old_value=pointer_to_raw_data,
                new_value=new_pointer,
            )
        )
    return tuple(rewrites)


def _parse_payload_relocation_directory(
    payload: bytes,
    sections: tuple[_Section, ...],
    directory: tuple[int, int],
    *,
    image_base: int,
) -> PayloadRelocationInventory:
    directory_rva, directory_size = directory
    if (directory_rva, directory_size) == (0, 0):
        return PayloadRelocationInventory(
            payload_sha256=sha256_bytes(payload),
            image_base=image_base,
            relocations=(),
        )
    if not directory_rva or directory_size < 8:
        raise StageBPECompositionError(
            "payload base-relocation directory is partial or too small"
        )
    raw = _read_payload_rva(
        payload,
        sections,
        directory_rva,
        directory_size,
        context="payload base-relocation directory",
    )
    relocations: list[PayloadRelocation] = []
    cursor = 0
    previous_page = -1
    seen_targets: set[int] = set()
    while cursor < len(raw):
        if len(raw) - cursor < 8:
            raise StageBPECompositionError(
                "payload base-relocation directory has a partial block"
            )
        page_rva, block_size = struct.unpack_from("<II", raw, cursor)
        if page_rva % 0x1000:
            raise StageBPECompositionError(
                "payload base-relocation block page is not 4 KiB aligned"
            )
        if page_rva <= previous_page:
            raise StageBPECompositionError(
                "payload base-relocation blocks are duplicated or unordered"
            )
        if (
            block_size < 8
            or block_size % 4
            or cursor + block_size > len(raw)
        ):
            raise StageBPECompositionError(
                "payload base-relocation block has an invalid size"
            )
        slot_count = (block_size - 8) // 2
        slots = struct.unpack_from(
            "<" + "H" * slot_count, raw, cursor + 8
        )
        for slot in slots:
            relocation_type = slot >> 12
            offset = slot & 0xFFF
            if relocation_type == _IMAGE_REL_BASED_ABSOLUTE:
                continue
            if relocation_type != _IMAGE_REL_BASED_HIGHLOW:
                raise StageBPECompositionError(
                    "payload base-relocation directory contains unsupported "
                    f"PE32 relocation type {relocation_type}"
                )
            target_rva = page_rva + offset
            if target_rva in seen_targets:
                raise StageBPECompositionError(
                    "payload base-relocation target is duplicated"
                )
            preferred = int.from_bytes(
                _read_payload_rva(
                    payload,
                    sections,
                    target_rva,
                    4,
                    context="payload HIGHLOW relocation target",
                ),
                "little",
            )
            seen_targets.add(target_rva)
            relocations.append(
                PayloadRelocation(
                    rva=target_rva,
                    preferred_value=preferred,
                )
            )
        previous_page = page_rva
        cursor += block_size
    return PayloadRelocationInventory(
        payload_sha256=sha256_bytes(payload),
        image_base=image_base,
        relocations=tuple(sorted(relocations, key=lambda item: item.rva)),
    )


def _validate_payload_relocation_inventory(
    inventory: PayloadRelocationInventory,
    *,
    payload: bytes,
    payload_sections: tuple[_Section, ...],
    image_base: int,
) -> None:
    if inventory.payload_sha256 != sha256_bytes(payload):
        raise StageBPECompositionError(
            "payload relocation inventory hash does not bind the payload PE"
        )
    if inventory.image_base != image_base:
        raise StageBPECompositionError(
            "payload relocation inventory image base differs from the payload"
        )
    spans: list[tuple[int, int, str]] = []
    for index, relocation in enumerate(inventory.relocations):
        _section_containing_rva(
            payload_sections,
            relocation.rva,
            relocation.width,
            context=f"payload relocation inventory entry {index}",
            require_raw=True,
        )
        observed = int.from_bytes(
            _read_payload_rva(
                payload,
                payload_sections,
                relocation.rva,
                relocation.width,
                context=f"payload relocation inventory entry {index}",
            ),
            "little",
        )
        if observed != relocation.preferred_value:
            raise StageBPECompositionError(
                f"payload relocation inventory entry {index} preferred value "
                "disagrees with payload bytes"
            )
        spans.append(
            (
                relocation.rva,
                relocation.rva + relocation.width,
                str(index),
            )
        )
    _require_disjoint(spans, context="payload relocation inventory target")


def _translate_payload_rva(
    rva: int,
    *,
    source_sections: tuple[_Section, ...],
    output_sections: tuple[_Section, ...],
    context: str,
) -> int:
    source = _section_containing_rva(
        source_sections, rva, 1, context=context, require_raw=False
    )
    output = output_sections[source.index]
    return output.rva + rva - source.rva


def _translate_payload_preferred_value(
    value: int,
    *,
    image_base: int,
    source_sections: tuple[_Section, ...],
    output_sections: tuple[_Section, ...],
) -> int:
    if value < image_base:
        return value
    rva = value - image_base
    matches = [
        section for section in source_sections if section.rva <= rva < section.mapped_end
    ]
    if not matches:
        return value
    if len(matches) != 1:
        raise StageBPECompositionError(
            "payload relocation preferred value has ambiguous section ownership"
        )
    translated = image_base + output_sections[matches[0].index].rva + rva - matches[0].rva
    if translated > _UINT32_MAX:
        raise StageBPECompositionError(
            "translated payload relocation preferred value exceeds PE32"
        )
    return translated


def _merge_relocations(
    *,
    contract: StageALoadImageContract,
    anchor_manifest: ExecutableAnchorManifest,
    original_sections: tuple[_Section, ...],
    payload_inventory: PayloadRelocationInventory,
    payload_sections: tuple[_Section, ...],
    output_payload_sections: tuple[_Section, ...],
) -> tuple[_MergedRelocation, ...]:
    merged: list[_MergedRelocation] = []
    anchors = tuple(anchor_manifest.anchors)
    for block in contract.relocations:
        for relocation in block.relocations:
            if relocation.type == _IMAGE_REL_BASED_ABSOLUTE:
                continue
            if (
                relocation.type != _IMAGE_REL_BASED_HIGHLOW
                or relocation.kind != "highlow"
                or relocation.width != 4
                or relocation.target_rva is None
                or relocation.preferred_value is None
                or relocation.adjustment is not None
            ):
                raise StageBPECompositionError(
                    "original image contains an unsupported non-HIGHLOW PE32 relocation"
                )
            _section_containing_rva(
                original_sections,
                relocation.target_rva,
                relocation.width,
                context="original HIGHLOW relocation target",
                require_raw=False,
            )
            overlapping = [
                anchor
                for anchor in anchors
                if relocation.target_rva < anchor.end_rva
                and anchor.rva < relocation.target_rva + relocation.width
            ]
            if overlapping:
                if len(overlapping) != 1 or not (
                    overlapping[0].rva <= relocation.target_rva
                    and relocation.target_rva + relocation.width
                    <= overlapping[0].end_rva
                ):
                    raise StageBPECompositionError(
                        "original HIGHLOW relocation target is only partially covered "
                        "by an executable anchor"
                    )
                # The anchor replaces every byte the loader would have patched.
                # Its relative jump and NOP suffix contain no preferred-base value.
                continue
            merged.append(
                _MergedRelocation(
                    source_target_rva=relocation.target_rva,
                    target_rva=relocation.target_rva,
                    type=relocation.type,
                    kind=relocation.kind,
                    width=relocation.width,
                    preferred_value=relocation.preferred_value,
                    adjustment=None,
                    source="original",
                )
            )

    for relocation in payload_inventory.relocations:
        target_rva = _translate_payload_rva(
            relocation.rva,
            source_sections=payload_sections,
            output_sections=output_payload_sections,
            context="payload HIGHLOW relocation target",
        )
        merged.append(
            _MergedRelocation(
                source_target_rva=relocation.rva,
                target_rva=target_rva,
                type=relocation.type,
                kind=relocation.kind,
                width=relocation.width,
                preferred_value=_translate_payload_preferred_value(
                    relocation.preferred_value,
                    image_base=contract.identity.preferred_base,
                    source_sections=payload_sections,
                    output_sections=output_payload_sections,
                ),
                adjustment=None,
                source="payload",
            )
        )

    ordered = tuple(sorted(merged, key=lambda item: (item.target_rva, item.source)))
    _require_disjoint(
        [
            (
                item.target_rva,
                item.target_rva + item.width,
                f"{item.source}:0x{item.source_target_rva:x}",
            )
            for item in ordered
        ],
        context="merged relocation target",
    )
    return ordered


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
) -> PECompositionPlan:
    """Validate all inputs and return a deterministic, write-free plan."""

    contract = _load_contract(load_image_contract)
    anchors = _load_anchor_manifest(anchor_manifest)
    payload = _load_payload(payload_pe)
    (
        original_pe,
        contract_original_sections,
        section_table_offset,
        file_alignment,
        section_alignment,
        original_directories,
    ) = _validate_original_layout(contract)
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
        contract_original_sections, indexed_anchors
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
    relocation_data = _encode_relocation_directory(merged_relocations)

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
        if plan.relocation_data or plan.merged_relocations:
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
    struct.pack_into(
        "<H",
        image,
        file_header_offset + 18,
        characteristics & ~_IMAGE_FILE_RELOCS_STRIPPED,
    )
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
    struct.pack_into(
        "<H",
        image,
        optional_offset + 70,
        dll_characteristics | _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    )
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
    if int(pe.FILE_HEADER.Characteristics) & _IMAGE_FILE_RELOCS_STRIPPED:
        raise StageBPECompositionError("composed candidate strips base relocations")
    if not int(pe.OPTIONAL_HEADER.DllCharacteristics) & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        raise StageBPECompositionError("composed candidate does not enable dynamic base")
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
        },
        "policy": {
            "executable_default_trap_byte_hex": bytes([_TRAP_BYTE]).hex(),
            "executable_raw_padding_byte_hex": bytes([_PADDING_BYTE]).hex(),
            "payload_layout": "append-raw-preserve-linked-rva",
            "fixed_base": False,
            "dynamic_base": True,
            "relocation_merge": "canonical-pe32-highlow",
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
    out_dir: Path | str,
) -> dict[str, Any]:
    """Compose and emit ``candidate.exe`` and a non-authoritative manifest."""

    plan = plan_stage_b_pe_composition(
        load_image_contract=load_image_contract,
        payload_pe=payload_pe,
        anchor_manifest=anchor_manifest,
        payload_relocation_inventory=payload_relocation_inventory,
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
