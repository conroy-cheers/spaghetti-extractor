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

from ..artifact_formats import (
    PAYLOAD_RELOCATION_INVENTORY_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
)
from ..roundtrip_fuzz.image_contract import (
    STAGE_A_LOAD_IMAGE_CONTRACT_FORMAT,
    StageALoadImageContract,
    load_stage_a_load_image_contract,
)
from ..recovered_executable_data import (
    RecoveredExecutableDataContract,
    RecoveredExecutableDataRange,
    load_recovered_executable_data_contract,
)
from ..util import sha256_bytes


EXECUTABLE_ANCHOR_MANIFEST_FORMAT = "stage-b-pe-executable-anchor-manifest-v1"
CANDIDATE_FILENAME = "candidate.exe"
COMPOSITION_MANIFEST_FILENAME = "composition-manifest.json"

_IMAGE_FILE_RELOCS_STRIPPED = 0x0001
_IMAGE_SCN_CNT_CODE = 0x00000020
_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
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

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_READ)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_WRITE)


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
    recovered_executable_data: RecoveredExecutableDataContract | None
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
    dynamic_base: bool
    runtime_relocations: bool
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


def _load_recovered_executable_data(
    source: Path | str | Mapping[str, Any] | RecoveredExecutableDataContract | None,
) -> RecoveredExecutableDataContract | None:
    if source is None:
        return None
    if isinstance(source, RecoveredExecutableDataContract):
        return RecoveredExecutableDataContract.parse(source.to_payload())
    if isinstance(source, Mapping):
        return RecoveredExecutableDataContract.parse(source)
    if isinstance(source, (str, Path)):
        return load_recovered_executable_data_contract(source)
    raise StageBPECompositionError(
        "recovered executable-data contract must be a path, object, or contract"
    )


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


def _validate_recovered_executable_data(
    recovered: RecoveredExecutableDataContract | None,
    *,
    contract: StageALoadImageContract,
    sections: tuple[_Section, ...],
    indexed_anchors: Mapping[int, tuple[ExecutableAnchor, _Section]],
) -> tuple[RecoveredExecutableDataRange, ...]:
    if recovered is None:
        return ()
    if recovered.original_pe_sha256 != contract.identity.pe_sha256:
        raise StageBPECompositionError(
            "recovered executable-data contract binds a different original PE"
        )
    if recovered.image_base != contract.identity.preferred_base:
        raise StageBPECompositionError(
            "recovered executable-data image base differs from the load-image contract"
        )
    anchors = tuple(anchor for anchor, _section in indexed_anchors.values())
    for item in recovered.ranges:
        if item.section_index >= len(sections):
            raise StageBPECompositionError(
                f"recovered executable-data range {item.identity} has an invalid section"
            )
        section = sections[item.section_index]
        logical_size = (
            min(section.virtual_size, section.raw_size)
            if section.virtual_size
            else section.raw_size
        )
        if (
            item.section_name != section.name
            or not section.executable
            or not section.readable
            or section.writable
            or not (
                section.rva <= item.rva_start
                and item.rva_end <= section.rva + logical_size
            )
        ):
            raise StageBPECompositionError(
                f"recovered executable-data range {item.identity} is not immutable "
                "initialized data in its declared executable section"
            )
        if any(
            item.rva_start < anchor.end_rva and anchor.rva < item.rva_end
            for anchor in anchors
        ):
            raise StageBPECompositionError(
                f"recovered executable-data range {item.identity} overlaps an anchor"
            )
    return recovered.ranges


def _classify_executable_bytes(
    sections: tuple[_Section, ...],
    indexed_anchors: Mapping[int, tuple[ExecutableAnchor, _Section]],
    recovered_data: Sequence[RecoveredExecutableDataRange] = (),
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
        classified_ranges = [
            (anchor.rva, anchor.end_rva, "anchor", anchor.bytes)
            for anchor, anchor_section in indexed_anchors.values()
            if anchor_section.index == section.index
        ]
        classified_ranges.extend(
            (item.rva_start, item.rva_end, "recovered_data", item.data)
            for item in recovered_data
            if item.section_index == section.index
        )
        classified_ranges.sort(key=lambda item: item[0])
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
        for start, end, kind, data in classified_ranges:
            if start < cursor or end - start != len(data):
                raise StageBPECompositionError(
                    f"executable section {section.index} has overlapping classifications"
                )
            append_default(cursor, start)
            append_range(section, kind, start, data)
            cursor = end
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
