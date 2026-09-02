"""Linked-library artifact parsers."""

from __future__ import annotations

import copy
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_CATALOG_LOCK_FORMAT,
    LIBRARY_HYPOTHESIS_SET_FORMAT,
    LIBRARY_INTERFACE_CATALOG_FORMAT,
    LIBRARY_MATCH_EVIDENCE_FORMAT,
    LIBRARY_REPLACEMENT_PLAN_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
    LINKED_INTERFACE_QUALIFICATION_FORMAT,
    LINKED_ISLAND_MANIFEST_FORMAT,
    LINKED_ISLAND_MANIFEST_V2_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
    MACHINE_IR_FORMAT,
)
from ..errors import ToolkitInputError
from ..pe32.image import parse_pe_image
from .contracts import (
    validate_linked_island_manifest as _validate_linked_island_contract,
)
from ..util import sha256_file, write_json


from .matching_support import (
    _canonical_sha256,
    _object,
    _trim_x86_function_alignment,
)
from .model import (
    LinkedLibraryError,
    _AR_MAGIC,
    _COFF_RELOCATION_WIDTHS_AMD64,
    _COFF_RELOCATION_WIDTHS_I386,
    _PE_MACHINE_AMD64,
    _PE_MACHINE_I386,
    _THIN_AR_MAGIC,
)

def _index_artifact_blob(*, data: bytes, label: str, source_path: Path) -> dict[str, Any]:
    if data.startswith(_THIN_AR_MAGIC):
        return {
            "kind": "thin_archive",
            "status": "incomplete",
            "sha256": sha256(data).hexdigest(),
            "issues": [{"code": "thin_archive_external_members", "message": "thin archives require an explicit materialized member manifest"}],
        }
    if data.startswith(_AR_MAGIC):
        return _index_archive(data, label=label)
    if data.startswith(b"MZ"):
        return _index_pe(source_path)
    if _looks_like_coff(data):
        return _index_coff(data, label=label)
    if _looks_like_omf(data):
        return _index_omf(data, label=label)
    return {
        "kind": "opaque",
        "status": "indexed",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "function_fingerprints": [],
    }


def _index_archive(data: bytes, *, label: str) -> dict[str, Any]:
    offset = len(_AR_MAGIC)
    long_names = b""
    members: list[dict[str, Any]] = []
    while offset < len(data):
        if offset + 60 > len(data):
            raise LinkedLibraryError(f"archive {label} has a truncated member header")
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise LinkedLibraryError(f"archive {label} has an invalid member header")
        raw_name = header[:16].decode("ascii", errors="replace").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip() or "0")
        except ValueError as error:
            raise LinkedLibraryError(f"archive {label} has an invalid member size") from error
        start = offset + 60
        end = start + size
        if end > len(data):
            raise LinkedLibraryError(f"archive {label} has a truncated member")
        body = data[start:end]
        name = raw_name.rstrip("/")
        if raw_name == "//":
            long_names = body
            offset = end + (end & 1)
            continue
        if raw_name.startswith("#1/"):
            name_size = int(raw_name[3:])
            if name_size > len(body):
                raise LinkedLibraryError(f"archive {label} has a bad BSD member name")
            name = body[:name_size].decode("utf-8", errors="replace").rstrip("\0")
            body = body[name_size:]
        elif raw_name.startswith("/") and raw_name[1:].isdigit() and long_names:
            name_offset = int(raw_name[1:])
            if name_offset >= len(long_names):
                raise LinkedLibraryError(f"archive {label} has a bad GNU name offset")
            name_end = long_names.find(b"/\n", name_offset)
            if name_end < 0:
                name_end = long_names.find(b"\0", name_offset)
            if name_end < 0:
                name_end = len(long_names)
            name = long_names[name_offset:name_end].decode("utf-8", errors="replace")
        special = raw_name in {"/", "//"} or raw_name.startswith("/ ")
        if special:
            nested = {
                "kind": "archive_index",
                "status": "indexed",
                "function_fingerprints": [],
            }
        elif body.startswith(b"MZ"):
            nested = {
                "kind": "pe_image_member",
                "status": "incomplete",
                "sha256": sha256(body).hexdigest(),
                "bytes": len(body),
                "function_fingerprints": [],
                "issues": [
                    {
                        "code": "embedded_pe_requires_materialization",
                        "message": (
                            "archive-contained PE images must be declared as "
                            "standalone content-bound artifacts"
                        ),
                    }
                ],
            }
        else:
            nested = _index_artifact_blob(
                data=body,
                label=f"{label}:{name}",
                source_path=Path(name),
            )
        members.append(
            {
                "name": name or raw_name,
                "sha256": sha256(body).hexdigest(),
                "bytes": len(body),
                "index": nested,
            }
        )
        offset = end + (end & 1)
    return {
        "kind": "archive",
        "status": "indexed",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "members": members,
        "counts": {
            "members": len(members),
            "function_fingerprints": sum(_artifact_function_count(member["index"]) for member in members),
        },
    }


def _looks_like_coff(data: bytes) -> bool:
    if len(data) < 20:
        return False
    machine, section_count, _time, _symbols, _count, optional_size, _flags = struct.unpack_from("<HHIIIHH", data, 0)
    return machine in {_PE_MACHINE_I386, _PE_MACHINE_AMD64} and 0 < section_count < 512 and optional_size == 0


def _index_coff(data: bytes, *, label: str) -> dict[str, Any]:
    machine, section_count, timestamp, symbol_pointer, symbol_count, optional_size, flags = struct.unpack_from("<HHIIIHH", data, 0)
    section_start = 20 + optional_size
    if section_start + section_count * 40 > len(data):
        raise LinkedLibraryError(f"COFF object {label} has a truncated section table")
    string_start = symbol_pointer + symbol_count * 18
    string_size = (
        int.from_bytes(data[string_start : string_start + 4], "little")
        if string_start + 4 <= len(data)
        else 0
    )
    sections: list[dict[str, Any]] = []
    relocations_by_section: dict[int, list[dict[str, int]]] = defaultdict(list)
    for index in range(section_count):
        offset = section_start + index * 40
        header = data[offset : offset + 40]
        name = _coff_name(header[:8], data, string_start, string_size)
        virtual_size, virtual_address, raw_size, raw_pointer, reloc_pointer, _line_pointer, reloc_count, _line_count, characteristics = struct.unpack_from("<IIIIIIHHI", header, 8)
        if raw_pointer + raw_size > len(data):
            raise LinkedLibraryError(f"COFF object {label} section {name} exceeds file")
        section_bytes = data[raw_pointer : raw_pointer + raw_size]
        relocation_widths = _COFF_RELOCATION_WIDTHS_I386 if machine == _PE_MACHINE_I386 else _COFF_RELOCATION_WIDTHS_AMD64
        if reloc_pointer + reloc_count * 10 > len(data):
            raise LinkedLibraryError(f"COFF object {label} has truncated relocations")
        for relocation_index in range(reloc_count):
            relocation_offset = reloc_pointer + relocation_index * 10
            address, symbol_index, relocation_type = struct.unpack_from("<IIH", data, relocation_offset)
            relocations_by_section[index + 1].append(
                {
                    "offset": address,
                    "symbol_index": symbol_index,
                    "type": relocation_type,
                    "width": relocation_widths.get(relocation_type, 0),
                }
            )
        sections.append(
            {
                "index": index + 1,
                "name": name,
                "raw_size": raw_size,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "characteristics": characteristics,
                "contains_code": bool(characteristics & 0x20),
                "executable": bool(characteristics & 0x20000000),
                "sha256": sha256(section_bytes).hexdigest(),
                "data": section_bytes,
            }
        )
    symbols = _coff_symbols(data, symbol_pointer, symbol_count, string_start, string_size)
    symbols_by_index = {int(symbol["index"]): symbol for symbol in symbols}
    for relocations in relocations_by_section.values():
        for relocation in relocations:
            target = symbols_by_index.get(int(relocation["symbol_index"]))
            relocation["target_symbol"] = (
                str(target.get("name", "")) if target is not None else ""
            )
            relocation["target_section_number"] = (
                int(target.get("section_number", 0)) if target is not None else 0
            )
            relocation["target_storage_class"] = (
                int(target.get("storage_class", 0)) if target is not None else 0
            )
    functions = _coff_function_fingerprints(sections, symbols, relocations_by_section)
    public_sections = [
        {key: value for key, value in section.items() if key != "data"}
        for section in sections
    ]
    return {
        "kind": "coff_object",
        "status": "indexed",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "machine": "i386" if machine == _PE_MACHINE_I386 else "x86_64",
        "timestamp": timestamp,
        "characteristics": flags,
        "sections": public_sections,
        "symbols": [
            {key: value for key, value in symbol.items() if key != "aux"}
            for symbol in symbols
        ],
        "defined_symbols": sorted(
            str(symbol["name"])
            for symbol in symbols
            if int(symbol["section_number"]) > 0 and symbol["name"]
        ),
        "undefined_symbols": sorted(
            str(symbol["name"])
            for symbol in symbols
            if int(symbol["section_number"]) == 0 and symbol["name"]
        ),
        "relocations": {
            str(key): value for key, value in sorted(relocations_by_section.items())
        },
        "function_fingerprints": functions,
        "counts": {
            "sections": len(sections),
            "symbols": len(symbols),
            "relocations": sum(len(value) for value in relocations_by_section.values()),
            "function_fingerprints": len(functions),
        },
    }


def _coff_symbols(data: bytes, pointer: int, count: int, string_start: int, string_size: int) -> list[dict[str, Any]]:
    if not pointer or not count:
        return []
    if pointer + count * 18 > len(data):
        raise LinkedLibraryError("COFF object has a truncated symbol table")
    symbols = []
    index = 0
    while index < count:
        offset = pointer + index * 18
        row = data[offset : offset + 18]
        name = _coff_name(row[:8], data, string_start, string_size)
        value, section_number, symbol_type, storage_class, aux_count = struct.unpack_from("<IhHBB", row, 8)
        aux_start = offset + 18
        aux_end = aux_start + aux_count * 18
        if aux_end > pointer + count * 18:
            raise LinkedLibraryError("COFF symbol has truncated auxiliary records")
        symbols.append(
            {
                "index": index,
                "name": name,
                "value": value,
                "section_number": section_number,
                "type": symbol_type,
                "storage_class": storage_class,
                "aux_count": aux_count,
                "aux": data[aux_start:aux_end],
            }
        )
        index += 1 + aux_count
    return symbols


def _coff_function_fingerprints(
    sections: Sequence[Mapping[str, Any]],
    symbols: Sequence[Mapping[str, Any]],
    relocations: Mapping[int, Sequence[Mapping[str, int]]],
) -> list[dict[str, Any]]:
    functions: list[dict[str, Any]] = []
    by_section: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for symbol in symbols:
        section_number = int(symbol["section_number"])
        if section_number <= 0 or section_number > len(sections):
            continue
        section = sections[section_number - 1]
        function_typed = bool(int(symbol["type"]) & 0x20)
        name = str(symbol["name"])
        section_pseudo_symbol = (
            not function_typed
            and (name == str(section["name"]) or name.startswith("."))
        )
        code_like = function_typed or (
            bool(section["contains_code"])
            and int(symbol["storage_class"]) in {2, 3}
            and not section_pseudo_symbol
        )
        if code_like and symbol["name"]:
            by_section[section_number].append(symbol)
    for section_number, members in sorted(by_section.items()):
        section = sections[section_number - 1]
        data = bytes(section["data"])
        aliases_by_offset: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
        for symbol in members:
            aliases_by_offset[int(symbol["value"])].append(symbol)
        ordered_offsets = sorted(aliases_by_offset)
        ordered = [
            min(aliases_by_offset[offset], key=lambda item: str(item["name"]))
            for offset in ordered_offsets
        ]
        for position, symbol in enumerate(ordered):
            start = int(symbol["value"])
            aliases = sorted(
                {
                    str(item["name"])
                    for item in aliases_by_offset[start]
                    if item["name"]
                }
            )
            size = 0
            for alias in aliases_by_offset[start]:
                aux = bytes(alias["aux"])
                if int(alias["aux_count"]) and len(aux) >= 8 and int(alias["type"]) & 0x20:
                    size = max(size, int.from_bytes(aux[4:8], "little"))
            if size <= 0:
                next_offsets = [int(other["value"]) for other in ordered[position + 1 :] if int(other["value"]) > start]
                end = next_offsets[0] if next_offsets else len(data)
            else:
                end = start + size
            if start < 0 or end <= start or end > len(data):
                continue
            object_blob = data[start:end]
            blob, trailing_alignment = _trim_x86_function_alignment(object_blob)
            end = start + len(blob)
            masked = bytearray(blob)
            holes: list[dict[str, int]] = []
            for relocation in relocations.get(section_number, []):
                relocation_offset = int(relocation["offset"])
                width = int(relocation["width"])
                if width <= 0 or relocation_offset < start or relocation_offset + width > end:
                    continue
                local = relocation_offset - start
                masked[local : local + width] = b"\0" * width
                target_symbol = str(relocation.get("target_symbol", ""))
                target_section = int(relocation.get("target_section_number", 0))
                holes.append(
                    {
                        "offset": local,
                        "width": width,
                        "type": int(relocation["type"]),
                        "target_symbol": target_symbol,
                        "target_section": target_section,
                    }
                )
            fixed = len(blob) - sum(item["width"] for item in holes)
            functions.append(
                {
                    "name": str(symbol["name"]),
                    "aliases": aliases,
                    "section": str(section["name"]),
                    "section_index": section_number,
                    "offset": start,
                    "size": len(blob),
                    "object_size": len(object_blob),
                    "trailing_alignment": trailing_alignment.hex(),
                    "bytes_sha256": sha256(blob).hexdigest(),
                    "normalized_sha256": sha256(masked).hexdigest(),
                    "masked_bytes": bytes(masked).hex(),
                    "relocation_holes": holes,
                    "relocation_targets": sorted(
                        {
                            str(item["target_symbol"])
                            for item in holes
                            if item["target_symbol"]
                        }
                    ),
                    "fixed_bytes": fixed,
                    "matchable": fixed >= 4,
                    "match_strength": (
                        "strong" if fixed >= max(8, len(blob) // 4) else "weak"
                    ),
                }
            )
    functions.sort(key=lambda item: (item["section_index"], item["offset"], item["name"]))
    return functions


def _coff_name(field: bytes, data: bytes, string_start: int, string_size: int) -> str:
    if len(field) != 8:
        return ""
    if field.startswith(b"/") and field[1:].rstrip(b"\0").isdigit():
        offset = int(field[1:].rstrip(b"\0"))
        return _coff_string(data, string_start, string_size, offset)
    if field[:4] == b"\0\0\0\0":
        offset = int.from_bytes(field[4:8], "little")
        return _coff_string(data, string_start, string_size, offset)
    return field.rstrip(b"\0").decode("utf-8", errors="replace")


def _coff_string(data: bytes, start: int, size: int, offset: int) -> str:
    if size < 4 or offset < 4 or offset >= size or start + size > len(data):
        return ""
    begin = start + offset
    end = data.find(b"\0", begin, start + size)
    if end < 0:
        end = start + size
    return data[begin:end].decode("utf-8", errors="replace")


def _looks_like_omf(data: bytes) -> bool:
    if len(data) < 4 or data[0] not in {0x80, 0x82, 0x88, 0x96, 0x98, 0x99}:
        return False
    length = int.from_bytes(data[1:3], "little")
    return 1 <= length <= len(data) - 3


def _index_omf(data: bytes, *, label: str) -> dict[str, Any]:
    offset = 0
    records: list[dict[str, Any]] = []
    names: list[str] = []
    public_names: list[str] = []
    public_symbols: list[dict[str, Any]] = []
    segment_data: dict[int, dict[int, int]] = defaultdict(dict)
    module_name = ""
    has_fixups = False
    while offset < len(data):
        if offset + 3 > len(data):
            raise LinkedLibraryError(f"OMF object {label} has a truncated record header")
        record_type = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + 3], "little")
        end = offset + 3 + length
        if length < 1 or end > len(data):
            raise LinkedLibraryError(f"OMF object {label} has a truncated record")
        payload = data[offset + 3 : end - 1]
        checksum = data[end - 1]
        checksum_valid = sum(data[offset:end]) & 0xFF == 0
        if record_type in {0x80, 0x82} and payload:
            name_length = payload[0]
            if name_length + 1 <= len(payload):
                module_name = payload[1 : 1 + name_length].decode("utf-8", errors="replace")
        elif record_type == 0x96:
            cursor = 0
            while cursor < len(payload):
                name_length = payload[cursor]
                cursor += 1
                if cursor + name_length > len(payload):
                    break
                names.append(payload[cursor : cursor + name_length].decode("utf-8", errors="replace"))
                cursor += name_length
        elif record_type in {0x90, 0x91}:
            symbols = _omf_public_symbols(payload, use32=record_type == 0x91)
            public_symbols.extend(symbols)
            public_names.extend(str(symbol["name"]) for symbol in symbols)
        elif record_type in {0xA0, 0xA1}:
            segment, cursor = _omf_index(payload, 0)
            offset_width = 4 if record_type == 0xA1 else 2
            if cursor + offset_width <= len(payload):
                data_offset = int.from_bytes(
                    payload[cursor : cursor + offset_width], "little"
                )
                cursor += offset_width
                for index, value in enumerate(payload[cursor:]):
                    segment_data[segment][data_offset + index] = value
        elif record_type in {0x9C, 0x9D}:
            has_fixups = True
        records.append(
            {
                "offset": offset,
                "type": record_type,
                "payload_bytes": len(payload),
                "payload_sha256": sha256(payload).hexdigest(),
                "checksum": checksum,
                "checksum_valid": checksum_valid,
            }
        )
        offset = end
    fingerprints = _omf_function_fingerprints(
        public_symbols,
        segment_data,
        has_fixups=has_fixups,
    )
    return {
        "kind": "omf_object",
        "status": "indexed" if all(row["checksum_valid"] for row in records) else "incomplete",
        "sha256": sha256(data).hexdigest(),
        "bytes": len(data),
        "module_name": module_name,
        "names": names,
        "public_names": sorted(set(public_names)),
        "public_symbols": public_symbols,
        "record_type_counts": {str(key): value for key, value in sorted(Counter(row["type"] for row in records).items())},
        "records": records,
        "function_fingerprints": fingerprints,
        "counts": {
            "records": len(records),
            "public_symbols": len(public_symbols),
            "function_fingerprints": len(fingerprints),
            "unresolved_fixup_records": sum(
                row["type"] in {0x9C, 0x9D} for row in records
            ),
        },
        "authority": "OMF names and records are proposal evidence; semantic matching remains required",
    }


def _omf_public_symbols(
    payload: bytes,
    *,
    use32: bool,
) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []
    try:
        cursor = 0
        group, cursor = _omf_index(payload, cursor)
        segment, cursor = _omf_index(payload, cursor)
        if segment == 0:
            cursor += 2
        offset_width = 4 if use32 else 2
        while cursor < len(payload):
            name_length = payload[cursor]
            cursor += 1
            if cursor + name_length + offset_width > len(payload):
                break
            name = payload[cursor : cursor + name_length].decode(
                "utf-8", errors="replace"
            )
            cursor += name_length
            symbol_offset = int.from_bytes(
                payload[cursor : cursor + offset_width], "little"
            )
            cursor += offset_width
            type_index, cursor = _omf_index(payload, cursor)
            symbols.append(
                {
                    "name": name,
                    "group_index": group,
                    "segment_index": segment,
                    "offset": symbol_offset,
                    "type_index": type_index,
                }
            )
    except (IndexError, ValueError):
        return symbols
    return symbols


def _omf_function_fingerprints(
    symbols: Sequence[Mapping[str, Any]],
    segment_data: Mapping[int, Mapping[int, int]],
    *,
    has_fixups: bool,
) -> list[dict[str, Any]]:
    by_segment: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for symbol in symbols:
        segment = int(symbol.get("segment_index", 0))
        if segment > 0:
            by_segment[segment].append(symbol)
    result: list[dict[str, Any]] = []
    for segment, segment_symbols in sorted(by_segment.items()):
        values = segment_data.get(segment, {})
        if not values:
            continue
        data_end = max(values) + 1
        ordered = sorted(
            segment_symbols,
            key=lambda item: (int(item["offset"]), str(item["name"])),
        )
        for position, symbol in enumerate(ordered):
            start = int(symbol["offset"])
            later = [
                int(item["offset"])
                for item in ordered[position + 1 :]
                if int(item["offset"]) > start
            ]
            end = later[0] if later else data_end
            if end <= start or any(offset not in values for offset in range(start, end)):
                continue
            blob = bytes(values[offset] for offset in range(start, end))
            result.append(
                {
                    "name": str(symbol["name"]),
                    "section": f"omf-segment-{segment}",
                    "section_index": segment,
                    "offset": start,
                    "size": len(blob),
                    "bytes_sha256": sha256(blob).hexdigest(),
                    "normalized_sha256": sha256(blob).hexdigest(),
                    "masked_bytes": blob.hex(),
                    "relocation_holes": [],
                    "fixed_bytes": len(blob),
                    "matchable": len(blob) >= 8 and not has_fixups,
                    "blocker": (
                        "unresolved_omf_fixupp_records" if has_fixups else None
                    ),
                }
            )
    return result


def _omf_index(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _index_pe(path: Path) -> dict[str, Any]:
    binary = parse_pe_image(path)
    debug = _pe_debug_identities(binary)
    return {
        "kind": "pe_image",
        "status": "indexed",
        "sha256": binary.sha256,
        "bytes": binary.size,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "is_dll": binary.is_dll,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "executable": section.executable,
                "writable": section.writable,
            }
            for section in binary.sections
        ],
        "imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in binary.imports
        ],
        "exports": [
            {"name": item.name, "ordinal": item.ordinal, "rva": item.rva, "kind": item.kind, "forwarder": item.forwarder}
            for item in (binary.exports or ())
        ],
        "debug_identities": debug,
        "function_fingerprints": [],
    }


def _pe_debug_identities(binary: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in getattr(binary.pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        entry = item.struct
        size = int(getattr(entry, "SizeOfData", 0) or 0)
        address = int(getattr(entry, "AddressOfRawData", 0) or 0)
        debug_type = int(getattr(entry, "Type", 0) or 0)
        payload = binary.pe.get_data(address, size) if address and size else b""
        row: dict[str, Any] = {
            "type": debug_type,
            "timestamp": int(getattr(entry, "TimeDateStamp", 0) or 0),
            "size": size,
            "payload_sha256": sha256(payload).hexdigest(),
        }
        if debug_type == 2 and payload.startswith(b"RSDS") and len(payload) >= 24:
            guid = payload[4:20]
            row.update(
                {
                    "kind": "codeview_rsds",
                    "guid": _format_guid(guid),
                    "age": int.from_bytes(payload[20:24], "little"),
                    "pdb_path": payload[24:].split(b"\0", 1)[0].decode("utf-8", errors="replace"),
                }
            )
        elif debug_type == 2 and payload.startswith(b"NB10") and len(payload) >= 16:
            row.update(
                {
                    "kind": "codeview_nb10",
                    "signature": int.from_bytes(payload[8:12], "little"),
                    "age": int.from_bytes(payload[12:16], "little"),
                    "pdb_path": payload[16:].split(b"\0", 1)[0].decode("utf-8", errors="replace"),
                }
            )
        elif debug_type == 16:
            row["kind"] = "reproducible"
        elif debug_type == 19:
            row["kind"] = "pdb_checksum"
            if b"\0" in payload:
                algorithm, digest = payload.split(b"\0", 1)
                row["algorithm"] = algorithm.decode("ascii", errors="replace")
                row["digest"] = digest.hex()
        else:
            row["kind"] = "other"
        result.append(row)
    return result


def _format_guid(data: bytes) -> str:
    if len(data) != 16:
        return data.hex()
    first, second, third = struct.unpack_from("<IHH", data, 0)
    return f"{first:08x}-{second:04x}-{third:04x}-{data[8:10].hex()}-{data[10:16].hex()}"


def _artifact_function_count(index: Mapping[str, Any]) -> int:
    own = len(index.get("function_fingerprints", []))
    return own + sum(
        _artifact_function_count(_object(member.get("index"), "nested artifact index"))
        for member in index.get("members", [])
        if isinstance(member, Mapping)
    )


def _decorate_v2_artifact_index(
    index: Mapping[str, Any],
    *,
    artifact_sha256: str,
    member_path: tuple[str, ...],
) -> dict[str, Any]:
    """Attach stable member and fingerprint identities to an indexed artifact."""

    result = copy.deepcopy(dict(index))
    functions = []
    for position, raw in enumerate(result.get("function_fingerprints", [])):
        function = dict(_object(raw, "function fingerprint"))
        canonical = {
            "artifact_sha256": artifact_sha256,
            "member_path": list(member_path),
            "section_index": function.get("section_index"),
            "offset": function.get("offset"),
            "size": function.get("size"),
            "normalized_sha256": function.get("normalized_sha256"),
        }
        function["fingerprint_id"] = "fingerprint:" + _canonical_sha256(
            canonical
        )[:24]
        function["fingerprint_scope"] = "function"
        function["ordinal"] = position
        functions.append(function)
    result["function_fingerprints"] = functions

    members = []
    for ordinal, raw in enumerate(result.get("members", [])):
        member = dict(_object(raw, "archive member"))
        name = str(member.get("name", f"member-{ordinal}"))
        child_path = (*member_path, name)
        member_identity = {
            "artifact_sha256": artifact_sha256,
            "member_path": list(child_path),
            "member_sha256": member.get("sha256"),
            "ordinal": ordinal,
        }
        member["ordinal"] = ordinal
        member["member_id"] = "member:" + _canonical_sha256(member_identity)[:24]
        member["index"] = _decorate_v2_artifact_index(
            _object(member.get("index"), "archive member index"),
            artifact_sha256=artifact_sha256,
            member_path=child_path,
        )
        members.append(member)
    if "members" in result:
        result["members"] = members
    return result
