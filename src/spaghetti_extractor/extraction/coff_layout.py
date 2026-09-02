"""Untrusted executable-layout proposals from an embedded PE COFF table."""

from __future__ import annotations

import struct
from collections import defaultdict
from typing import Any, Mapping

from ..errors import ToolkitInputError
from ..pe32.model import ParsedPEImage
from ..util import sha256_bytes


def _coff_string(data: bytes, start: int, size: int, offset: int) -> str:
    if size < 4 or offset < 4 or offset >= size or start + size > len(data):
        return ""
    begin = start + offset
    end = data.find(b"\0", begin, start + size)
    if end < 0:
        end = start + size
    return data[begin:end].decode("utf-8", errors="replace")


def _coff_name(field: bytes, data: bytes, start: int, size: int) -> str:
    if field[:4] == b"\0\0\0\0":
        return _coff_string(
            data, start, size, int.from_bytes(field[4:8], "little")
        )
    return field.rstrip(b"\0").decode("utf-8", errors="replace")


def _symbols(binary: ParsedPEImage) -> tuple[list[dict[str, Any]], str] | None:
    pointer = int(binary.pe.FILE_HEADER.PointerToSymbolTable)
    count = int(binary.pe.FILE_HEADER.NumberOfSymbols)
    if pointer == 0 and count == 0:
        return None
    data = binary.path.read_bytes()
    if pointer <= 0 or count <= 0 or pointer + count * 18 > len(data):
        raise ToolkitInputError("PE COFF symbol table is truncated")
    string_start = pointer + count * 18
    if string_start + 4 > len(data):
        raise ToolkitInputError("PE COFF string table is truncated")
    string_size = int.from_bytes(data[string_start : string_start + 4], "little")
    if string_size < 4 or string_start + string_size > len(data):
        raise ToolkitInputError("PE COFF string table is malformed")
    result: list[dict[str, Any]] = []
    index = 0
    while index < count:
        offset = pointer + index * 18
        row = data[offset : offset + 18]
        value, section_number, symbol_type, storage_class, aux_count = (
            struct.unpack_from("<IhHBB", row, 8)
        )
        aux_start = offset + 18
        aux_end = aux_start + aux_count * 18
        if aux_end > pointer + count * 18:
            raise ToolkitInputError("PE COFF symbol has truncated auxiliaries")
        result.append({
            "index": index,
            "name": _coff_name(row[:8], data, string_start, string_size),
            "value": value,
            "section_number": section_number,
            "type": symbol_type,
            "storage_class": storage_class,
            "aux_count": aux_count,
            "aux": data[aux_start:aux_end],
        })
        index += 1 + aux_count
    table_end = string_start + string_size
    return result, sha256_bytes(data[pointer:table_end])


def pe32_coff_executable_layout(
    binary: ParsedPEImage,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Propose code contributions and explicit executable-data exclusions.

    GNU PE images commonly retain the original COFF table even when no linker
    map is installed.  Section-definition auxiliaries preserve each input
    contribution's exact extent.  A contribution containing a typed function
    is proposed as code.  A contribution with local data labels is excluded
    only when it does not decode exactly as IA-32.  Any later control edge or
    PE root into an excluded span remains a fail-closed universe error.
    """

    parsed = _symbols(binary)
    if parsed is None:
        return [], []
    symbols, table_sha256 = parsed
    symbols_by_section: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for symbol in symbols:
        section_number = int(symbol["section_number"])
        if 1 <= section_number <= len(binary.sections):
            symbols_by_section[section_number].append(symbol)

    code: list[dict[str, Any]] = []
    non_code: list[dict[str, Any]] = []
    for section_number, section in enumerate(binary.sections, start=1):
        if not section.executable:
            continue
        members = symbols_by_section.get(section_number, [])
        contributions: dict[tuple[int, int], list[Mapping[str, Any]]] = {}
        for symbol in members:
            aux = bytes(symbol["aux"])
            if (
                int(symbol["storage_class"]) != 3
                or int(symbol["aux_count"]) < 1
                or str(symbol["name"]) != section.name
                or len(aux) < 4
            ):
                continue
            size = int.from_bytes(aux[:4], "little")
            start = section.rva_start + int(symbol["value"])
            if size <= 0 or not (
                section.rva_start <= start < start + size <= section.rva_end
            ):
                continue
            contributions.setdefault((start, start + size), []).append(symbol)
        for start, stop in sorted(contributions):
            local_members = [
                symbol for symbol in members
                if start <= section.rva_start + int(symbol["value"]) < stop
            ]
            members_by_rva: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
            for symbol in local_members:
                is_function = bool(int(symbol["type"]) & 0x20)
                is_local_data = int(symbol["storage_class"]) == 6
                if is_function or is_local_data:
                    members_by_rva[
                        section.rva_start + int(symbol["value"])
                    ].append(symbol)
            boundaries = sorted({start, stop, *members_by_rva})
            for segment_start, segment_stop in zip(
                boundaries, boundaries[1:]
            ):
                if segment_stop <= segment_start:
                    continue
                at_start = members_by_rva.get(segment_start, [])
                functions = [
                    symbol for symbol in at_start
                    if int(symbol["type"]) & 0x20 and str(symbol["name"])
                ]
                data_labels = [
                    symbol for symbol in at_start
                    if int(symbol["storage_class"]) == 6
                    and str(symbol["name"])
                ]
                if data_labels and not functions:
                    labels = sorted({
                        str(symbol["name"]) for symbol in data_labels
                    })
                    non_code.append({
                        "binary": "",
                        "id": "",
                        "classification": "coff_executable_data",
                        "reason": (
                            "embedded COFF contribution is delimited by a "
                            "local data label"
                        ),
                        "rva": segment_start,
                        "size": segment_stop - segment_start,
                        "source": {
                            "kind": "embedded_pe_coff_section_contribution",
                            "section": section.name,
                            "symbol_table_sha256": table_sha256,
                            "labels": labels,
                        },
                    })
                    continue
                aliases = sorted({
                    str(symbol["name"]) for symbol in functions
                })
                code.append({
                    "name": aliases[0] if aliases else (
                        f"coff-contribution-{segment_start:08x}"
                    ),
                    "aliases": aliases,
                    "rva_start": segment_start,
                    "rva_end": segment_stop,
                    "section": section.name,
                    "source_kind": "embedded_pe_coff_section_contribution",
                    "symbol_table_sha256": table_sha256,
                })
    return code, non_code


__all__ = ["pe32_coff_executable_layout"]
