"""Untrusted COFF symbol-table hints bound to parsed PE32 images."""

from __future__ import annotations

import struct

from .stage_binary import StageABinary


def coff_symbol_aliases_by_rva(binary: StageABinary) -> dict[int, list[str]]:
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
        string_table_size = int.from_bytes(
            data[string_table_start : string_table_start + 4],
            "little",
            signed=False,
        )
    result: dict[int, list[str]] = {}
    index = 0
    while index < count:
        offset = pointer + index * 18
        if offset + 18 > len(data):
            break
        entry = data[offset : offset + 18]
        name = _coff_symbol_name(
            entry[:8], data, string_table_start, string_table_size
        )
        value, section_number, symbol_type, storage_class, auxiliary_count = (
            struct.unpack("<IhHBB", entry[8:18])
        )
        if name and 0 < section_number <= len(binary.sections):
            section = binary.sections[section_number - 1]
            rva = section.rva_start + int(value)
            if (
                section.executable
                and section.rva_start <= rva < section.rva_end
                and _coff_symbol_is_code_like(symbol_type, storage_class)
            ):
                aliases = result.setdefault(rva, [])
                for alias in _coff_symbol_aliases(name):
                    if alias not in aliases:
                        aliases.append(alias)
        index += 1 + int(auxiliary_count)
    return result


def _coff_symbol_name(
    name_field: bytes,
    data: bytes,
    string_table_start: int,
    string_table_size: int,
) -> str:
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
    if symbol_type & 0x20:
        return True
    return storage_class in {2, 3}


__all__ = ["coff_symbol_aliases_by_rva"]
