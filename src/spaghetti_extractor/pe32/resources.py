"""Exact, bounded PE32 resource-directory decoding and validation.

Resource directory links are image-relative offsets, while leaf data entries
carry RVAs.  Keeping both forms explicit lets semantic linking name resource
storage without treating either field as an ordinary native pointer.
"""

from __future__ import annotations

import struct
from typing import Any, Mapping

from ..errors import ToolkitInputError
from ..util import sha256_bytes


MAX_RESOURCE_ROWS = 65_536
_DIRECTORY_FIELDS = {
    "directory_id", "relative_offset", "characteristics", "timestamp",
    "major_version", "minor_version", "named_entry_count",
    "id_entry_count", "entries",
}
_ENTRY_FIELDS = {"entry_index", "name", "target"}
_DATA_FIELDS = {
    "data_id", "relative_offset", "data_rva", "size", "code_page",
    "reserved", "content_sha256", "content_hex", "locator",
}


class _ResourceDecodeError(ValueError):
    pass


def _directory_id(offset: int) -> str:
    return f"resource:directory:{offset:08x}"


def _data_id(offset: int) -> str:
    return f"resource:data-entry:{offset:08x}"


def _mapped_locator(
    *, rva: int, size: int, image_size: int, header_size: int,
    sections: list[Mapping[str, Any]],
) -> dict[str, Any] | None:
    end = rva + size
    if rva < 0 or end < rva or end > image_size:
        return None
    if rva < header_size and end <= header_size:
        return {"kind": "image_headers", "section_index": None, "offset": rva}
    matches = [
        section for section in sections
        if int(section["rva"]) <= rva
        and end <= int(section["rva"]) + int(section["mapped_size"])
        and (size != 0 or rva < int(section["rva"]) + int(section["mapped_size"]))
    ]
    if len(matches) != 1:
        return None
    section = matches[0]
    return {
        "kind": "image_section",
        "section_index": int(section["index"]),
        "offset": rva - int(section["rva"]),
    }


def _section_for_locator(
    locator: Mapping[str, Any], sections: list[Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    if locator.get("kind") != "image_section":
        return None
    section_index = locator.get("section_index")
    matches = [row for row in sections if row.get("index") == section_index]
    return matches[0] if len(matches) == 1 else None


def extract_resource_surface_v1(
    *, pe: Any, image_size: int, header_size: int,
    sections: list[Mapping[str, Any]],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Decode one PE32 resource tree, returning a stable blocker on failure."""

    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
    directory_rva = int(directory.VirtualAddress)
    directory_size = int(directory.Size)
    if directory_rva == 0 and directory_size == 0:
        return None, []
    if directory_rva == 0 or directory_size < 16:
        return None, [{"category": "resource_directory_span_malformed"}]
    directory_locator = _mapped_locator(
        rva=directory_rva,
        size=directory_size,
        image_size=image_size,
        header_size=header_size,
        sections=sections,
    )
    if directory_locator is None:
        return None, [{"category": "resource_directory_not_fully_mapped"}]
    directory_section = _section_for_locator(directory_locator, sections)
    if directory_locator["kind"] == "image_section" and directory_section is None:
        return None, [{"category": "resource_directory_section_identity_ambiguous"}]
    if directory_section is not None and bool(directory_section["executable"]):
        return None, [{"category": "resource_directory_executable_storage"}]

    directories: dict[int, dict[str, Any]] = {}
    data_entries: dict[int, dict[str, Any]] = {}
    visiting: set[int] = set()

    def read_relative(offset: int, size: int, context: str) -> bytes:
        if offset < 0 or size < 0 or offset + size > directory_size:
            raise _ResourceDecodeError(f"{context} exceeds the resource span")
        data = bytes(pe.get_data(directory_rva + offset, size))
        if len(data) != size:
            raise _ResourceDecodeError(f"{context} is not fully mapped")
        return data

    def parse_name(raw: int, context: str) -> dict[str, Any]:
        if not raw & 0x80000000:
            return {
                "kind": "id", "id": raw, "text": None,
                "relative_offset": None, "utf16le_hex": None,
            }
        relative_offset = raw & 0x7FFFFFFF
        length = struct.unpack("<H", read_relative(
            relative_offset, 2, f"{context} name length"
        ))[0]
        encoded = read_relative(
            relative_offset + 2, length * 2, f"{context} name"
        )
        try:
            text = encoded.decode("utf-16-le")
        except UnicodeDecodeError as exc:
            raise _ResourceDecodeError(
                f"{context} name is not valid UTF-16LE"
            ) from exc
        return {
            "kind": "string", "id": None, "text": text,
            "relative_offset": relative_offset,
            "utf16le_hex": encoded.hex(),
        }

    def parse_data(offset: int) -> str:
        if offset in data_entries:
            return _data_id(offset)
        raw = read_relative(offset, 16, f"resource data entry {offset:#x}")
        data_rva, size, code_page, reserved = struct.unpack("<IIII", raw)
        locator = _mapped_locator(
            rva=data_rva,
            size=size,
            image_size=image_size,
            header_size=header_size,
            sections=sections,
        )
        if locator is None:
            raise _ResourceDecodeError(
                f"resource data entry {offset:#x} payload is not fully mapped"
            )
        content = bytes(pe.get_data(data_rva, size))
        if len(content) != size:
            raise _ResourceDecodeError(
                f"resource data entry {offset:#x} payload is truncated"
            )
        identity = _data_id(offset)
        data_entries[offset] = {
            "data_id": identity,
            "relative_offset": offset,
            "data_rva": data_rva,
            "size": size,
            "code_page": code_page,
            "reserved": reserved,
            "content_sha256": sha256_bytes(content),
            "content_hex": content.hex(),
            "locator": locator,
        }
        if len(directories) + len(data_entries) > MAX_RESOURCE_ROWS:
            raise _ResourceDecodeError("resource tree exceeds the row bound")
        return identity

    def parse_directory(offset: int) -> str:
        if offset in directories:
            if offset in visiting:
                raise _ResourceDecodeError("resource directory contains a cycle")
            return _directory_id(offset)
        if offset in visiting:
            raise _ResourceDecodeError("resource directory contains a cycle")
        visiting.add(offset)
        raw = read_relative(offset, 16, f"resource directory {offset:#x}")
        characteristics, timestamp, major, minor, named, ids = struct.unpack(
            "<IIHHHH", raw
        )
        count = named + ids
        if count > MAX_RESOURCE_ROWS:
            raise _ResourceDecodeError("resource directory entry count is unbounded")
        entry_bytes = read_relative(
            offset + 16, count * 8, f"resource directory {offset:#x} entries"
        )
        identity = _directory_id(offset)
        row = {
            "directory_id": identity,
            "relative_offset": offset,
            "characteristics": characteristics,
            "timestamp": timestamp,
            "major_version": major,
            "minor_version": minor,
            "named_entry_count": named,
            "id_entry_count": ids,
            "entries": [],
        }
        directories[offset] = row
        if len(directories) + len(data_entries) > MAX_RESOURCE_ROWS:
            raise _ResourceDecodeError("resource tree exceeds the row bound")
        keys: set[tuple[str, object]] = set()
        pending: list[tuple[dict[str, Any], int, bool]] = []
        for index in range(count):
            name_raw, target_raw = struct.unpack_from("<II", entry_bytes, index * 8)
            name = parse_name(name_raw, f"resource entry {offset:#x}:{index}")
            key = (str(name["kind"]), name["text"] if name["kind"] == "string" else name["id"])
            if key in keys:
                raise _ResourceDecodeError("resource directory contains a duplicate name")
            keys.add(key)
            if (index < named) != (name["kind"] == "string"):
                raise _ResourceDecodeError("resource named/ID entry counts are incoherent")
            target_offset = target_raw & 0x7FFFFFFF
            target_is_directory = bool(target_raw & 0x80000000)
            entry = {"entry_index": index, "name": name, "target": None}
            row["entries"].append(entry)
            pending.append((entry, target_offset, target_is_directory))
        for entry, target_offset, target_is_directory in pending:
            if target_is_directory:
                target_id = parse_directory(target_offset)
                target_kind = "directory"
            else:
                target_id = parse_data(target_offset)
                target_kind = "data"
            entry["target"] = {
                "kind": target_kind,
                "id": target_id,
                "relative_offset": target_offset,
            }
        visiting.remove(offset)
        return identity

    try:
        root_id = parse_directory(0)
    except _ResourceDecodeError as exc:
        return None, [{
            "category": "resource_directory_tree_malformed",
            "detail": str(exc),
        }]
    return {
        "directory_rva": directory_rva,
        "directory_size": directory_size,
        "directory_locator": directory_locator,
        "root_directory_id": root_id,
        "directories": [directories[key] for key in sorted(directories)],
        "data_entries": [data_entries[key] for key in sorted(data_entries)],
    }, []


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    return value


def _integer(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ToolkitInputError(f"{context} must be a nonnegative integer")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise ToolkitInputError(f"{context} fields are incomplete")


def validate_resource_surface_v1(
    value: object, *, directory: Mapping[str, Any],
    sections: list[Mapping[str, Any]], runtime_headers: Mapping[str, Any],
    allow_missing: bool = False,
) -> None:
    """Validate exact tree geometry, content, and mapped leaf locators."""

    present = bool(int(directory["rva"]) or int(directory["size"]))
    if value is None:
        if present and not allow_missing:
            raise ToolkitInputError("nonempty resource directory lacks its typed codec")
        return
    surface = _mapping(value, "module resources")
    _exact(surface, {
        "directory_rva", "directory_size", "directory_locator",
        "root_directory_id", "directories", "data_entries",
    }, "module resources")
    directory_rva = _integer(surface["directory_rva"], "resource directory RVA")
    directory_size = _integer(surface["directory_size"], "resource directory size")
    if (directory_rva, directory_size) != (
        int(directory["rva"]), int(directory["size"])
    ) or not present:
        raise ToolkitInputError("resource directory binding is stale")
    expected_directory_locator = _mapped_locator(
        rva=directory_rva,
        size=directory_size,
        image_size=max(
            int(runtime_headers["size"]),
            *(int(row["rva"]) + int(row["mapped_size"]) for row in sections),
        ),
        header_size=int(runtime_headers["size"]),
        sections=sections,
    )
    if surface["directory_locator"] != expected_directory_locator:
        raise ToolkitInputError("resource directory locator is stale")
    raw_directories = surface["directories"]
    raw_data = surface["data_entries"]
    if not isinstance(raw_directories, list) or not isinstance(raw_data, list):
        raise ToolkitInputError("resource inventories must be arrays")
    if len(raw_directories) + len(raw_data) > MAX_RESOURCE_ROWS:
        raise ToolkitInputError("resource inventory exceeds its row bound")
    directories: dict[str, Mapping[str, Any]] = {}
    offsets: list[int] = []
    for index, raw in enumerate(raw_directories):
        row = _mapping(raw, f"resource directory {index}")
        _exact(row, _DIRECTORY_FIELDS, f"resource directory {index}")
        offset = _integer(row["relative_offset"], "resource directory offset")
        identity = row.get("directory_id")
        if identity != _directory_id(offset) or identity in directories:
            raise ToolkitInputError("resource directory identity is stale or duplicated")
        for field in (
            "characteristics", "timestamp", "major_version", "minor_version",
            "named_entry_count", "id_entry_count",
        ):
            _integer(row[field], f"resource directory {field}")
        entries = row["entries"]
        if not isinstance(entries, list) or len(entries) != (
            int(row["named_entry_count"]) + int(row["id_entry_count"])
        ):
            raise ToolkitInputError("resource directory entry count is stale")
        directories[str(identity)] = row
        offsets.append(offset)
    if offsets != sorted(offsets) or len(offsets) != len(set(offsets)):
        raise ToolkitInputError("resource directories are not canonically ordered")
    data_entries: dict[str, Mapping[str, Any]] = {}
    data_offsets: list[int] = []
    image_size = max(
        int(runtime_headers["size"]),
        *(int(row["rva"]) + int(row["mapped_size"]) for row in sections),
    )
    for index, raw in enumerate(raw_data):
        row = _mapping(raw, f"resource data entry {index}")
        _exact(row, _DATA_FIELDS, f"resource data entry {index}")
        offset = _integer(row["relative_offset"], "resource data-entry offset")
        identity = row.get("data_id")
        if identity != _data_id(offset) or identity in data_entries:
            raise ToolkitInputError("resource data identity is stale or duplicated")
        data_rva = _integer(row["data_rva"], "resource data RVA")
        size = _integer(row["size"], "resource data size")
        _integer(row["code_page"], "resource code page")
        _integer(row["reserved"], "resource reserved field")
        content_hex = row.get("content_hex")
        if not isinstance(content_hex, str):
            raise ToolkitInputError("resource content must be hexadecimal text")
        try:
            content = bytes.fromhex(content_hex)
        except ValueError as exc:
            raise ToolkitInputError("resource content is not hexadecimal") from exc
        if content.hex() != content_hex or len(content) != size:
            raise ToolkitInputError("resource content extent is stale")
        if row.get("content_sha256") != sha256_bytes(content):
            raise ToolkitInputError("resource content hash is stale")
        expected_locator = _mapped_locator(
            rva=data_rva, size=size, image_size=image_size,
            header_size=int(runtime_headers["size"]), sections=sections,
        )
        if row.get("locator") != expected_locator or expected_locator is None:
            raise ToolkitInputError("resource data locator is stale")
        data_entries[str(identity)] = row
        data_offsets.append(offset)
    if data_offsets != sorted(data_offsets) or len(data_offsets) != len(set(data_offsets)):
        raise ToolkitInputError("resource data entries are not canonically ordered")

    referenced_directories: set[str] = set()
    referenced_data: set[str] = set()
    for identity, row in directories.items():
        keys: set[tuple[str, object]] = set()
        named = int(row["named_entry_count"])
        for index, raw_entry in enumerate(row["entries"]):
            entry = _mapping(raw_entry, f"resource entry {identity}:{index}")
            _exact(entry, _ENTRY_FIELDS, f"resource entry {identity}:{index}")
            if entry.get("entry_index") != index:
                raise ToolkitInputError("resource entry index is stale")
            name = _mapping(entry.get("name"), "resource entry name")
            _exact(name, {"kind", "id", "text", "relative_offset", "utf16le_hex"}, "resource entry name")
            kind = name.get("kind")
            if kind == "id":
                name_id = _integer(name.get("id"), "resource numeric ID")
                if any(name.get(field) is not None for field in ("text", "relative_offset", "utf16le_hex")):
                    raise ToolkitInputError("numeric resource name carries string fields")
                key = ("id", name_id)
            elif kind == "string":
                text = name.get("text")
                relative = name.get("relative_offset")
                encoded_hex = name.get("utf16le_hex")
                if not isinstance(text, str) or not isinstance(encoded_hex, str):
                    raise ToolkitInputError("string resource name is incomplete")
                _integer(relative, "resource-name relative offset")
                try:
                    encoded = bytes.fromhex(encoded_hex)
                    decoded = encoded.decode("utf-16-le")
                except (ValueError, UnicodeDecodeError) as exc:
                    raise ToolkitInputError("resource name is not canonical UTF-16LE") from exc
                if encoded.hex() != encoded_hex or decoded != text or name.get("id") is not None:
                    raise ToolkitInputError("resource string name is stale")
                key = ("string", text)
            else:
                raise ToolkitInputError("resource name kind is unsupported")
            if (index < named) != (kind == "string") or key in keys:
                raise ToolkitInputError("resource named/ID partition is incoherent")
            keys.add(key)
            target = _mapping(entry.get("target"), "resource entry target")
            _exact(target, {"kind", "id", "relative_offset"}, "resource entry target")
            target_offset = _integer(target.get("relative_offset"), "resource target offset")
            target_id = target.get("id")
            if target.get("kind") == "directory":
                expected = directories.get(str(target_id))
                referenced_directories.add(str(target_id))
            elif target.get("kind") == "data":
                expected = data_entries.get(str(target_id))
                referenced_data.add(str(target_id))
            else:
                raise ToolkitInputError("resource target kind is unsupported")
            if expected is None or int(expected["relative_offset"]) != target_offset:
                raise ToolkitInputError("resource entry target is stale")
    root = surface.get("root_directory_id")
    if root != _directory_id(0) or root not in directories:
        raise ToolkitInputError("resource root directory is stale")
    if set(directories) - {str(root)} != referenced_directories:
        raise ToolkitInputError("resource directory graph has unreachable nodes")
    if set(data_entries) != referenced_data:
        raise ToolkitInputError("resource directory graph has unreachable data")


__all__ = ["extract_resource_surface_v1", "validate_resource_surface_v1"]
