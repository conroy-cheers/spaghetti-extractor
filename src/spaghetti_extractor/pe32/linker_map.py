from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..errors import ToolkitInputError
from .model import ParsedPEImage
from .queries import executable_section_for_rva


def parse_linker_map_functions(path: Path, binary: ParsedPEImage) -> list[dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ToolkitInputError(f"cannot read linker map {path}: {exc}") from exc
    symbol_starts: dict[int, list[str]] = {}
    boundary_starts: set[int] = set()
    pending_text_section: str | None = None
    for line in text.splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is not None:
            rva, name = parsed
            if _linker_map_symbol_is_non_function_label(name):
                continue
            if executable_section_for_rva(binary, rva) is None:
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
        section = executable_section_for_rva(binary, rva)
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


def _parse_linker_map_text_boundary_line(line: str, binary: ParsedPEImage) -> int | None:
    match = re.match(r"^\s*\.text\S*\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    rva = address - binary.image_base if address >= binary.image_base else address
    if executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_boundary_continuation_line(line: str, binary: ParsedPEImage) -> int | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    rva = address - binary.image_base if address >= binary.image_base else address
    if executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_section_only_line(line: str) -> str | None:
    match = re.match(r"^\s*(\.text\S*)\s*$", line)
    return match.group(1) if match is not None else None


def _linker_map_symbol_is_non_function_label(name: str) -> bool:
    stripped = name.lstrip("_")
    if re.match(r"^fu\d+_+", stripped):
        return True
    return stripped.startswith("spx_contract_rva_")


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


def _parse_linker_map_symbol_line(line: str, binary: ParsedPEImage) -> tuple[int, str] | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$", line)
    if match is not None:
        address = int(match.group(1), 16)
        name = match.group(2)
    else:
        # LINK and lld-link maps identify a symbol by section:offset and also
        # print its image-relative absolute address. The latter is sufficient
        # here; section numbers and symbols remain untrusted mapping hints.
        msvc_match = re.match(
            r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8,16}\s+"
            r"(\S+)\s+([0-9a-fA-F]{8,16})(?:\s+.*)?$",
            line,
        )
        if msvc_match is None:
            return None
        name = msvc_match.group(1)
        address = int(msvc_match.group(2), 16)
    if name.startswith(".") or name in {"PROVIDE", "CREATE_OBJECT_SYMBOLS"}:
        return None
    rva = address - binary.image_base if address >= binary.image_base else address
    return rva, name


def _primary_symbol_name(names: list[str]) -> str:
    for name in names:
        if not name.startswith("__") and not name.startswith("___"):
            return name
    return names[0]


__all__ = ["parse_linker_map_functions"]
