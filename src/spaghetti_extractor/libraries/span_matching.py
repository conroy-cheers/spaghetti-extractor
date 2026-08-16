"""Relocation-aware static span retrieval for linked-library signatures."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..pe32.image import parse_pe_image
from ..util import sha256_file
from .abi_catalog import CatalogSearchIndexV3
from .abi_records import LibraryAbiError, LibraryFunctionSignatureV3, stable_id
from .signature_graph import TargetSignatureGraphV3


@dataclass(frozen=True, order=True)
class StaticSpanMatch:
    match_id: str
    target_rva_start: int
    target_rva_end: int
    target_unit_ids: tuple[str, ...]
    catalog_function_id: str
    evidence: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.match_id,
            "target_rva_start": self.target_rva_start,
            "target_rva_end": self.target_rva_end,
            "target_unit_ids": list(self.target_unit_ids),
            "catalog_function_id": self.catalog_function_id,
            "evidence": list(self.evidence),
        }


def _fixed_mask(function: LibraryFunctionSignatureV3) -> bytes | None:
    if function.masked_bytes_hex is None or function.match_strength != "strong":
        return None
    size = len(bytes.fromhex(function.masked_bytes_hex))
    mask = bytearray(b"\1" * size)
    for offset, width, _kind, _target in function.relocation_holes:
        if offset + width > size:
            return None
        mask[offset : offset + width] = b"\0" * width
    return bytes(mask)


def _anchor(function: LibraryFunctionSignatureV3) -> tuple[int, bytes] | None:
    mask = _fixed_mask(function)
    if mask is None or function.masked_bytes_hex is None:
        return None
    data = bytes.fromhex(function.masked_bytes_hex)
    runs: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(mask):
        while cursor < len(mask) and not mask[cursor]:
            cursor += 1
        end = cursor
        while end < len(mask) and mask[end]:
            end += 1
        if end - cursor >= 4:
            runs.append((cursor, end))
        cursor = end + 1
    if not runs:
        return None
    start, end = min(runs, key=lambda item: (-min(item[1] - item[0], 8), item[0]))
    return start, data[start : min(start + 8, end)]


def _matches_at(data: bytes, start: int, function: LibraryFunctionSignatureV3) -> bool:
    if function.masked_bytes_hex is None:
        return False
    expected = bytes.fromhex(function.masked_bytes_hex)
    end = start + len(expected)
    if start < 0 or end > len(data):
        return False
    mask = _fixed_mask(function)
    return mask is not None and all(
        not mask[index] or data[start + index] == value
        for index, value in enumerate(expected)
    )


def _covered_units(
    graph: TargetSignatureGraphV3, start: int, end: int
) -> tuple[str, ...] | None:
    overlapping = tuple(
        span
        for span in graph.unit_spans
        if span.rva_start < end and start < span.rva_end
    )
    if not overlapping or any(
        span.rva_start < start or span.rva_end > end for span in overlapping
    ):
        return None
    ordered = sorted(overlapping, key=lambda item: (item.rva_start, item.rva_end, item.unit_id))
    cursor = start
    for span in ordered:
        if span.rva_start > cursor:
            return None
        cursor = max(cursor, span.rva_end)
    if cursor != end:
        return None
    return tuple(sorted(span.unit_id for span in overlapping))


def discover_static_span_matches(
    *,
    target_graph: TargetSignatureGraphV3,
    search_index: CatalogSearchIndexV3,
    target_pe: Path | str,
) -> tuple[StaticSpanMatch, ...]:
    """Find strong relocation-masked catalog bodies in exact target PE bytes.

    Retrieval is linear in executable bytes plus verified candidates: each
    catalog signature contributes one four-byte anchor, and executable sections
    are scanned once. The result remains proposal evidence until island and
    boundary checking consume it.
    """

    pe_path = Path(target_pe)
    if sha256_file(pe_path) != target_graph.binary_sha256:
        raise LibraryAbiError(
            "target_pe_graph_contradiction",
            "target PE does not match the target signature graph",
            location=str(pe_path),
        )
    parsed = parse_pe_image(pe_path)
    pe_bytes = pe_path.read_bytes()
    catalog_by_anchor: dict[bytes, list[tuple[int, LibraryFunctionSignatureV3]]] = {}
    for function in search_index.functions:
        anchor = _anchor(function)
        if anchor is None:
            continue
        offset, data = anchor
        catalog_by_anchor.setdefault(data[:4], []).append((offset, function))
    results: dict[tuple[int, int, str], StaticSpanMatch] = {}
    for section in parsed.sections:
        if not section.executable or section.raw_size <= 0:
            continue
        raw = pe_bytes[section.raw_pointer : section.raw_pointer + section.raw_size]
        for position in range(max(0, len(raw) - 3)):
            bucket = catalog_by_anchor.get(raw[position : position + 4])
            if not bucket:
                continue
            for anchor_offset, function in bucket:
                local_start = position - anchor_offset
                if not _matches_at(raw, local_start, function):
                    continue
                size = len(bytes.fromhex(function.masked_bytes_hex or ""))
                rva_start = section.rva_start + local_start
                rva_end = rva_start + size
                unit_ids = _covered_units(target_graph, rva_start, rva_end)
                if unit_ids is None:
                    continue
                binding = {
                    "binary_sha256": target_graph.binary_sha256,
                    "search_index_sha256": search_index.index_sha256,
                    "rva_start": rva_start,
                    "rva_end": rva_end,
                    "target_unit_ids": list(unit_ids),
                    "catalog_function_id": function.function_id,
                }
                result = StaticSpanMatch(
                    match_id=stable_id("library-static-span-v1", binding),
                    target_rva_start=rva_start,
                    target_rva_end=rva_end,
                    target_unit_ids=unit_ids,
                    catalog_function_id=function.function_id,
                    evidence=("relocation_masked_static_span",),
                )
                results[(rva_start, rva_end, function.function_id)] = result
    return tuple(sorted(results.values()))


__all__ = ["StaticSpanMatch", "discover_static_span_matches"]
