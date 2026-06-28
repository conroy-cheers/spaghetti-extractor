from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from .labels import ensure_label, ensure_oracle_mapping, executable_byte_class_label


EXECUTABLE_BYTE_CLASSIFICATIONS = {
    "code",
    "thunk",
    "jump/data table",
    "padding/alignment",
    "dead/unreachable",
    "source-available external",
    "excluded tool/runtime",
    "vendor/replaceable",
    "unknown",
}

WAIVER_CATEGORY_CLASSIFICATION = {
    "proven-padding-data": "padding/alignment",
    "unreachable-dead-code": "dead/unreachable",
    "excluded-source-available-dependency": "source-available external",
    "excluded-installer-update-tool": "excluded tool/runtime",
    "platform-impossible-path": "dead/unreachable",
    "duplicate-compiler-runtime-thunk": "thunk",
    "legally-unsafe-distributable-artifact": "unknown",
}


@dataclass(frozen=True)
class _Overlay:
    rva_start: int
    rva_end: int
    classification: str
    source: str
    evidence: str
    confidence: str
    priority: int


@dataclass(frozen=True)
class _Segment:
    rva_start: int
    rva_end: int
    classification: str
    source: str
    evidence: str
    confidence: str


def rebuild_executable_byte_classes(conn: sqlite3.Connection, binary_id: int | None = None) -> dict[str, int]:
    """Rebuild executable-byte partitions from section, block, coverage, and waiver evidence."""

    binary_ids = _target_binary_ids(conn, binary_id)
    if not binary_ids:
        return {"binaries": 0, "byte_classes": 0}

    placeholders = ", ".join("?" for _ in binary_ids)
    conn.execute(f"DELETE FROM executable_byte_classes WHERE binary_id IN ({placeholders})", binary_ids)

    rows_inserted = 0
    ranges = conn.execute(
        f"""
        SELECT x.id, x.binary_id, x.rva_start, x.rva_end, x.classification, x.evidence,
               b.label AS binary_label, b.sha256 AS module_sha256, b.scope
        FROM executable_ranges x
        JOIN binaries b ON b.id = x.binary_id
        WHERE x.binary_id IN ({placeholders})
        ORDER BY x.binary_id, x.rva_start, x.rva_end
        """,
        binary_ids,
    ).fetchall()
    for executable_range in ranges:
        segments = _segments_for_range(conn, executable_range)
        rows_inserted += _insert_segments(conn, executable_range, segments)

    return {"binaries": len(binary_ids), "byte_classes": rows_inserted}


def _target_binary_ids(conn: sqlite3.Connection, binary_id: int | None) -> list[int]:
    if binary_id is not None:
        row = conn.execute("SELECT id FROM binaries WHERE id = ?", (binary_id,)).fetchone()
        return [int(row["id"])] if row is not None else []
    return [int(row["id"]) for row in conn.execute("SELECT id FROM binaries ORDER BY id")]


def _segments_for_range(conn: sqlite3.Connection, executable_range: sqlite3.Row) -> list[_Segment]:
    range_start = int(executable_range["rva_start"])
    range_end = int(executable_range["rva_end"])
    if range_end <= range_start:
        return []

    base = _Segment(
        rva_start=range_start,
        rva_end=range_end,
        classification=_normalize_classification(str(executable_range["classification"])),
        source="executable-range",
        evidence=str(executable_range["evidence"]),
        confidence="low",
    )
    overlays: list[_Overlay] = []
    if str(executable_range["scope"]) in {"included", "candidate"}:
        overlays.extend(_basic_block_overlays(conn, executable_range))
        overlays.extend(_ghidra_data_overlays(conn, executable_range))
        overlays.extend(_coverage_block_overlays(conn, executable_range))
        overlays.extend(_waiver_overlays(conn, executable_range))

    boundaries = {range_start, range_end}
    for overlay in overlays:
        boundaries.add(overlay.rva_start)
        boundaries.add(overlay.rva_end)
    ordered = sorted(boundaries)

    segments: list[_Segment] = []
    for start, end in zip(ordered, ordered[1:]):
        if end <= start:
            continue
        candidates = [overlay for overlay in overlays if overlay.rva_start <= start and overlay.rva_end >= end]
        if candidates:
            overlay = sorted(candidates, key=lambda item: (item.priority, item.source, item.evidence))[-1]
            segments.append(
                _Segment(
                    rva_start=start,
                    rva_end=end,
                    classification=overlay.classification,
                    source=overlay.source,
                    evidence=overlay.evidence,
                    confidence=overlay.confidence,
                )
            )
        else:
            segments.append(
                _Segment(
                    rva_start=start,
                    rva_end=end,
                    classification=base.classification,
                    source=base.source,
                    evidence=base.evidence,
                    confidence=base.confidence,
                )
            )
    return _coalesce_segments(segments)


def _basic_block_overlays(conn: sqlite3.Connection, executable_range: sqlite3.Row) -> list[_Overlay]:
    rows = conn.execute(
        """
        SELECT label, rva_start, rva_end, classification, source, confidence
        FROM basic_blocks
        WHERE binary_id = ?
          AND rva_start < ?
          AND rva_end > ?
        ORDER BY rva_start, rva_end, source
        """,
        (executable_range["binary_id"], executable_range["rva_end"], executable_range["rva_start"]),
    ).fetchall()
    overlays = []
    for row in rows:
        start, end = _clamped_overlap(row, executable_range)
        if start >= end:
            continue
        source = str(row["source"])
        overlays.append(
            _Overlay(
                rva_start=start,
                rva_end=end,
                classification=_normalize_classification(str(row["classification"])),
                source=source,
                evidence=f"basic block {row['label']}",
                confidence=str(row["confidence"]),
                priority=50,
            )
        )
    return overlays


def _coverage_block_overlays(conn: sqlite3.Connection, executable_range: sqlite3.Row) -> list[_Overlay]:
    rows = conn.execute(
        """
        SELECT cb.label, cb.rva_start, cb.rva_end, cb.source_log, tr.test_id
        FROM coverage_blocks cb
        JOIN test_runs tr ON tr.id = cb.test_run_id
        WHERE cb.binary_id = ?
          AND cb.rva_start < ?
          AND cb.rva_end > ?
        ORDER BY cb.rva_start, cb.rva_end, tr.test_id
        """,
        (executable_range["binary_id"], executable_range["rva_end"], executable_range["rva_start"]),
    ).fetchall()
    overlays = []
    for row in rows:
        start, end = _clamped_overlap(row, executable_range)
        if start >= end:
            continue
        overlays.append(
            _Overlay(
                rva_start=start,
                rva_end=end,
                classification="code",
                source="dynamic-coverage",
                evidence=f"coverage block {row['label']} from {row['test_id']}",
                confidence="medium",
                priority=40,
            )
        )
    return overlays


def _ghidra_data_overlays(conn: sqlite3.Connection, executable_range: sqlite3.Row) -> list[_Overlay]:
    rows = conn.execute(
        """
        SELECT g.label, g.name, g.data_type, om.rva_start, om.rva_end
        FROM globals g
        JOIN oracle_mappings om ON om.label = g.label
        WHERE g.binary_id = ?
          AND om.entity_type = 'global'
          AND om.rva_end IS NOT NULL
          AND om.rva_start < ?
          AND om.rva_end > ?
          AND NOT EXISTS (
            SELECT 1
            FROM basic_blocks bb
            WHERE bb.binary_id = g.binary_id
              AND bb.rva_start < om.rva_end
              AND bb.rva_end > om.rva_start
          )
          AND NOT EXISTS (
            SELECT 1
            FROM coverage_blocks cb
            WHERE cb.binary_id = g.binary_id
              AND cb.rva_start < om.rva_end
              AND cb.rva_end > om.rva_start
          )
        ORDER BY om.rva_start, om.rva_end, g.name
        """,
        (executable_range["binary_id"], executable_range["rva_end"], executable_range["rva_start"]),
    ).fetchall()
    overlays = []
    for row in rows:
        start, end = _clamped_overlap(row, executable_range)
        if start >= end:
            continue
        overlays.append(
            _Overlay(
                rva_start=start,
                rva_end=end,
                classification="jump/data table",
                source="ghidra-data",
                evidence=f"defined data {row['label']} {row['name']} ({row['data_type']})",
                confidence="medium",
                priority=30,
            )
        )
    return overlays


def _waiver_overlays(conn: sqlite3.Connection, executable_range: sqlite3.Row) -> list[_Overlay]:
    rows = conn.execute(
        """
        SELECT label, rva_start, rva_end, category, reason, evidence
        FROM waivers
        WHERE binary_id = ?
          AND rva_start < ?
          AND rva_end > ?
        ORDER BY rva_start, rva_end, category
        """,
        (executable_range["binary_id"], executable_range["rva_end"], executable_range["rva_start"]),
    ).fetchall()
    overlays = []
    for row in rows:
        start, end = _clamped_overlap(row, executable_range)
        if start >= end:
            continue
        overlays.append(
            _Overlay(
                rva_start=start,
                rva_end=end,
                classification=WAIVER_CATEGORY_CLASSIFICATION.get(str(row["category"]), "unknown"),
                source="waiver",
                evidence=f"{row['label']}: {row['category']}: {row['reason']} ({row['evidence']})",
                confidence="high",
                priority=100,
            )
        )
    return overlays


def _clamped_overlap(row: Any, executable_range: sqlite3.Row) -> tuple[int, int]:
    start = max(int(row["rva_start"]), int(executable_range["rva_start"]))
    end = min(int(row["rva_end"]), int(executable_range["rva_end"]))
    return start, end


def _coalesce_segments(segments: list[_Segment]) -> list[_Segment]:
    if not segments:
        return []
    coalesced = [segments[0]]
    for segment in segments[1:]:
        previous = coalesced[-1]
        if (
            previous.rva_end == segment.rva_start
            and previous.classification == segment.classification
            and previous.source == segment.source
            and previous.evidence == segment.evidence
            and previous.confidence == segment.confidence
        ):
            coalesced[-1] = _Segment(
                rva_start=previous.rva_start,
                rva_end=segment.rva_end,
                classification=previous.classification,
                source=previous.source,
                evidence=previous.evidence,
                confidence=previous.confidence,
            )
        else:
            coalesced.append(segment)
    return coalesced


def _insert_segments(conn: sqlite3.Connection, executable_range: sqlite3.Row, segments: list[_Segment]) -> int:
    rows = []
    binary_label = str(executable_range["binary_label"])
    module_sha = str(executable_range["module_sha256"])
    for segment in segments:
        label = executable_byte_class_label(
            binary_label,
            segment.rva_start,
            segment.rva_end,
            segment.classification,
            segment.source,
        )
        ensure_label(
            conn,
            label,
            "executable_byte_class",
            f"{binary_label}:{segment.classification}",
            segment.evidence,
        )
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="executable_byte_class",
            binary_id=int(executable_range["binary_id"]),
            module_sha256=module_sha,
            rva_start=segment.rva_start,
            rva_end=segment.rva_end,
            private={
                "classification": segment.classification,
                "source": segment.source,
                "evidence": segment.evidence,
                "executable_range_id": int(executable_range["id"]),
            },
        )
        rows.append(
            (
                label,
                int(executable_range["binary_id"]),
                int(executable_range["id"]),
                segment.rva_start,
                segment.rva_end,
                segment.classification,
                segment.source,
                segment.evidence,
                segment.confidence,
            )
        )
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO executable_byte_classes(
          label, binary_id, executable_range_id, rva_start, rva_end,
          classification, source, evidence, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    return conn.total_changes - before


def _normalize_classification(value: str) -> str:
    return value if value in EXECUTABLE_BYTE_CLASSIFICATIONS else "unknown"
