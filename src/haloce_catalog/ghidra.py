from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import connect, initialize


def import_ghidra_json(db_path: Path, json_path: Path) -> dict[str, int]:
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    binary_sha = payload.get("binary_sha256")
    if not binary_sha:
        raise ValueError(f"{json_path} lacks binary_sha256")

    conn = connect(db_path)
    initialize(conn)
    binary = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (binary_sha,)).fetchone()
    if binary is None:
        raise ValueError(f"{json_path} references unknown binary sha256 {binary_sha}")
    binary_id = int(binary["id"])

    with conn:
        functions = _insert_functions(conn, binary_id, payload.get("functions", []))
        blocks = _insert_blocks(conn, binary_id, payload.get("basic_blocks", []))
        cfg_edges = _insert_cfg_edges(conn, binary_id, payload.get("cfg_edges", []))
        call_edges = _insert_call_edges(conn, binary_id, payload.get("call_edges", []))
        data_refs = _insert_data_refs(conn, binary_id, payload.get("data_refs", []))

    return {
        "functions": functions,
        "basic_blocks": blocks,
        "cfg_edges": cfg_edges,
        "call_edges": call_edges,
        "data_refs": data_refs,
    }


def _insert_functions(conn: Any, binary_id: int, rows: list[dict[str, Any]]) -> int:
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO functions(
          binary_id, rva, name, source, calling_convention, signature, subsystem, purity,
          side_effects, confidence, test_status, clean_room_status
        )
        VALUES (?, ?, ?, 'ghidra', ?, ?, ?, ?, ?, ?, 'untested', 'needs-spec')
        """,
        [
            (
                binary_id,
                int(row["rva"]),
                str(row.get("name") or f"sub_{int(row['rva']):x}"),
                str(row.get("calling_convention", "unknown")),
                str(row.get("signature", "unknown")),
                str(row.get("subsystem", "unknown")),
                str(row.get("purity", "unknown")),
                str(row.get("side_effects", "unknown")),
                str(row.get("confidence", "medium")),
            )
            for row in rows
        ],
    )
    return conn.total_changes - before


def _insert_blocks(conn: Any, binary_id: int, rows: list[dict[str, Any]]) -> int:
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO basic_blocks(
          binary_id, rva_start, rva_end, size, source, classification, confidence
        )
        VALUES (?, ?, ?, ?, 'ghidra', ?, ?)
        """,
        [
            (
                binary_id,
                int(row["rva_start"]),
                int(row["rva_end"]),
                int(row["rva_end"]) - int(row["rva_start"]),
                str(row.get("classification", "code")),
                str(row.get("confidence", "medium")),
            )
            for row in rows
        ],
    )
    return conn.total_changes - before


def _insert_cfg_edges(conn: Any, binary_id: int, rows: list[dict[str, Any]]) -> int:
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO cfg_edges(binary_id, from_rva, to_rva, edge_type, source, confidence)
        VALUES (?, ?, ?, ?, 'ghidra', ?)
        """,
        [
            (
                binary_id,
                int(row["from_rva"]),
                int(row["to_rva"]),
                str(row.get("edge_type", "flow")),
                str(row.get("confidence", "medium")),
            )
            for row in rows
        ],
    )
    return conn.total_changes - before


def _insert_call_edges(conn: Any, binary_id: int, rows: list[dict[str, Any]]) -> int:
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO call_edges(
          binary_id, caller_rva, callee_rva, callee_symbol, call_type, source, confidence
        )
        VALUES (?, ?, ?, ?, ?, 'ghidra', ?)
        """,
        [
            (
                binary_id,
                int(row["caller_rva"]),
                int(row["callee_rva"]) if row.get("callee_rva") is not None else None,
                row.get("callee_symbol"),
                str(row.get("call_type", "direct")),
                str(row.get("confidence", "medium")),
            )
            for row in rows
        ],
    )
    return conn.total_changes - before


def _insert_data_refs(conn: Any, binary_id: int, rows: list[dict[str, Any]]) -> int:
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO data_refs(binary_id, from_rva, to_rva, ref_type, source, confidence)
        VALUES (?, ?, ?, ?, 'ghidra', ?)
        """,
        [
            (
                binary_id,
                int(row["from_rva"]),
                int(row["to_rva"]),
                str(row.get("ref_type", "data")),
                str(row.get("confidence", "medium")),
            )
            for row in rows
        ],
    )
    return conn.total_changes - before
