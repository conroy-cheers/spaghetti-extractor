from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

from .byteclasses import rebuild_executable_byte_classes
from .db import connect, initialize
from .labels import (
    basic_block_label,
    call_edge_label,
    cfg_edge_label,
    data_ref_label,
    ensure_label,
    ensure_oracle_mapping,
    function_label,
    global_label,
)
from .util import json_dumps, utc_now


DEFAULT_GHIDRA_SCRIPT = "HaloCatalogExport.java"


def run_ghidra_export(
    db_path: Path,
    *,
    out_dir: Path,
    project_dir: Path,
    project_name: str = "halo-catalog",
    analyze_headless: str | None = None,
    script_path: Path | None = None,
    scopes: Iterable[str] = ("included",),
    filenames: Iterable[str] | None = None,
    import_results: bool = True,
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Run Ghidra headless export for cataloged PE files and optionally import it.

    Ghidra remains a private metadata discovery step. The exported JSON is
    limited to RVAs, labels, blocks, edges, and references consumed by
    import_ghidra_json().
    """

    analyze_headless = _resolve_analyze_headless(analyze_headless)
    script_path = _resolve_script_path(script_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    project_dir.mkdir(parents=True, exist_ok=True)

    rows = _select_binaries(db_path, scopes=scopes, filenames=filenames)
    if not rows:
        raise ValueError("no cataloged binaries matched the requested scope/filename filters")

    result: dict[str, Any] = {
        "selected": len(rows),
        "exported": 0,
        "imported": {
            "functions": 0,
            "function_semantics": 0,
            "basic_blocks": 0,
            "block_semantics": 0,
            "cfg_edges": 0,
            "call_edges": 0,
            "data_refs": 0,
            "globals": 0,
        },
        "exports": [],
        "failures": [],
    }

    for row in rows:
        binary_path = (Path(row["source_root"]) / str(row["path"])).resolve()
        export_path = out_dir / f"{_safe_name(str(row['label']))}.ghidra.json"
        project = _safe_name(f"{project_name}-{Path(str(row['filename'])).stem}-{str(row['sha256'])[:12]}")

        export_record: dict[str, Any] = {
            "binary": str(row["path"]),
            "filename": str(row["filename"]),
            "sha256": str(row["sha256"]),
            "json": str(export_path),
            "project": project,
        }
        result["exports"].append(export_record)

        if not binary_path.is_file():
            result["failures"].append(
                {
                    **export_record,
                    "error": f"binary file not found: {binary_path}",
                }
            )
            continue

        command = [
            analyze_headless,
            str(project_dir),
            project,
            "-import",
            str(binary_path),
            "-scriptPath",
            str(script_path),
            "-postScript",
            DEFAULT_GHIDRA_SCRIPT,
            str(export_path),
            str(row["sha256"]),
            "-deleteProject",
        ]

        try:
            proc = subprocess.run(
                command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
            )
        except FileNotFoundError as exc:
            result["failures"].append(
                {
                    **export_record,
                    "error": f"analyzeHeadless not found: {exc.filename or analyze_headless}",
                }
            )
            break
        except subprocess.TimeoutExpired as exc:
            result["failures"].append(
                {
                    **export_record,
                    "error": f"Ghidra export timed out after {timeout_seconds} seconds",
                    "stdout": exc.stdout or "",
                    "stderr": exc.stderr or "",
                }
            )
            continue

        export_record["returncode"] = proc.returncode
        if proc.returncode != 0:
            result["failures"].append(
                {
                    **export_record,
                    "error": "Ghidra export failed",
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                }
            )
            continue

        result["exported"] += 1
        if import_results:
            try:
                counts = import_ghidra_json(db_path, export_path)
            except Exception as exc:
                result["failures"].append(
                    {
                        **export_record,
                        "error": f"Ghidra metadata import failed: {exc}",
                    }
                )
                continue
            for key, value in counts.items():
                result["imported"][key] = int(result["imported"].get(key, 0)) + int(value)
            export_record["imported"] = counts

    return result


def import_ghidra_json(db_path: Path, json_path: Path) -> dict[str, int]:
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    binary_sha = payload.get("binary_sha256")
    if not binary_sha:
        raise ValueError(f"{json_path} lacks binary_sha256")

    conn = connect(db_path)
    initialize(conn)
    try:
        binary = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (binary_sha,)).fetchone()
        if binary is None:
            raise ValueError(f"{json_path} references unknown binary sha256 {binary_sha}")
        binary_id = int(binary["id"])
        binary_row = conn.execute("SELECT label, sha256 FROM binaries WHERE id = ?", (binary_id,)).fetchone()
        binary_label = str(binary_row["label"])
        module_sha = str(binary_row["sha256"])

        with conn:
            functions = _insert_functions(conn, binary_id, binary_label, module_sha, payload.get("functions", []))
            function_ranges = _function_ranges(conn, binary_id, payload.get("functions", []))
            blocks = _insert_blocks(
                conn,
                binary_id,
                binary_label,
                module_sha,
                payload.get("basic_blocks", []),
                function_ranges,
            )
            function_ranges = _function_ranges(conn, binary_id, payload.get("functions", []))
            cfg_edges = _insert_cfg_edges(
                conn,
                binary_id,
                binary_label,
                module_sha,
                payload.get("cfg_edges", []),
                function_ranges,
            )
            call_edges = _insert_call_edges(conn, binary_id, binary_label, module_sha, payload.get("call_edges", []))
            data_refs = _insert_data_refs(conn, binary_id, binary_label, module_sha, payload.get("data_refs", []))
            globals_ = _insert_globals(conn, binary_id, binary_label, module_sha, payload.get("globals", []))
            function_semantics = _insert_function_semantics(
                conn,
                binary_id,
                payload.get("functions", []),
                function_ranges,
            )
            block_semantics = _insert_block_semantics(
                conn,
                binary_id,
                payload.get("basic_blocks", []),
                function_ranges,
            )
            block_function_backfills = _backfill_block_function_ids(conn, binary_id, function_ranges)
            block_alignment_classifications = _classify_alignment_blocks(conn, binary_id, function_ranges)
            rebuild_executable_byte_classes(conn, binary_id)

        return {
            "functions": functions,
            "function_semantics": function_semantics,
            "basic_blocks": blocks,
            "block_semantics": block_semantics,
            "block_function_backfills": block_function_backfills,
            "block_alignment_classifications": block_alignment_classifications,
            "cfg_edges": cfg_edges,
            "call_edges": call_edges,
            "data_refs": data_refs,
            "globals": globals_,
        }
    finally:
        conn.close()


def _insert_functions(conn: Any, binary_id: int, binary_label_value: str, module_sha: str, rows: list[dict[str, Any]]) -> int:
    inserted = 0
    for row in rows:
        rva = int(row["rva"])
        name = str(row.get("name") or f"sub_{rva:x}")
        calling_convention = str(row.get("calling_convention", "unknown"))
        signature = str(row.get("signature", "unknown"))
        confidence = str(row.get("confidence", "medium"))
        existing = conn.execute(
            """
            SELECT id
            FROM functions
            WHERE binary_id = ?
              AND rva = ?
            ORDER BY CASE WHEN source = 'ghidra' THEN 0 ELSE 1 END, id
            LIMIT 1
            """,
            (binary_id, rva),
        ).fetchone()
        if existing is not None:
            conn.execute(
                """
                UPDATE functions
                SET calling_convention = CASE WHEN calling_convention = 'unknown' THEN ? ELSE calling_convention END,
                    signature = CASE WHEN signature = 'unknown' THEN ? ELSE signature END,
                    confidence = CASE WHEN confidence IN ('low', 'unknown') THEN ? ELSE confidence END
                WHERE id = ?
                """,
                (calling_convention, signature, confidence, int(existing["id"])),
            )
            continue
        label = function_label(binary_label_value, rva, "ghidra", name)
        ensure_label(conn, label, "function", f"{binary_label_value}:{name}", "Ghidra-discovered function")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="function",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=rva,
            rva_end=None,
            private={"name": name, "source": "ghidra"},
        )
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO functions(
              label, binary_id, rva, name, source, calling_convention, signature, subsystem, purity,
              side_effects, confidence, test_status, clean_room_status
            )
            VALUES (?, ?, ?, ?, 'ghidra', ?, ?, ?, ?, ?, ?, 'untested', 'needs-spec')
            """,
            (
                label,
                binary_id,
                rva,
                name,
                calling_convention,
                signature,
                str(row.get("subsystem", "unknown")),
                str(row.get("purity", "unknown")),
                str(row.get("side_effects", "unknown")),
                confidence,
            ),
        )
        inserted += int(cursor.rowcount or 0)
    return inserted


def _function_ranges(conn: Any, binary_id: int, payload_functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    explicit_end_by_rva: dict[int, int] = {}
    for row in payload_functions:
        try:
            rva = int(row["rva"])
        except (KeyError, TypeError, ValueError):
            continue
        rva_end = _row_int(row, "rva_end", "body_rva_end", "end_rva")
        if rva_end is not None and rva_end > rva:
            explicit_end_by_rva[rva] = rva_end

    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, label, rva, name
            FROM functions
            WHERE binary_id = ?
            ORDER BY rva, id
            """,
            (binary_id,),
        )
    ]
    ranges: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        start = int(row["rva"])
        next_start = int(rows[index + 1]["rva"]) if index + 1 < len(rows) else None
        explicit_end = explicit_end_by_rva.get(start)
        end = explicit_end if explicit_end is not None else next_start
        ranges.append(
            {
                **row,
                "rva_start": start,
                "rva_end": end,
                "rva_end_source": "explicit" if explicit_end is not None else "next_function",
            }
        )
    return ranges


def _function_id_for_rva(
    rva: int,
    function_rva: int | None,
    function_ranges: list[dict[str, Any]],
) -> int | None:
    if function_rva is not None:
        for row in function_ranges:
            if int(row["rva_start"]) == function_rva:
                return int(row["id"])
    containing: dict[str, Any] | None = None
    for row in function_ranges:
        start = int(row["rva_start"])
        end = row.get("rva_end")
        end_int = int(end) if end is not None else None
        if start <= rva and (end_int is None or rva < end_int):
            containing = row
            break
    if containing is not None:
        return int(containing["id"])
    previous = [row for row in function_ranges if int(row["rva_start"]) <= rva]
    if previous:
        return int(previous[-1]["id"])
    return None


def _backfill_block_function_ids(conn: Any, binary_id: int, function_ranges: list[dict[str, Any]]) -> int:
    prepared: list[tuple[int, int]] = []
    for row in conn.execute(
        """
        SELECT id, rva_start
        FROM basic_blocks
        WHERE binary_id = ?
          AND function_id IS NULL
        ORDER BY rva_start, rva_end
        """,
        (binary_id,),
    ):
        function_id = _function_id_for_rva(int(row["rva_start"]), None, function_ranges)
        if function_id is not None:
            prepared.append((function_id, int(row["id"])))
    before = conn.total_changes
    conn.executemany("UPDATE basic_blocks SET function_id = ? WHERE id = ?", prepared)
    return conn.total_changes - before


def _classify_alignment_blocks(conn: Any, binary_id: int, function_ranges: list[dict[str, Any]]) -> int:
    starts = sorted({int(row["rva_start"]) for row in function_ranges})
    gaps: list[tuple[int, int | None]] = []
    for row in function_ranges:
        if row.get("rva_end_source") != "explicit" or row.get("rva_end") is None:
            continue
        end = int(row["rva_end"])
        later_starts = [start for start in starts if start > int(row["rva_start"])]
        next_start = later_starts[0] if later_starts else None
        if next_start is None or end < next_start:
            gaps.append((end, next_start))
    prepared: list[tuple[int]] = []
    for block in conn.execute(
        """
        SELECT id, rva_start, rva_end
        FROM basic_blocks
        WHERE binary_id = ?
          AND source != 'ghidra'
          AND classification = 'code'
        ORDER BY rva_start, rva_end
        """,
        (binary_id,),
    ):
        start = int(block["rva_start"])
        end = int(block["rva_end"])
        for gap_start, gap_end in gaps:
            if start >= gap_start and (gap_end is None or end <= gap_end):
                prepared.append((int(block["id"]),))
                break
    before = conn.total_changes
    conn.executemany(
        "UPDATE basic_blocks SET classification = 'padding/alignment', confidence = 'high' WHERE id = ?",
        prepared,
    )
    return conn.total_changes - before


def _insert_function_semantics(
    conn: Any,
    binary_id: int,
    rows: list[dict[str, Any]],
    function_ranges: list[dict[str, Any]],
) -> int:
    prepared = []
    imported_at = utc_now()
    for row in rows:
        try:
            rva = int(row["rva"])
        except (KeyError, TypeError, ValueError):
            continue
        function_id = _function_id_for_rva(rva, rva, function_ranges)
        if function_id is None:
            continue
        decompiler = _mapping(_first_present(row, "decompiler", "decompiler_artifact", default={}))
        decompiled_c = str(
            _first_present(
                row,
                "decompiled_c",
                "decompiler_c",
                default=_first_present(decompiler, "c", "code", "decompiled_c", default=""),
            )
            or ""
        )
        decompiler_error = str(_first_present(row, "decompiler_error", default=decompiler.get("error", "")) or "")
        pcode = _list(_first_present(row, "pcode", "pcode_ops", default=decompiler.get("pcode", [])))
        status = str(_first_present(row, "decompiler_status", default=decompiler.get("status", "")) or "")
        if not status:
            if decompiled_c or pcode:
                status = "success"
            elif decompiler_error:
                status = "error"
            else:
                status = "not_available"
        rva_end = _row_int(row, "rva_end", "body_rva_end", "end_rva")
        prepared.append(
            (
                function_id,
                binary_id,
                rva,
                rva_end,
                str(row.get("semantic_source") or row.get("source") or "ghidra"),
                status,
                decompiler_error,
                decompiled_c,
                json_dumps(_list(_first_present(row, "variables", "locals", "parameters", default=[]))),
                json_dumps(_first_present(row, "inferred_types", "types", default={})),
                json_dumps(_list(_first_present(row, "stack_refs", "stack_references", default=[]))),
                json_dumps(_list(_first_present(row, "global_refs", "global_references", default=[]))),
                json_dumps(_list(_first_present(row, "strings", "string_refs", "string_references", default=[]))),
                json_dumps(_list(_first_present(row, "callsites", "call_sites", default=[]))),
                json_dumps(_list(_first_present(row, "instructions", "instruction_metadata", default=[]))),
                json_dumps(pcode),
                json_dumps(_semantic_source_summary(row, decompiler)),
                imported_at,
            )
        )
    before = conn.total_changes
    conn.executemany(
        """
        INSERT INTO function_semantics(
          function_id, binary_id, rva_start, rva_end, source, decompiler_status,
          decompiler_error, decompiled_c, variables_json, inferred_types_json,
          stack_refs_json, global_refs_json, strings_json, callsites_json,
          instructions_json, pcode_json, source_json, imported_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(function_id) DO UPDATE SET
          rva_end = excluded.rva_end,
          source = excluded.source,
          decompiler_status = excluded.decompiler_status,
          decompiler_error = excluded.decompiler_error,
          decompiled_c = excluded.decompiled_c,
          variables_json = excluded.variables_json,
          inferred_types_json = excluded.inferred_types_json,
          stack_refs_json = excluded.stack_refs_json,
          global_refs_json = excluded.global_refs_json,
          strings_json = excluded.strings_json,
          callsites_json = excluded.callsites_json,
          instructions_json = excluded.instructions_json,
          pcode_json = excluded.pcode_json,
          source_json = excluded.source_json,
          imported_at = excluded.imported_at
        """,
        prepared,
    )
    return conn.total_changes - before


def _insert_block_semantics(
    conn: Any,
    binary_id: int,
    rows: list[dict[str, Any]],
    function_ranges: list[dict[str, Any]],
) -> int:
    prepared = []
    imported_at = utc_now()
    function_semantics_by_id = {
        int(row["function_id"]): dict(row)
        for row in conn.execute("SELECT * FROM function_semantics WHERE binary_id = ?", (binary_id,))
    }
    for row in rows:
        try:
            rva_start = int(row["rva_start"])
            rva_end = int(row["rva_end"])
        except (KeyError, TypeError, ValueError):
            continue
        block = conn.execute(
            """
            SELECT id, function_id
            FROM basic_blocks
            WHERE binary_id = ?
              AND rva_start = ?
              AND rva_end = ?
              AND source = 'ghidra'
            """,
            (binary_id, rva_start, rva_end),
        ).fetchone()
        if block is None:
            continue
        function_id = int(block["function_id"]) if block["function_id"] is not None else _function_id_for_rva(
            rva_start,
            _row_int(row, "function_rva", "parent_function_rva"),
            function_ranges,
        )
        if block["function_id"] is None and function_id is not None:
            conn.execute("UPDATE basic_blocks SET function_id = ? WHERE id = ?", (function_id, int(block["id"])))
        function_semantics = function_semantics_by_id.get(function_id or -1, {})
        instructions = _list(_first_present(row, "instructions", "instruction_metadata", default=[]))
        if not instructions:
            instructions = _slice_ranged_items(_json_list(function_semantics.get("instructions_json")), rva_start, rva_end)
        pcode = _list(_first_present(row, "pcode", "pcode_ops", default=[]))
        if not pcode:
            pcode = _slice_ranged_items(_json_list(function_semantics.get("pcode_json")), rva_start, rva_end)
        decompiler_status = _mapping(
            _first_present(
                row,
                "decompiler",
                "decompiler_status",
                default={
                    "status": function_semantics.get("decompiler_status") or "not_available",
                    "reason": function_semantics.get("decompiler_error") or "",
                    "source": function_semantics.get("source") or "ghidra",
                },
            )
        )
        if "status" not in decompiler_status:
            decompiler_status = {"status": str(decompiler_status or "not_available")}
        prepared.append(
            (
                int(block["id"]),
                binary_id,
                function_id,
                rva_start,
                rva_end,
                str(row.get("semantic_source") or row.get("source") or "ghidra"),
                json_dumps(instructions),
                json_dumps(pcode),
                json_dumps(_first_present(row, "data_flow", "dataflow", default={})),
                json_dumps(_first_present(row, "xrefs", "cross_references", default={})),
                str(row.get("semantic_summary") or row.get("summary") or ""),
                json_dumps(decompiler_status),
                imported_at,
            )
        )
    before = conn.total_changes
    conn.executemany(
        """
        INSERT INTO block_semantics(
          basic_block_id, binary_id, function_id, rva_start, rva_end, source,
          instructions_json, pcode_json, data_flow_json, xrefs_json,
          semantic_summary, decompiler_status_json, imported_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(basic_block_id) DO UPDATE SET
          function_id = excluded.function_id,
          rva_start = excluded.rva_start,
          rva_end = excluded.rva_end,
          source = excluded.source,
          instructions_json = excluded.instructions_json,
          pcode_json = excluded.pcode_json,
          data_flow_json = excluded.data_flow_json,
          xrefs_json = excluded.xrefs_json,
          semantic_summary = excluded.semantic_summary,
          decompiler_status_json = excluded.decompiler_status_json,
          imported_at = excluded.imported_at
        """,
        prepared,
    )
    return conn.total_changes - before


def _semantic_source_summary(row: dict[str, Any], decompiler: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": row.get("schema") or row.get("schema_version"),
        "exporter": row.get("exporter") or "ghidra",
        "has_decompiler": bool(row.get("decompiled_c") or row.get("decompiler_c") or decompiler),
        "has_instruction_metadata": bool(row.get("instructions") or row.get("instruction_metadata")),
        "has_pcode": bool(row.get("pcode") or row.get("pcode_ops") or decompiler.get("pcode")),
    }


def _row_int(row: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _first_present(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if not isinstance(value, str) or not value:
        return []
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def _slice_ranged_items(items: list[Any], rva_start: int, rva_end: int) -> list[Any]:
    result: list[Any] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        item_rva = _row_int(item, "rva", "rva_start", "address_rva")
        if item_rva is None:
            continue
        if rva_start <= item_rva < rva_end:
            result.append(item)
    return result


def _select_binaries(db_path: Path, *, scopes: Iterable[str], filenames: Iterable[str] | None) -> list[dict[str, Any]]:
    scope_values = [str(scope) for scope in scopes]
    if not scope_values:
        raise ValueError("at least one scope is required")
    filename_values = [filename.lower() for filename in filenames or []]

    conn = connect(db_path)
    initialize(conn)
    params: list[Any] = scope_values
    where = [f"scope IN ({', '.join('?' for _ in scope_values)})"]
    if filename_values:
        where.append(f"lower(filename) IN ({', '.join('?' for _ in filename_values)})")
        params.extend(filename_values)
    rows = conn.execute(
        f"""
        SELECT id, label, path, filename, sha256, source_root, scope
        FROM binaries
        WHERE {' AND '.join(where)}
        ORDER BY scope, path, sha256
        """,
        params,
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def _resolve_analyze_headless(value: str | None) -> str:
    if value:
        return value
    env_value = os.environ.get("WINCR_GHIDRA_HEADLESS") or os.environ.get("HALOCE_GHIDRA_HEADLESS")
    if env_value:
        return env_value
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    for env_name in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        ghidra_root = os.environ.get(env_name)
        if not ghidra_root:
            continue
        candidate = Path(ghidra_root) / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)
    return "analyzeHeadless"


def _resolve_script_path(value: Path | None) -> Path:
    candidates = []
    if value is not None:
        candidates.append(value)
    candidates.append(Path("tools/ghidra"))
    candidates.append(Path(__file__).resolve().parents[2] / "tools" / "ghidra")
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    searched = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"Ghidra script path not found; searched: {searched}")


def _safe_name(value: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")
    while "__" in safe:
        safe = safe.replace("__", "_")
    return safe[:96] or "item"


def _insert_blocks(
    conn: Any,
    binary_id: int,
    binary_label_value: str,
    module_sha: str,
    rows: list[dict[str, Any]],
    function_ranges: list[dict[str, Any]],
) -> int:
    prepared = []
    for row in rows:
        rva_start = int(row["rva_start"])
        rva_end = int(row["rva_end"])
        label = basic_block_label(binary_label_value, rva_start, rva_end, "ghidra")
        function_id = _function_id_for_rva(rva_start, _row_int(row, "function_rva", "parent_function_rva"), function_ranges)
        ensure_label(conn, label, "basic_block", f"{binary_label_value}:block", "Ghidra basic block")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="basic_block",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=rva_start,
            rva_end=rva_end,
            private={"source": "ghidra", "classification": row.get("classification", "code")},
        )
        prepared.append(
            (
                label,
                binary_id,
                function_id,
                rva_start,
                rva_end,
                rva_end - rva_start,
                str(row.get("classification", "code")),
                str(row.get("confidence", "medium")),
            )
        )
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO basic_blocks(
          label, binary_id, function_id, rva_start, rva_end, size, source, classification, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, 'ghidra', ?, ?)
        """,
        prepared,
    )
    inserted = conn.total_changes - before
    for label, _binary_id, function_id, *_rest in prepared:
        if function_id is not None:
            conn.execute("UPDATE basic_blocks SET function_id = COALESCE(function_id, ?) WHERE label = ?", (function_id, label))
    return inserted


def _insert_cfg_edges(
    conn: Any,
    binary_id: int,
    binary_label_value: str,
    module_sha: str,
    rows: list[dict[str, Any]],
    function_ranges: list[dict[str, Any]],
) -> int:
    prepared = []
    for row in rows:
        from_rva = int(row["from_rva"])
        to_rva = int(row["to_rva"])
        edge_type = str(row.get("edge_type", "flow"))
        label = cfg_edge_label(binary_label_value, from_rva, to_rva, edge_type, "ghidra")
        function_id = _function_id_for_rva(from_rva, _row_int(row, "function_rva", "parent_function_rva"), function_ranges)
        ensure_label(conn, label, "cfg_edge", f"{binary_label_value}:cfg", "Ghidra CFG edge")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="cfg_edge",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=from_rva,
            rva_end=to_rva,
            private={"source": "ghidra", "edge_type": edge_type},
        )
        prepared.append((label, binary_id, function_id, from_rva, to_rva, edge_type, str(row.get("confidence", "medium"))))
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO cfg_edges(label, binary_id, function_id, from_rva, to_rva, edge_type, source, confidence)
        VALUES (?, ?, ?, ?, ?, ?, 'ghidra', ?)
        """,
        prepared,
    )
    inserted = conn.total_changes - before
    for label, _binary_id, function_id, *_rest in prepared:
        if function_id is not None:
            conn.execute("UPDATE cfg_edges SET function_id = COALESCE(function_id, ?) WHERE label = ?", (function_id, label))
    return inserted


def _insert_call_edges(conn: Any, binary_id: int, binary_label_value: str, module_sha: str, rows: list[dict[str, Any]]) -> int:
    prepared = []
    for row in rows:
        caller_rva = int(row["caller_rva"])
        callee_rva = int(row["callee_rva"]) if row.get("callee_rva") is not None else None
        callee_symbol = row.get("callee_symbol")
        call_type = str(row.get("call_type", "direct"))
        label = call_edge_label(binary_label_value, caller_rva, None, callee_rva, callee_symbol, call_type, "ghidra")
        ensure_label(conn, label, "call_edge", f"{binary_label_value}:call", "Ghidra call edge")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="call_edge",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=caller_rva,
            rva_end=callee_rva,
            private={"source": "ghidra", "call_type": call_type, "callee_symbol": callee_symbol},
        )
        prepared.append((label, binary_id, caller_rva, callee_rva, callee_symbol, call_type, str(row.get("confidence", "medium"))))
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO call_edges(
          label, binary_id, caller_rva, callee_rva, callee_symbol, call_type, source, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, 'ghidra', ?)
        """,
        prepared,
    )
    return conn.total_changes - before


def _insert_data_refs(conn: Any, binary_id: int, binary_label_value: str, module_sha: str, rows: list[dict[str, Any]]) -> int:
    prepared = []
    for row in rows:
        from_rva = int(row["from_rva"])
        to_rva = int(row["to_rva"])
        ref_type = str(row.get("ref_type", "data"))
        label = data_ref_label(binary_label_value, from_rva, to_rva, ref_type, "ghidra")
        ensure_label(conn, label, "data_ref", f"{binary_label_value}:data-ref", "Ghidra data reference")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="data_ref",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=from_rva,
            rva_end=to_rva,
            private={"source": "ghidra", "ref_type": ref_type},
        )
        prepared.append((label, binary_id, from_rva, to_rva, ref_type, str(row.get("confidence", "medium"))))
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO data_refs(label, binary_id, from_rva, to_rva, ref_type, source, confidence)
        VALUES (?, ?, ?, ?, ?, 'ghidra', ?)
        """,
        prepared,
    )
    return conn.total_changes - before


def _insert_globals(conn: Any, binary_id: int, binary_label_value: str, module_sha: str, rows: list[dict[str, Any]]) -> int:
    prepared = []
    for row in rows:
        rva = int(row["rva"])
        name = str(row.get("name") or f"data_{rva:x}")
        data_type = str(row.get("data_type", "unknown"))
        label = global_label(binary_label_value, rva, name)
        ensure_label(conn, label, "global", f"{binary_label_value}:{name}", "Ghidra-discovered global/data symbol")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="global",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=rva,
            rva_end=int(row["rva_end"]) if row.get("rva_end") is not None else None,
            private={
                "source": "ghidra",
                "name": name,
                "data_type": data_type,
                "symbol_type": row.get("symbol_type", "unknown"),
            },
        )
        prepared.append(
            (
                label,
                binary_id,
                rva,
                name,
                data_type,
                str(row.get("subsystem", "unknown")),
                str(row.get("confidence", "medium")),
            )
        )
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO globals(label, binary_id, rva, name, data_type, subsystem, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        prepared,
    )
    return conn.total_changes - before
