from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .byteclasses import rebuild_executable_byte_classes
from .catalog import runtime_provenance, tool_versions
from .db import connect, initialize
from .labels import (
    coverage_block_label,
    coverage_call_label,
    coverage_edge_label,
    ensure_label,
    ensure_oracle_mapping,
    test_run_label,
    value_trace_label,
)
from .util import json_dumps, sha256_file, utc_now


@dataclass(frozen=True)
class DrcovModule:
    module_id: int
    path: str
    start: int | None = None
    end: int | None = None
    entry: int | None = None
    preferred_base: int | None = None


@dataclass(frozen=True)
class DrcovBlock:
    module_id: int
    start: int
    size: int


@dataclass(frozen=True)
class DrcovLog:
    modules: list[DrcovModule]
    blocks: list[DrcovBlock]


def parse_drcov_log(path: Path) -> DrcovLog:
    data = path.read_bytes()
    text_prefix = data[: min(len(data), 1024 * 1024)].decode("utf-8", errors="replace")
    modules = _parse_modules(text_prefix)
    blocks = _parse_text_blocks(text_prefix)
    if blocks is None:
        blocks = _parse_binary_blocks(data)
    return DrcovLog(modules=modules, blocks=blocks)


def ingest_drcov(db_path: Path, log_path: Path, test_id: str, *, suite: str = "drcov") -> dict[str, Any]:
    conn = connect(db_path)
    initialize(conn)
    parsed = parse_drcov_log(log_path)
    install_root_row = conn.execute("SELECT value FROM metadata WHERE key = 'install_root'").fetchone()
    install_root = Path(install_root_row["value"]) if install_root_row is not None else None
    started = utc_now()
    test_label = test_run_label(test_id, suite, started)
    with conn:
        ensure_label(conn, test_label, "test", test_id, f"{suite} imported coverage run", created_at=started)
        cursor = conn.execute(
            """
            INSERT INTO test_runs(
              label, test_id, suite, command, status, started_at, finished_at,
              tool_versions_json, provenance_json
            )
            VALUES (?, ?, ?, ?, 'imported', ?, ?, ?, ?)
            """,
            (
                test_label,
                test_id,
                suite,
                f"ingest-drcov {log_path}",
                started,
                utc_now(),
                json_dumps(tool_versions()),
                json_dumps(runtime_provenance()),
            ),
        )
        test_run_id = int(cursor.lastrowid)
        module_db_ids: dict[int, tuple[int, int | None, str | None, str | None]] = {}
        affected_binary_ids: set[int] = set()
        for module in parsed.modules:
            resolved_path = resolve_observed_path(module.path, install_root=install_root)
            module_sha = sha256_file(resolved_path) if resolved_path and resolved_path.exists() else None
            binary_id = _find_binary(conn, module_sha, module.path)
            if binary_id is not None:
                affected_binary_ids.add(binary_id)
            binary_label = _binary_label(conn, binary_id)
            cursor = conn.execute(
                """
                INSERT INTO observed_modules(
                  test_run_id, drcov_module_id, path, base, end, entry, preferred_base, sha256, binary_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    test_run_id,
                    module.module_id,
                    module.path,
                    module.start,
                    module.end,
                    module.entry,
                    module.preferred_base,
                    module_sha,
                    binary_id,
                ),
            )
            module_db_ids[module.module_id] = (int(cursor.lastrowid), binary_id, binary_label, module_sha)

        rows = []
        for block in parsed.blocks:
            module_ids = module_db_ids.get(block.module_id)
            if module_ids is None:
                continue
            observed_module_id, binary_id, binary_label, module_sha = module_ids
            label = coverage_block_label(test_label, binary_label, block.start, block.start + block.size)
            ensure_label(conn, label, "coverage_block", f"{test_id}:block", "dynamic basic-block coverage")
            ensure_oracle_mapping(
                conn,
                label=label,
                entity_type="coverage_block",
                binary_id=binary_id,
                module_sha256=module_sha,
                rva_start=block.start,
                rva_end=block.start + block.size,
                private={"test_id": test_id, "source_log": str(log_path)},
            )
            rows.append(
                (
                    label,
                    test_run_id,
                    observed_module_id,
                    binary_id,
                    block.start,
                    block.start + block.size,
                    block.size,
                    str(log_path),
                )
            )
        conn.executemany(
            """
            INSERT OR IGNORE INTO coverage_blocks(
              label, test_run_id, observed_module_id, binary_id, rva_start, rva_end, size, source_log
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        for affected_binary_id in sorted(affected_binary_ids):
            rebuild_executable_byte_classes(conn, affected_binary_id)

    return {
        "test_id": test_id,
        "modules": len(parsed.modules),
        "blocks": len(parsed.blocks),
        "mapped_blocks": len(rows),
    }


def ingest_trace(db_path: Path, log_path: Path, *, suite: str = "trace") -> dict[str, Any]:
    """Ingest JSONL emitted by the custom DynamoRIO client.

    Expected records:
      {"kind":"module","test_id":"...","pid":1,"module_name":"target.exe","module_sha256":"...","module_path":"...","drcov_module_id":0}
      {"kind":"block","test_id":"...","pid":1,"module_sha256":"...","rva_block":4096,"size":12}
      {"kind":"cfg_edge","test_id":"...","pid":1,"module_sha256":"...","rva_edge_from":4096,"rva_edge_to":4108}
      {"kind":"call_edge","test_id":"...","pid":1,"module_sha256":"...","caller_rva":4096,"callee_module_sha256":"...","callee_rva":8192}
      {"kind":"value_trace","test_id":"...","module_sha256":"...","routine_label":"fn_...","block_label":"bb_...","values":{...}}
      {"kind":"block_entry","test_id":"...","module_sha256":"...","rva_start":4096,"rva_end":4108,"state":{...}}
      {"kind":"block_exit","test_id":"...","module_sha256":"...","rva_start":4096,"rva_end":4108,"state":{...},"side_effects":{...}}
    """

    conn = connect(db_path)
    initialize(conn)
    started_by_test: dict[str, tuple[int, str]] = {}
    module_by_key: dict[tuple[str, int, str], tuple[int, int | None, str | None, str | None]] = {}
    counts = {"modules": 0, "blocks": 0, "cfg_edges": 0, "call_edges": 0, "value_traces": 0}
    next_module_id = 0
    affected_binary_ids: set[int] = set()

    with conn, log_path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            test_id = str(record["test_id"])
            pid = int(record.get("pid", 0))
            test_run_id, test_label = _ensure_trace_test_run(conn, started_by_test, test_id, suite, started_at=utc_now())
            kind = record.get("kind")
            if kind == "module":
                key = (test_id, pid, str(record["module_sha256"]))
                binary_id = _find_binary(conn, str(record["module_sha256"]), str(record.get("module_name", "")))
                if binary_id is not None:
                    affected_binary_ids.add(binary_id)
                binary_label = _binary_label(conn, binary_id)
                if "drcov_module_id" in record:
                    drcov_module_id = int(record["drcov_module_id"])
                    next_module_id = max(next_module_id, drcov_module_id + 1)
                else:
                    drcov_module_id = next_module_id
                    next_module_id += 1
                cursor = conn.execute(
                    """
                    INSERT INTO observed_modules(
                      test_run_id, drcov_module_id, path, base, end, entry, preferred_base, sha256, binary_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        test_run_id,
                        drcov_module_id,
                        str(record.get("module_path") or record.get("module_name") or ""),
                        record.get("base"),
                        record.get("end"),
                        record.get("entry"),
                        record.get("preferred_base"),
                        str(record["module_sha256"]),
                        binary_id,
                    ),
                )
                module_by_key[key] = (int(cursor.lastrowid), binary_id, binary_label, str(record["module_sha256"]))
                counts["modules"] += 1
            elif kind == "block":
                module, next_module_id = _trace_module(
                    conn, module_by_key, test_run_id, test_id, pid, record, next_module_id
                )
                observed_module_id, binary_id, binary_label, module_sha = module
                if binary_id is not None:
                    affected_binary_ids.add(binary_id)
                rva_start = int(record["rva_block"])
                size = int(record.get("size", 1))
                label = coverage_block_label(test_label, binary_label, rva_start, rva_start + size)
                ensure_label(conn, label, "coverage_block", f"{test_id}:block", "custom tracer basic-block coverage")
                ensure_oracle_mapping(
                    conn,
                    label=label,
                    entity_type="coverage_block",
                    binary_id=binary_id,
                    module_sha256=module_sha,
                    rva_start=rva_start,
                    rva_end=rva_start + size,
                    private={"test_id": test_id, "source_log": str(log_path), "pid": pid},
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO coverage_blocks(
                      label, test_run_id, observed_module_id, binary_id, rva_start, rva_end, size, source_log
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (label, test_run_id, observed_module_id, binary_id, rva_start, rva_start + size, size, str(log_path)),
                )
                counts["blocks"] += 1
            elif kind == "cfg_edge":
                module, next_module_id = _trace_module(
                    conn, module_by_key, test_run_id, test_id, pid, record, next_module_id
                )
                observed_module_id, binary_id, binary_label, module_sha = module
                from_rva = int(record["rva_edge_from"])
                to_rva = int(record["rva_edge_to"])
                label = coverage_edge_label(test_label, binary_label, from_rva, to_rva)
                ensure_label(conn, label, "coverage_edge", f"{test_id}:cfg", "custom tracer CFG edge coverage")
                ensure_oracle_mapping(
                    conn,
                    label=label,
                    entity_type="coverage_edge",
                    binary_id=binary_id,
                    module_sha256=module_sha,
                    rva_start=from_rva,
                    rva_end=to_rva,
                    private={"test_id": test_id, "source_log": str(log_path), "pid": pid},
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO coverage_edges(
                      label, test_run_id, observed_module_id, binary_id, from_rva, to_rva, source_log
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (label, test_run_id, observed_module_id, binary_id, from_rva, to_rva, str(log_path)),
                )
                counts["cfg_edges"] += 1
            elif kind == "call_edge":
                module, next_module_id = _trace_module(
                    conn, module_by_key, test_run_id, test_id, pid, record, next_module_id
                )
                observed_module_id, binary_id, binary_label, module_sha = module
                caller_rva = int(record["caller_rva"])
                callee_binary_id = _find_binary(conn, record.get("callee_module_sha256"), str(record.get("callee_symbol", "")))
                callee_label = _binary_label(conn, callee_binary_id)
                callee_rva = int(record["callee_rva"]) if record.get("callee_rva") is not None else None
                callee_symbol = record.get("callee_symbol")
                label = coverage_call_label(test_label, binary_label, caller_rva, callee_label, callee_rva, callee_symbol)
                ensure_label(conn, label, "coverage_call_edge", f"{test_id}:call", "custom tracer call-edge coverage")
                ensure_oracle_mapping(
                    conn,
                    label=label,
                    entity_type="coverage_call_edge",
                    binary_id=binary_id,
                    module_sha256=module_sha,
                    rva_start=caller_rva,
                    rva_end=callee_rva,
                    private={"test_id": test_id, "source_log": str(log_path), "pid": pid, "callee_symbol": callee_symbol},
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO coverage_call_edges(
                      label, test_run_id, observed_module_id, binary_id, caller_rva,
                      callee_binary_id, callee_rva, callee_symbol, source_log
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        label,
                        test_run_id,
                        observed_module_id,
                        binary_id,
                        caller_rva,
                        callee_binary_id,
                        callee_rva,
                        callee_symbol,
                        str(log_path),
                    ),
                )
                counts["call_edges"] += 1
            elif kind in {"value_trace", "semantic_value"}:
                module_sha = str(record["module_sha256"])
                routine_label = record.get("routine_label")
                block_label = record.get("block_label")
                value_rva = _parse_int(str(record["rva"])) if record.get("rva") is not None else None
                binary_id = _find_binary(conn, module_sha, str(record.get("module_name", "")))
                if value_rva is not None and binary_id is not None and (routine_label is None or block_label is None):
                    mapped_value = _labels_for_value_rva(conn, binary_id, value_rva)
                    routine_label = routine_label or mapped_value.get("routine_label")
                    block_label = block_label or mapped_value.get("block_label")
                label = value_trace_label(
                    test_id,
                    module_sha,
                    str(routine_label) if routine_label is not None else None,
                    str(block_label) if block_label is not None else None,
                )
                ensure_label(conn, label, "value_trace", f"{test_id}:values", "bounded semantic value trace")
                ensure_oracle_mapping(
                    conn,
                    label=label,
                    entity_type="value_trace",
                    binary_id=binary_id,
                    module_sha256=module_sha,
                    rva_start=value_rva,
                    rva_end=value_rva,
                    private={"test_id": test_id, "source_log": str(log_path), "pid": pid},
                )
                conn.execute(
                    """
                    INSERT INTO value_traces(
                      label, test_id, module_sha256, routine_label, block_label,
                      values_json, provenance_json, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(test_id, module_sha256, routine_label, block_label) DO UPDATE SET
                      values_json = excluded.values_json,
                      provenance_json = excluded.provenance_json,
                      created_at = excluded.created_at
                    """,
                    (
                        label,
                        test_id,
                        module_sha,
                        str(routine_label) if routine_label is not None else None,
                        str(block_label) if block_label is not None else None,
                        json_dumps(record.get("values") or {}),
                        json_dumps(
                            {
                                "source_log": str(log_path),
                                "pid": pid,
                                "profile": record.get("profile") or record.get("semantic_profile"),
                                "api_boundary": record.get("api_boundary"),
                            }
                        ),
                        utc_now(),
                    ),
                )
                counts["value_traces"] += 1
            elif kind in {"block_entry", "block_exit"}:
                counts["block_state_records"] = counts.get("block_state_records", 0) + 1
            else:
                raise ValueError(f"unknown trace record kind: {kind}")

        for affected_binary_id in sorted(affected_binary_ids):
            rebuild_executable_byte_classes(conn, affected_binary_id)

    return counts


def _labels_for_value_rva(conn: sqlite3.Connection, binary_id: int, rva: int) -> dict[str, str | None]:
    row = conn.execute(
        """
        SELECT bb.label AS block_label, f.label AS routine_label
        FROM basic_blocks bb
        LEFT JOIN functions f ON f.id = bb.function_id
        WHERE bb.binary_id = ?
          AND bb.rva_start <= ?
          AND bb.rva_end > ?
        ORDER BY bb.rva_start DESC, bb.rva_end ASC
        LIMIT 1
        """,
        (binary_id, rva, rva),
    ).fetchone()
    if row is not None:
        routine_label = row["routine_label"]
        if routine_label is None:
            routine_label = _function_label_for_rva(conn, binary_id, rva)
        return {"block_label": row["block_label"], "routine_label": routine_label}
    return {"block_label": None, "routine_label": _function_label_for_rva(conn, binary_id, rva)}


def _function_label_for_rva(conn: sqlite3.Connection, binary_id: int, rva: int) -> str | None:
    routine = conn.execute(
        """
        SELECT f.label
        FROM function_semantics fs
        JOIN functions f ON f.id = fs.function_id
        WHERE fs.binary_id = ?
          AND fs.rva_start <= ?
          AND (fs.rva_end IS NULL OR fs.rva_end > ?)
        ORDER BY fs.rva_start DESC, fs.rva_end IS NULL ASC, fs.rva_end ASC
        LIMIT 1
        """,
        (binary_id, rva, rva),
    ).fetchone()
    if routine is not None:
        return str(routine["label"])
    routine = conn.execute(
        """
        SELECT f.label
        FROM functions f
        JOIN basic_blocks bb ON bb.function_id = f.id
        WHERE f.binary_id = ?
          AND f.rva <= ?
          AND bb.rva_end > ?
        GROUP BY f.id, f.label, f.rva
        ORDER BY f.rva DESC
        LIMIT 1
        """,
        (binary_id, rva, rva),
    ).fetchone()
    return str(routine["label"]) if routine is not None else None


def ingest_halo_trace(db_path: Path, log_path: Path, *, suite: str = "halo-trace") -> dict[str, Any]:
    return ingest_trace(db_path, log_path, suite=suite)


def prove_trace(
    db_path: Path,
    out_path: Path,
    test_id: str,
    app: list[str],
    *,
    expected_filename: str | None = None,
    expected_sha256: str | None = None,
    arch: str = "auto",
    trace_runner: str | None = None,
    timeout_seconds: int | None = None,
    suite: str = "halo-trace",
    allow_timeout: bool = True,
    pretraced: bool = False,
    expected_returncode: int | None = 0,
    semantic_profile: bool = False,
    semantic_max_records: int = 128,
    block_state_trace: bool = False,
    block_state_max_records: int = 8192,
) -> dict[str, Any]:
    app = list(app)
    if app and app[0] == "--":
        app = app[1:]
    if not app:
        raise ValueError("prove_trace requires an application command after --")

    expected = _expected_binary(db_path, expected_filename=expected_filename, expected_sha256=expected_sha256)
    if expected is None:
        raise ValueError("expected module not found; pass --expected-filename or --expected-sha256 for a cataloged binary")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    trace_env = os.environ.copy()
    trace_env["WINCR_TRACE_OUT"] = str(out_path.resolve())
    trace_env["WINCR_TRACE_TEST_ID"] = test_id
    trace_env["HALOCE_TRACE_OUT"] = str(out_path.resolve())
    trace_env["HALOCE_TRACE_TEST_ID"] = test_id
    if pretraced:
        command = app
    else:
        runner_args = [
            _resolve_trace_runner(trace_runner),
            "--out",
            str(out_path),
            "--test-id",
            test_id,
            "--arch",
            arch,
        ]
        if semantic_profile:
            runner_args.extend(["--semantic-profile", "--semantic-max-records", str(max(1, semantic_max_records))])
        if block_state_trace:
            runner_args.extend(["--block-state-trace", "--block-state-max-records", str(max(1, block_state_max_records))])
        command = [
            *runner_args,
            "--",
            *app,
        ]

    timed_out = False
    stdout_path = out_path.with_name(out_path.stem + ".process-stdout.txt")
    stderr_path = out_path.with_name(out_path.stem + ".process-stderr.txt")
    try:
        with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout_handle, stderr_path.open(
            "w", encoding="utf-8", errors="replace"
        ) as stderr_handle:
            proc = subprocess.run(
                command,
                text=True,
                stdout=stdout_handle,
                stderr=stderr_handle,
                check=False,
                timeout=timeout_seconds,
                env=trace_env,
            )
        returncode = proc.returncode
        stdout = _read_trace_process_text(stdout_path)
        stderr = _read_trace_process_text(stderr_path)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout = _timeout_text(exc.stdout) or _read_trace_process_text(stdout_path)
        stderr = _timeout_text(exc.stderr) or _read_trace_process_text(stderr_path)
    _finalize_trace_parts(out_path)

    return _prove_trace_log(
        db_path,
        out_path,
        test_id,
        expected=expected,
        suite=suite,
        command=command,
        pretraced=pretraced,
        returncode=returncode,
        timed_out=timed_out,
        timeout_seconds=timeout_seconds,
        allow_timeout=allow_timeout,
        expected_returncode=expected_returncode,
        stdout=stdout,
        stderr=stderr,
        block_state_trace=block_state_trace,
    )


def prove_halo_trace(
    db_path: Path,
    out_path: Path,
    test_id: str,
    app: list[str],
    *,
    expected_filename: str | None = None,
    expected_sha256: str | None = None,
    arch: str = "auto",
    trace_runner: str | None = None,
    timeout_seconds: int | None = None,
    suite: str = "halo-trace",
    allow_timeout: bool = True,
    pretraced: bool = False,
    expected_returncode: int | None = 0,
    semantic_profile: bool = False,
    semantic_max_records: int = 128,
    block_state_trace: bool = False,
    block_state_max_records: int = 8192,
) -> dict[str, Any]:
    legacy_trace_runner = trace_runner or os.environ.get("HALOCE_TRACE_RUNNER") or shutil.which("halo-trace-run") or "halo-trace-run"
    return prove_trace(
        db_path,
        out_path,
        test_id,
        app,
        expected_filename=expected_filename,
        expected_sha256=expected_sha256,
        arch=arch,
        trace_runner=legacy_trace_runner,
        timeout_seconds=timeout_seconds,
        suite=suite,
        allow_timeout=allow_timeout,
        pretraced=pretraced,
        expected_returncode=expected_returncode,
        semantic_profile=semantic_profile,
        semantic_max_records=semantic_max_records,
        block_state_trace=block_state_trace,
        block_state_max_records=block_state_max_records,
    )


def prove_trace_log(
    db_path: Path,
    log_path: Path,
    test_id: str,
    *,
    expected_filename: str | None = None,
    expected_sha256: str | None = None,
    suite: str = "halo-trace",
    command: list[str] | None = None,
    returncode: int | None = 0,
    timed_out: bool = False,
    timeout_seconds: int | None = None,
    allow_timeout: bool = True,
    expected_returncode: int | None = 0,
    stdout: str = "",
    stderr: str = "",
    block_state_trace: bool = False,
) -> dict[str, Any]:
    expected = _expected_binary(db_path, expected_filename=expected_filename, expected_sha256=expected_sha256)
    if expected is None:
        raise ValueError("expected module not found; pass --expected-filename or --expected-sha256 for a cataloged binary")
    _finalize_trace_parts(log_path)
    return _prove_trace_log(
        db_path,
        log_path,
        test_id,
        expected=expected,
        suite=suite,
        command=command or [],
        pretraced=True,
        returncode=returncode,
        timed_out=timed_out,
        timeout_seconds=timeout_seconds,
        allow_timeout=allow_timeout,
        expected_returncode=expected_returncode,
        stdout=stdout,
        stderr=stderr,
        block_state_trace=block_state_trace,
    )


def prove_halo_trace_log(
    db_path: Path,
    log_path: Path,
    test_id: str,
    *,
    expected_filename: str | None = None,
    expected_sha256: str | None = None,
    suite: str = "halo-trace",
    command: list[str] | None = None,
    returncode: int | None = 0,
    timed_out: bool = False,
    timeout_seconds: int | None = None,
    allow_timeout: bool = True,
    expected_returncode: int | None = 0,
    stdout: str = "",
    stderr: str = "",
    block_state_trace: bool = False,
) -> dict[str, Any]:
    return prove_trace_log(
        db_path,
        log_path,
        test_id,
        expected_filename=expected_filename,
        expected_sha256=expected_sha256,
        suite=suite,
        command=command,
        returncode=returncode,
        timed_out=timed_out,
        timeout_seconds=timeout_seconds,
        allow_timeout=allow_timeout,
        expected_returncode=expected_returncode,
        stdout=stdout,
        stderr=stderr,
        block_state_trace=block_state_trace,
    )


def _prove_trace_log(
    db_path: Path,
    log_path: Path,
    test_id: str,
    *,
    expected: dict[str, Any],
    suite: str,
    command: list[str],
    pretraced: bool,
    returncode: int | None,
    timed_out: bool,
    timeout_seconds: int | None,
    allow_timeout: bool,
    expected_returncode: int | None,
    stdout: str,
    stderr: str,
    block_state_trace: bool,
) -> dict[str, Any]:
    failures: list[str] = []
    if timed_out and not allow_timeout:
        failures.append(f"trace command timed out after {timeout_seconds} seconds")
    if returncode is not None and expected_returncode is not None and returncode != expected_returncode:
        failures.append(f"trace command exited with {returncode}; expected {expected_returncode}")
    if not log_path.exists():
        failures.append(f"trace log was not created: {log_path}")
        summary = _empty_trace_summary(expected["sha256"])
        ingest_result = {"modules": 0, "blocks": 0, "cfg_edges": 0, "call_edges": 0}
        mapped = {"blocks": 0, "cfg_edges": 0, "call_edges": 0}
    else:
        summary = _summarize_trace(log_path, expected["sha256"])
        if summary["malformed_lines"]:
            failures.append(f"trace log contains malformed JSON lines: {summary['malformed_lines'][:5]}")
            ingest_result = {"modules": 0, "blocks": 0, "cfg_edges": 0, "call_edges": 0}
            mapped = {"blocks": 0, "cfg_edges": 0, "call_edges": 0}
        else:
            try:
                if not all(
                    summary[key] > 0
                    for key in (
                        "expected_modules",
                        "expected_blocks",
                        "expected_cfg_edges",
                        "expected_call_edges",
                    )
                ):
                    ingest_result = {"modules": 0, "blocks": 0, "cfg_edges": 0, "call_edges": 0}
                    mapped = {"blocks": 0, "cfg_edges": 0, "call_edges": 0}
                else:
                    ingest_result = ingest_trace(db_path, log_path, suite=suite)
                    mapped = _mapped_trace_counts(db_path, test_id, suite, int(expected["id"]))
            except Exception as exc:
                failures.append(f"trace ingest failed: {exc}")
                ingest_result = {"modules": 0, "blocks": 0, "cfg_edges": 0, "call_edges": 0}
                mapped = {"blocks": 0, "cfg_edges": 0, "call_edges": 0}

    required_raw = {
        "expected_modules": "expected module record",
        "expected_blocks": "expected module block events",
        "expected_cfg_edges": "expected module CFG-edge events",
        "expected_call_edges": "expected module call-edge events",
    }
    for key, description in required_raw.items():
        if int(summary.get(key, 0)) <= 0:
            failures.append(f"missing {description} in trace log for {expected['filename']}")

    expected_block_state_records = int(summary.get("expected_block_state_records", 0))
    expected_block_state_exits = int(summary.get("expected_block_state_exits", 0))
    if (block_state_trace or expected_block_state_records > 0) and expected_block_state_exits <= 0:
        failures.append(f"missing expected module block-state exit records in trace log for {expected['filename']}")
    if expected_block_state_exits > 0:
        incomplete_exits = int(summary.get("expected_side_effect_incomplete_exits", 0))
        if incomplete_exits > 0:
            failures.append(
                f"incomplete side-effect capture on {incomplete_exits} expected module block exits for {expected['filename']}"
            )
        limitations = summary.get("expected_side_effect_limitations") or {}
        if limitations:
            limitation_text = ", ".join(f"{key}={limitations[key]}" for key in sorted(limitations))
            failures.append(f"side-effect capture limitations for {expected['filename']}: {limitation_text}")
        unknown_calls = int(summary.get("expected_api_unknown_semantic_calls", 0))
        if unknown_calls > 0:
            failures.append(f"unknown API side-effect semantics on {unknown_calls} expected module calls for {expected['filename']}")
        unresolved_calls = int(summary.get("expected_api_unresolved_external_calls", 0))
        if unresolved_calls > 0:
            failures.append(f"unresolved external API side-effect calls on {unresolved_calls} expected module calls for {expected['filename']}")

    for key, description in {
        "blocks": "mapped dynamic blocks",
        "cfg_edges": "mapped dynamic CFG edges",
        "call_edges": "mapped dynamic call edges",
    }.items():
        if int(mapped.get(key, 0)) <= 0:
            failures.append(f"missing {description} in catalog for {expected['filename']}")

    return {
        "ok": not failures,
        "test_id": test_id,
        "suite": suite,
        "command": command,
        "pretraced": pretraced,
        "returncode": returncode,
        "expected_returncode": expected_returncode,
        "timed_out": timed_out,
        "stdout": _bounded_text(stdout),
        "stderr": _bounded_text(stderr),
        "trace_log": str(log_path),
        "expected": {
            "filename": expected["filename"],
            "sha256": expected["sha256"],
            "binary_id": expected["id"],
        },
        "raw_trace": summary,
        "ingested": ingest_result,
        "mapped": mapped,
        "failures": failures,
    }


def run_drcov(log_dir: Path, app: list[str], *, timeout_seconds: int | None = None) -> subprocess.CompletedProcess[str]:
    log_dir.mkdir(parents=True, exist_ok=True)
    command = ["drrun", "-t", "drcov", "-dump_text", "-logdir", str(log_dir), "--", *app]
    if timeout_seconds is not None:
        command[1:1] = ["-s", str(timeout_seconds)]
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def doctor_drcov() -> dict[str, Any]:
    try:
        smoke_executable = _resolve_true_executable()
    except FileNotFoundError as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "smoke_executable": None,
            "note": "Many Windows targets are 32-bit; a passing native 64-bit smoke test is necessary but not sufficient.",
        }

    proc = subprocess.run(
        ["drrun", "-64", "-quiet", "-t", "drcov", "-dump_text", "--", str(smoke_executable)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "smoke_executable": str(smoke_executable),
        "note": "Many Windows targets are 32-bit; a passing native 64-bit smoke test is necessary but not sufficient.",
    }


def _resolve_true_executable() -> Path:
    candidates = [os.environ.get("HALOCE_DRCOV_TRUE"), shutil.which("true")]
    for candidate in candidates:
        if candidate is not None and Path(candidate).is_file():
            return Path(candidate)
    raise FileNotFoundError("no true executable found; set HALOCE_DRCOV_TRUE or put true on PATH")


def _resolve_trace_runner(value: str | None) -> str:
    if value:
        return value
    env_value = os.environ.get("WINCR_TRACE_RUNNER")
    if env_value:
        return env_value
    env_value = os.environ.get("HALOCE_TRACE_RUNNER")
    if env_value:
        return env_value
    return shutil.which("wincr-trace-run") or shutil.which("halo-trace-run") or "wincr-trace-run"


def _finalize_trace_parts(out_path: Path) -> None:
    parts = sorted(path for path in out_path.parent.glob(out_path.name + ".*") if path.is_file())
    if not parts:
        return
    with out_path.open("wb") as out_handle:
        for part in parts:
            out_handle.write(part.read_bytes())


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _read_trace_process_text(path: Path) -> str:
    if not path.exists():
        return ""
    return _bounded_text(path.read_text(encoding="utf-8", errors="replace"))


def _bounded_text(value: str, limit: int = 12000) -> str:
    if len(value) <= limit:
        return value
    half = limit // 2
    return value[:half] + "\n... truncated ...\n" + value[-half:]


def resolve_observed_path(path: str, *, install_root: Path | None = None) -> Path | None:
    normalized = path.replace("\\", "/")
    direct = Path(normalized)
    if direct.exists():
        return direct
    if normalized.lower().startswith("z:/"):
        z_path = Path("/" + normalized[3:].lstrip("/"))
        if z_path.exists():
            return z_path
    if install_root is not None and normalized.lower().startswith("c:/"):
        c_path = install_root / "drive_c" / normalized[3:].lstrip("/")
        if c_path.exists():
            return c_path
    return None


def _parse_modules(text: str) -> list[DrcovModule]:
    lines = text.splitlines()
    modules: list[DrcovModule] = []
    for index, line in enumerate(lines):
        if not line.startswith("Module Table:"):
            continue
        count_match = re.search(r"count\s+(\d+)", line)
        expected_count = int(count_match.group(1)) if count_match else None
        columns_line = lines[index + 1] if index + 1 < len(lines) else ""
        if not columns_line.startswith("Columns:"):
            return modules
        columns = [column.strip() for column in columns_line.split(":", 1)[1].split(",")]
        row_index = index + 2
        while row_index < len(lines):
            row = lines[row_index]
            if row.startswith("BB Table:") or not row:
                break
            parts = [part.strip() for part in row.split(",", len(columns) - 1)]
            if len(parts) == len(columns):
                data = dict(zip(columns, parts, strict=True))
                modules.append(_module_from_columns(data))
                if expected_count is not None and len(modules) >= expected_count:
                    break
            row_index += 1
        break
    return modules


def _module_from_columns(data: dict[str, str]) -> DrcovModule:
    def get_int(*names: str) -> int | None:
        for name in names:
            value = data.get(name)
            if value:
                return _parse_int(value)
        return None

    module_id = get_int("id", "module id")
    if module_id is None:
        raise ValueError(f"drcov module row lacks id: {data}")
    return DrcovModule(
        module_id=module_id,
        path=data.get("path", ""),
        start=get_int("start", "base"),
        end=get_int("end"),
        entry=get_int("entry"),
        preferred_base=get_int("preferred_base", "preferred base"),
    )


def _parse_text_blocks(text: str) -> list[DrcovBlock] | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("BB Table:"):
            continue
        rows = lines[index + 1 :]
        if rows and rows[0].lower().startswith("module id"):
            rows = rows[1:]
        result: list[DrcovBlock] = []
        saw_text_row = False
        for row in rows:
            if not row.strip():
                continue
            parsed = _parse_text_block_row(row)
            if parsed is None:
                if saw_text_row:
                    break
                continue
            saw_text_row = True
            result.append(parsed)
        return result if saw_text_row else None
    return None


def _parse_text_block_row(row: str) -> DrcovBlock | None:
    row = row.strip()
    module_style = re.match(r"module\[\s*(\d+)\]\s*:\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(\d+)", row)
    if module_style:
        return DrcovBlock(
            module_id=int(module_style.group(1)),
            start=_parse_int(module_style.group(2)),
            size=int(module_style.group(3)),
        )
    csv_style = re.match(r"(\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(\d+)", row)
    if csv_style:
        return DrcovBlock(
            module_id=int(csv_style.group(1)),
            start=_parse_int(csv_style.group(2)),
            size=int(csv_style.group(3)),
        )
    return None


def _parse_binary_blocks(data: bytes) -> list[DrcovBlock]:
    marker = b"BB Table:"
    marker_index = data.find(marker)
    if marker_index < 0:
        return []
    line_end = data.find(b"\n", marker_index)
    if line_end < 0:
        return []
    header = data[marker_index:line_end].decode("utf-8", errors="replace")
    count_match = re.search(r"(\d+)\s+bbs", header)
    if not count_match:
        return []
    count = int(count_match.group(1))
    payload = data[line_end + 1 :]
    blocks: list[DrcovBlock] = []
    record_size = struct.calcsize("<IHH")
    for index in range(count):
        start = index * record_size
        end = start + record_size
        if end > len(payload):
            break
        block_start, size, module_id = struct.unpack("<IHH", payload[start:end])
        blocks.append(DrcovBlock(module_id=module_id, start=block_start, size=size))
    return blocks


def _find_binary(conn: sqlite3.Connection, module_sha: str | None, module_path: str) -> int | None:
    if module_sha:
        row = conn.execute("SELECT id FROM binaries WHERE sha256 = ? ORDER BY scope LIMIT 1", (module_sha,)).fetchone()
        if row:
            return int(row["id"])
    filename = Path(module_path.replace("\\", "/")).name.lower()
    if not filename:
        return None
    row = conn.execute(
        "SELECT id FROM binaries WHERE lower(filename) = ? ORDER BY CASE scope WHEN 'included' THEN 0 ELSE 1 END LIMIT 1",
        (filename,),
    ).fetchone()
    return int(row["id"]) if row else None


def _binary_label(conn: sqlite3.Connection, binary_id: int | None) -> str | None:
    if binary_id is None:
        return None
    row = conn.execute("SELECT label FROM binaries WHERE id = ?", (binary_id,)).fetchone()
    return str(row["label"]) if row else None


def _ensure_trace_test_run(
    conn: sqlite3.Connection,
    started_by_test: dict[str, tuple[int, str]],
    test_id: str,
    suite: str,
    *,
    started_at: str,
) -> tuple[int, str]:
    if test_id in started_by_test:
        return started_by_test[test_id]
    label = test_run_label(test_id, suite, started_at)
    ensure_label(conn, label, "test", test_id, f"{suite} dynamic trace", created_at=started_at)
    cursor = conn.execute(
        """
        INSERT INTO test_runs(
          label, test_id, suite, command, status, started_at, finished_at,
          tool_versions_json, provenance_json
        )
        VALUES (?, ?, ?, ?, 'imported', ?, ?, ?, ?)
        """,
        (
            label,
            test_id,
            suite,
            "ingest-halo-trace" if suite == "halo-trace" else "ingest-trace",
            started_at,
            utc_now(),
            json_dumps(tool_versions()),
            json_dumps(runtime_provenance()),
        ),
    )
    value = (int(cursor.lastrowid), label)
    started_by_test[test_id] = value
    return value


def _trace_module(
    conn: sqlite3.Connection,
    module_by_key: dict[tuple[str, int, str], tuple[int, int | None, str | None, str | None]],
    test_run_id: int,
    test_id: str,
    pid: int,
    record: dict[str, Any],
    next_module_id: int,
) -> tuple[tuple[int, int | None, str | None, str | None], int]:
    module_sha = str(record["module_sha256"])
    key = (test_id, pid, module_sha)
    if key in module_by_key:
        return module_by_key[key], next_module_id
    binary_id = _find_binary(conn, module_sha, str(record.get("module_name", "")))
    binary_label = _binary_label(conn, binary_id)
    cursor = conn.execute(
        """
        INSERT INTO observed_modules(
          test_run_id, drcov_module_id, path, base, end, entry, preferred_base, sha256, binary_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            test_run_id,
            next_module_id,
            str(record.get("module_path") or record.get("module_name") or module_sha),
            record.get("base"),
            record.get("end"),
            record.get("entry"),
            record.get("preferred_base"),
            module_sha,
            binary_id,
        ),
    )
    value = (int(cursor.lastrowid), binary_id, binary_label, module_sha)
    module_by_key[key] = value
    return value, next_module_id + 1


def _expected_binary(
    db_path: Path,
    *,
    expected_filename: str | None,
    expected_sha256: str | None,
) -> dict[str, Any] | None:
    conn = connect(db_path)
    initialize(conn)
    if expected_sha256:
        row = conn.execute(
            """
            SELECT id, filename, sha256
            FROM binaries
            WHERE sha256 = ?
            ORDER BY CASE scope WHEN 'included' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END, path
            LIMIT 1
            """,
            (expected_sha256,),
        ).fetchone()
    elif expected_filename:
        row = conn.execute(
            """
            SELECT id, filename, sha256
            FROM binaries
            WHERE lower(filename) = lower(?)
            ORDER BY CASE scope WHEN 'included' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END, path
            LIMIT 1
            """,
            (expected_filename,),
        ).fetchone()
    else:
        row = None
    conn.close()
    return dict(row) if row is not None else None


def _empty_trace_summary(expected_sha256: str) -> dict[str, Any]:
    return {
        "expected_sha256": expected_sha256,
        "modules": 0,
        "blocks": 0,
        "cfg_edges": 0,
        "call_edges": 0,
        "block_state_records": 0,
        "block_state_entries": 0,
        "block_state_exits": 0,
        "expected_modules": 0,
        "expected_blocks": 0,
        "expected_cfg_edges": 0,
        "expected_call_edges": 0,
        "expected_block_state_records": 0,
        "expected_block_state_entries": 0,
        "expected_block_state_exits": 0,
        "side_effect_complete_exits": 0,
        "side_effect_incomplete_exits": 0,
        "side_effect_limitations": {},
        "api_unknown_semantic_calls": 0,
        "api_unresolved_external_calls": 0,
        "expected_side_effect_complete_exits": 0,
        "expected_side_effect_incomplete_exits": 0,
        "expected_side_effect_limitations": {},
        "expected_api_unknown_semantic_calls": 0,
        "expected_api_unresolved_external_calls": 0,
        "malformed_line_count": 0,
        "malformed_lines": [],
        "module_samples": [],
    }


def _increment_counter_map(mapping: dict[str, Any], key: str) -> None:
    mapping[key] = int(mapping.get(key, 0)) + 1


def _summarize_side_effects(summary: dict[str, Any], record: dict[str, Any], *, expected: bool) -> None:
    side_effects = record.get("side_effects") or {}
    status = str(side_effects.get("capture_status") or "")
    limitations = [str(value) for value in side_effects.get("limitations") or []]
    api_calls = side_effects.get("api_calls") or []
    incomplete = status != "complete" or bool(limitations)

    if incomplete:
        summary["side_effect_incomplete_exits"] += 1
        if expected:
            summary["expected_side_effect_incomplete_exits"] += 1
    else:
        summary["side_effect_complete_exits"] += 1
        if expected:
            summary["expected_side_effect_complete_exits"] += 1

    for limitation in limitations:
        _increment_counter_map(summary["side_effect_limitations"], limitation)
        if expected:
            _increment_counter_map(summary["expected_side_effect_limitations"], limitation)

    for call in api_calls:
        semantic_class = str(call.get("semantic_class") or "")
        if semantic_class == "unknown":
            summary["api_unknown_semantic_calls"] += 1
            if expected:
                summary["expected_api_unknown_semantic_calls"] += 1
        if (
            call.get("external")
            and not call.get("symbol_resolved")
            and semantic_class != "application_callback"
        ):
            summary["api_unresolved_external_calls"] += 1
            if expected:
                summary["expected_api_unresolved_external_calls"] += 1


def _summarize_trace(log_path: Path, expected_sha256: str) -> dict[str, Any]:
    summary = _empty_trace_summary(expected_sha256)
    with log_path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                summary["malformed_line_count"] += 1
                if len(summary["malformed_lines"]) < 20:
                    summary["malformed_lines"].append(line_number)
                continue
            kind = str(record.get("kind", ""))
            if kind not in {"module", "block", "cfg_edge", "call_edge", "block_entry", "block_exit"}:
                continue
            if kind in {"block_entry", "block_exit"}:
                summary["block_state_records"] += 1
                summary["block_state_entries" if kind == "block_entry" else "block_state_exits"] += 1
            else:
                count_key = "cfg_edges" if kind == "cfg_edge" else "call_edges" if kind == "call_edge" else f"{kind}s"
                summary[count_key] += 1
            if kind == "module" and len(summary["module_samples"]) < 20:
                summary["module_samples"].append(
                    {
                        "pid": record.get("pid"),
                        "module_name": record.get("module_name"),
                        "module_path": record.get("module_path"),
                        "module_sha256": record.get("module_sha256"),
                        "expected": record.get("module_sha256") == expected_sha256,
                    }
                )
            if record.get("module_sha256") == expected_sha256:
                if kind in {"block_entry", "block_exit"}:
                    summary["expected_block_state_records"] += 1
                    summary[
                        "expected_block_state_entries"
                        if kind == "block_entry"
                        else "expected_block_state_exits"
                    ] += 1
                else:
                    expected_key = (
                        "expected_cfg_edges"
                        if kind == "cfg_edge"
                        else "expected_call_edges"
                        if kind == "call_edge"
                        else f"expected_{kind}s"
                    )
                    summary[expected_key] += 1
            if kind == "block_exit":
                _summarize_side_effects(summary, record, expected=record.get("module_sha256") == expected_sha256)
    return summary


def _summarize_halo_trace(log_path: Path, expected_sha256: str) -> dict[str, Any]:
    return _summarize_trace(log_path, expected_sha256)


def _mapped_trace_counts(db_path: Path, test_id: str, suite: str, binary_id: int) -> dict[str, int]:
    conn = connect(db_path)
    initialize(conn)
    counts = {
        "blocks": _mapped_count(
            conn,
            """
            SELECT COUNT(*)
            FROM coverage_blocks cb
            JOIN test_runs tr ON tr.id = cb.test_run_id
            WHERE tr.test_id = ? AND tr.suite = ? AND cb.binary_id = ?
            """,
            test_id,
            suite,
            binary_id,
        ),
        "cfg_edges": _mapped_count(
            conn,
            """
            SELECT COUNT(*)
            FROM coverage_edges ce
            JOIN test_runs tr ON tr.id = ce.test_run_id
            WHERE tr.test_id = ? AND tr.suite = ? AND ce.binary_id = ?
            """,
            test_id,
            suite,
            binary_id,
        ),
        "call_edges": _mapped_count(
            conn,
            """
            SELECT COUNT(*)
            FROM coverage_call_edges cce
            JOIN test_runs tr ON tr.id = cce.test_run_id
            WHERE tr.test_id = ? AND tr.suite = ? AND cce.binary_id = ?
            """,
            test_id,
            suite,
            binary_id,
        ),
    }
    conn.close()
    return counts


def _mapped_count(conn: sqlite3.Connection, query: str, test_id: str, suite: str, binary_id: int) -> int:
    row = conn.execute(query, (test_id, suite, binary_id)).fetchone()
    return int(row[0]) if row is not None else 0


def _parse_int(value: str) -> int:
    value = value.strip()
    return int(value, 16) if value.lower().startswith("0x") else int(value)
