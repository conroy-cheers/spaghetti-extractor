from __future__ import annotations

import os
import re
import shutil
import sqlite3
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .catalog import tool_versions
from .db import connect, initialize
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
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO test_runs(test_id, suite, command, status, started_at, finished_at, tool_versions_json)
            VALUES (?, ?, ?, 'imported', ?, ?, ?)
            """,
            (test_id, suite, f"ingest-drcov {log_path}", started, utc_now(), json_dumps(tool_versions())),
        )
        test_run_id = int(cursor.lastrowid)
        module_db_ids: dict[int, tuple[int, int | None]] = {}
        for module in parsed.modules:
            resolved_path = resolve_observed_path(module.path, install_root=install_root)
            module_sha = sha256_file(resolved_path) if resolved_path and resolved_path.exists() else None
            binary_id = _find_binary(conn, module_sha, module.path)
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
            module_db_ids[module.module_id] = (int(cursor.lastrowid), binary_id)

        rows = []
        for block in parsed.blocks:
            module_ids = module_db_ids.get(block.module_id)
            if module_ids is None:
                continue
            observed_module_id, binary_id = module_ids
            rows.append(
                (
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
              test_run_id, observed_module_id, binary_id, rva_start, rva_end, size, source_log
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    return {
        "test_id": test_id,
        "modules": len(parsed.modules),
        "blocks": len(parsed.blocks),
        "mapped_blocks": len(rows),
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
            "note": "Halo CE is 32-bit; a passing native 64-bit smoke test is necessary but not sufficient.",
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
        "note": "Halo CE is 32-bit; a passing native 64-bit smoke test is necessary but not sufficient.",
    }


def _resolve_true_executable() -> Path:
    candidates = [os.environ.get("HALOCE_DRCOV_TRUE"), shutil.which("true")]
    for candidate in candidates:
        if candidate is not None and Path(candidate).is_file():
            return Path(candidate)
    raise FileNotFoundError("no true executable found; set HALOCE_DRCOV_TRUE or put true on PATH")


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


def _parse_int(value: str) -> int:
    value = value.strip()
    return int(value, 16) if value.lower().startswith("0x") else int(value)
