from __future__ import annotations

import platform
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from . import __version__
from .db import reset_database
from .pe import discover_linear_blocks, executable_range_classification, find_pe_files, parse_pe
from .roles import classify_pe
from .util import json_dumps, utc_now


def resolve_install_root(install_root: str | None) -> Path:
    candidates: list[Path] = []
    if install_root:
        candidates.append(Path(install_root))
    env_root = _env_install_root()
    if env_root is not None:
        candidates.append(env_root)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    searched = ", ".join(str(path) for path in candidates)
    if searched:
        raise FileNotFoundError(f"no Halo CE install root found; searched: {searched}")
    raise FileNotFoundError("no Halo CE install root provided; pass --install-root or set HALOCE_INSTALL_ROOT")


def build_catalog(
    install_root: Path,
    db_path: Path,
    *,
    static_depth: str = "none",
    max_disassembly_bytes: int = 6 * 1024 * 1024,
    catalog_version: str = __version__,
) -> dict[str, Any]:
    install_root = install_root.resolve()
    conn = reset_database(db_path)
    started = utc_now()
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("catalog_version", catalog_version))
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("install_root", str(install_root)))
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("created_at", started))
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("tool_versions", json_dumps(tool_versions())))

    pe_paths = find_pe_files(install_root)
    inserted = 0
    block_count = 0
    edge_count = 0
    errors: list[str] = []
    static_skips: list[str] = []

    with conn:
        for path in pe_paths:
            relative = path.relative_to(install_root).as_posix()
            role = classify_pe(relative)
            try:
                info = parse_pe(path, install_root, role)
            except Exception as exc:  # pragma: no cover - exercised by malformed local inputs
                errors.append(f"{relative}: {exc}")
                continue
            binary_id = _insert_binary(conn, info, install_root, catalog_version, started)
            inserted += 1
            _insert_sections(conn, binary_id, info)
            _insert_imports(conn, binary_id, info)
            _insert_exports(conn, binary_id, info)
            _insert_resources(conn, binary_id, info)
            _insert_executable_ranges(conn, binary_id, info)
            _insert_function_seeds(conn, binary_id, info)

            if _should_discover_blocks(static_depth, info.role.scope):
                executable_bytes = _executable_raw_bytes(info)
                if max_disassembly_bytes > 0 and executable_bytes > max_disassembly_bytes:
                    static_skips.append(
                        f"{relative}: skipped capstone-linear discovery for {executable_bytes} executable bytes "
                        f"(limit {max_disassembly_bytes})"
                    )
                    continue
                try:
                    blocks, edges = discover_linear_blocks(path)
                except Exception as exc:  # pragma: no cover - depends on local binary oddities
                    errors.append(f"{relative}: capstone discovery failed: {exc}")
                else:
                    block_count += _insert_blocks(conn, binary_id, blocks)
                    edge_count += _insert_edges(conn, binary_id, edges)

        if errors:
            conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("catalog_errors", json_dumps(errors)))
        if static_skips:
            conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                ("static_disassembly_skips", json_dumps(static_skips)),
            )

    return {
        "database": str(db_path),
        "install_root": str(install_root),
        "pe_files_seen": len(pe_paths),
        "binaries_inserted": inserted,
        "basic_blocks_inserted": block_count,
        "cfg_edges_inserted": edge_count,
        "errors": errors,
        "static_skips": static_skips,
    }


def tool_versions() -> dict[str, str]:
    versions = {
        "haloce_catalog": __version__,
        "python": platform.python_version(),
    }
    for name, command in {
        "llvm-objdump": ["llvm-objdump", "--version"],
        "rizin": ["rizin", "-v"],
        "radare2": ["r2", "-v"],
        "drrun": ["drrun", "-version"],
    }.items():
        versions[name] = _first_line(command)
    return versions


def _first_line(command: list[str]) -> str:
    try:
        proc = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        return "not found"
    first = proc.stdout.splitlines()[0] if proc.stdout else ""
    return first.strip()


def _env_install_root() -> Path | None:
    import os

    value = os.environ.get("HALOCE_INSTALL_ROOT")
    return Path(value) if value else None


def _insert_binary(conn: sqlite3.Connection, info: Any, install_root: Path, catalog_version: str, discovered_at: str) -> int:
    cursor = conn.execute(
        """
        INSERT INTO binaries(
          path, filename, sha256, size, kind, machine, timestamp, image_base, entrypoint_rva,
          size_of_image, subsystem, linker_version, pe_checksum, role, scope, role_reason,
          source_root, catalog_version, discovered_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            info.relative_path,
            Path(info.relative_path).name,
            info.sha256,
            info.size,
            info.kind,
            info.machine,
            info.timestamp,
            info.image_base,
            info.entrypoint_rva,
            info.size_of_image,
            info.subsystem,
            info.linker_version,
            info.checksum,
            info.role.role,
            info.role.scope,
            info.role.reason,
            str(install_root),
            catalog_version,
            discovered_at,
        ),
    )
    return int(cursor.lastrowid)


def _insert_sections(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    conn.executemany(
        """
        INSERT INTO sections(
          binary_id, name, virtual_address, virtual_size, raw_pointer, raw_size,
          characteristics, flags, sha256, entropy
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                binary_id,
                section.name,
                section.virtual_address,
                section.virtual_size,
                section.raw_pointer,
                section.raw_size,
                section.characteristics,
                section.flags,
                section.sha256,
                section.entropy,
            )
            for section in info.sections
        ],
    )


def _insert_imports(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    conn.executemany(
        "INSERT INTO imports(binary_id, dll, symbol, ordinal, hint, thunk_rva) VALUES (?, ?, ?, ?, ?, ?)",
        [(binary_id, item.dll, item.symbol, item.ordinal, item.hint, item.thunk_rva) for item in info.imports],
    )


def _insert_exports(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    conn.executemany(
        "INSERT INTO exports(binary_id, symbol, ordinal, rva, forwarder) VALUES (?, ?, ?, ?, ?)",
        [(binary_id, item.symbol, item.ordinal, item.rva, item.forwarder) for item in info.exports],
    )


def _insert_resources(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    conn.executemany(
        """
        INSERT INTO resources(binary_id, type_name, name, language, rva, size, sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (binary_id, item.type_name, item.name, item.language, item.rva, item.size, item.sha256)
            for item in info.resources
        ],
    )


def _insert_executable_ranges(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    classification, evidence = executable_range_classification(info.role)
    rows = []
    for section in info.sections:
        if not section.executable:
            continue
        rva_start = section.virtual_address
        rva_end = section.virtual_address + max(section.virtual_size, section.raw_size)
        rows.append(
            (
                binary_id,
                rva_start,
                rva_end,
                section.raw_pointer,
                section.raw_pointer + section.raw_size,
                classification,
                evidence,
            )
        )
    conn.executemany(
        """
        INSERT OR IGNORE INTO executable_ranges(
          binary_id, rva_start, rva_end, file_offset_start, file_offset_end, classification, evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def _insert_function_seeds(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    conn.executemany(
        """
        INSERT OR IGNORE INTO functions(
          binary_id, rva, name, source, confidence, test_status, clean_room_status
        )
        VALUES (?, ?, ?, ?, ?, 'untested', 'needs-spec')
        """,
        [(binary_id, seed.rva, seed.name, seed.source, seed.confidence) for seed in info.function_seeds],
    )


def _insert_blocks(conn: sqlite3.Connection, binary_id: int, blocks: list[Any]) -> int:
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO basic_blocks(
          binary_id, rva_start, rva_end, size, source, classification, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                binary_id,
                block.rva_start,
                block.rva_end,
                block.rva_end - block.rva_start,
                block.source,
                block.classification,
                block.confidence,
            )
            for block in blocks
        ],
    )
    return conn.total_changes - before


def _insert_edges(conn: sqlite3.Connection, binary_id: int, edges: list[Any]) -> int:
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO cfg_edges(binary_id, from_rva, to_rva, edge_type, source, confidence)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [(binary_id, edge.from_rva, edge.to_rva, edge.edge_type, edge.source, edge.confidence) for edge in edges],
    )
    return conn.total_changes - before


def _should_discover_blocks(static_depth: str, scope: str) -> bool:
    if static_depth == "none":
        return False
    if static_depth == "all":
        return True
    if static_depth == "candidate":
        return scope in {"included", "candidate"}
    if static_depth == "included":
        return scope == "included"
    raise ValueError(f"unknown static depth: {static_depth}")


def _executable_raw_bytes(info: Any) -> int:
    return sum(section.raw_size for section in info.sections if section.executable)
