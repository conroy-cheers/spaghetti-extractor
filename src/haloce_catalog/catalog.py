from __future__ import annotations

import json
import os
import platform
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from . import __version__
from .byteclasses import rebuild_executable_byte_classes
from .db import reset_database
from .interfaces import endpoint_mock_status, endpoint_subsystem
from .labels import (
    basic_block_label,
    cfg_edge_label,
    ensure_label,
    ensure_oracle_mapping,
    executable_range_label,
    function_label,
    module_label,
    platform_endpoint_label,
)
from .pe import discover_linear_blocks, executable_range_classification, find_pe_files, mapped_section_size, parse_pe
from .roles import classify_pe
from .target import TargetConfig, load_target_config
from .util import json_dumps, utc_now


def resolve_install_root(install_root: str | None, target_config: TargetConfig | None = None) -> Path:
    target = target_config or load_target_config()
    candidates: list[Path] = []
    if install_root:
        candidates.append(Path(install_root))
    env_root = _env_install_root(target)
    if env_root is not None:
        candidates.append(env_root)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    searched = ", ".join(str(path) for path in candidates)
    if searched:
        raise FileNotFoundError(f"no {target.project_name} install root found; searched: {searched}")
    raise FileNotFoundError(
        f"no {target.project_name} install root provided; pass --install-root or set {target.install_root_env}"
    )


def build_catalog(
    install_root: Path,
    db_path: Path,
    *,
    static_depth: str = "none",
    max_disassembly_bytes: int = 6 * 1024 * 1024,
    catalog_version: str = __version__,
    target_config: TargetConfig | None = None,
) -> dict[str, Any]:
    target = target_config or load_target_config()
    install_root = install_root.resolve()
    conn = reset_database(db_path)
    started = utc_now()
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("catalog_version", catalog_version))
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("install_root", str(install_root)))
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("created_at", started))
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("tool_versions", json_dumps(tool_versions())))
    for key, value in target.metadata_rows().items():
        conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", (key, value))
    reference_package = _env_value(target.reference_package_env) or _env_value("WINCR_REFERENCE_PACKAGE") or _infer_reference_package(install_root)
    if reference_package:
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("reference_package", reference_package),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            (target.reference_package_metadata_key, reference_package),
        )
    source_info = target_source_info(target)
    if source_info:
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            ("source_info", source_info),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
            (target.source_info_metadata_key, source_info),
        )
    nix_shell = _env_value("IN_NIX_SHELL")
    if nix_shell:
        conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("nix_shell", nix_shell))

    pe_paths = find_pe_files(install_root)
    inserted = 0
    block_count = 0
    edge_count = 0
    errors: list[str] = []
    static_skips: list[str] = []

    with conn:
        for path in pe_paths:
            relative = path.relative_to(install_root).as_posix()
            role = classify_pe(relative, target_config=target)
            try:
                info = parse_pe(path, install_root, role)
            except Exception as exc:  # pragma: no cover - exercised by malformed local inputs
                errors.append(f"{relative}: {exc}")
                continue
            binary_id = _insert_binary(conn, info, install_root, catalog_version, started)
            inserted += 1
            _insert_sections(conn, binary_id, info)
            _insert_imports(conn, binary_id, info)
            _insert_platform_endpoints(conn, binary_id, info)
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
                else:
                    try:
                        blocks, edges = discover_linear_blocks(path)
                    except Exception as exc:  # pragma: no cover - depends on local binary oddities
                        errors.append(f"{relative}: capstone discovery failed: {exc}")
                    else:
                        block_count += _insert_blocks(conn, binary_id, blocks)
                        edge_count += _insert_edges(conn, binary_id, edges)
            rebuild_executable_byte_classes(conn, binary_id)

        if errors:
            conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("catalog_errors", json_dumps(errors)))
        if static_skips:
            conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                ("static_disassembly_skips", json_dumps(static_skips)),
            )

    return {
        "database": str(db_path),
        "target_project_id": target.project_id,
        "target_project_name": target.project_name,
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
        "wincr": __version__,
        "haloce_catalog": __version__,
        "python": platform.python_version(),
    }
    for name, command in {
        "llvm-objdump": ["llvm-objdump", "--version"],
        "rizin": ["rizin", "-v"],
        "radare2": ["r2", "-v"],
        "drrun": ["drrun", "-version"],
        "wincr-trace-run": ["wincr-trace-run", "--version"],
        "halo-trace-run": ["halo-trace-run", "--version"],
        "wine": ["wine", "--version"],
        "ghidra_analyzeHeadless": [_ghidra_headless(), "-version"],
        "frida": ["frida", "--version"],
        "sqlite3": ["sqlite3", "--version"],
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


def _env_install_root(target_config: TargetConfig) -> Path | None:
    value = _env_value(target_config.install_root_env) or _env_value("WINCR_INSTALL_ROOT")
    return Path(value) if value else None


def _env_value(name: str) -> str | None:
    return os.environ.get(name)


def _ghidra_headless() -> str:
    return _env_value("WINCR_GHIDRA_HEADLESS") or _env_value("HALOCE_GHIDRA_HEADLESS") or "analyzeHeadless"


def nix_haloce_source_info() -> str | None:
    return target_source_info(load_target_config())


def target_source_info(target_config: TargetConfig) -> str | None:
    env_value = _env_value(target_config.source_info_env) or _env_value("WINCR_SOURCE_INFO")
    if env_value:
        return env_value
    if not target_config.flake_lock_node:
        return None
    for root in (Path.cwd(), *Path.cwd().parents):
        lock_path = root / "flake.lock"
        if not lock_path.exists():
            continue
        try:
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
            locked = lock["nodes"][target_config.flake_lock_node]["locked"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            continue
        return json_dumps(locked)
    return None


def runtime_provenance(target_config: TargetConfig | None = None) -> dict[str, object]:
    target = target_config or load_target_config()
    provenance: dict[str, object] = {
        "cwd": str(Path.cwd()),
        "target_project_id": target.project_id,
        "target_project_name": target.project_name,
    }
    for key in {
        "IN_NIX_SHELL",
        "WINCR_REFERENCE_PACKAGE",
        "WINCR_INSTALL_ROOT",
        target.reference_package_env,
        target.install_root_env,
    }:
        value = _env_value(key)
        if value:
            provenance[key.lower()] = value
    source_info = target_source_info(target)
    if source_info:
        try:
            provenance["source_info"] = json.loads(source_info)
            provenance[target.source_info_metadata_key] = json.loads(source_info)
        except json.JSONDecodeError:
            provenance["source_info"] = source_info
            provenance[target.source_info_metadata_key] = source_info
    return provenance


def _infer_reference_package(install_root: Path) -> str | None:
    if install_root.name == "basePackage" and install_root.parent.exists():
        return str(install_root.parent)
    return None


def _insert_binary(conn: sqlite3.Connection, info: Any, install_root: Path, catalog_version: str, discovered_at: str) -> int:
    label = module_label(info.relative_path, info.sha256)
    ensure_label(
        conn,
        label,
        "module",
        info.relative_path,
        f"{info.role.scope} {info.role.role}: {info.role.reason}",
        created_at=discovered_at,
    )
    cursor = conn.execute(
        """
        INSERT INTO binaries(
          label, path, filename, sha256, size, kind, machine, timestamp, image_base, entrypoint_rva,
          size_of_image, subsystem, linker_version, pe_checksum, role, scope, role_reason,
          source_root, catalog_version, discovered_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            label,
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
    binary_id = int(cursor.lastrowid)
    ensure_oracle_mapping(
        conn,
        label=label,
        entity_type="module",
        binary_id=binary_id,
        module_sha256=info.sha256,
        rva_start=0,
        rva_end=info.size_of_image,
        private={"path": info.relative_path, "image_base": info.image_base},
    )
    return binary_id


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


def _insert_platform_endpoints(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    rows = []
    for item in info.imports:
        label = platform_endpoint_label(item.dll, item.symbol, item.ordinal)
        display = f"{item.dll}!{item.symbol}" if item.symbol else f"{item.dll}!#{item.ordinal}"
        ensure_label(conn, label, "platform_endpoint", display, "static PE import endpoint")
        conn.execute(
            """
            INSERT OR IGNORE INTO platform_endpoints(
              label, dll, symbol, ordinal, endpoint_kind, subsystem, mock_status, test_status
            )
            VALUES (?, ?, ?, ?, 'import', ?, ?, 'untested')
            """,
            (
                label,
                item.dll,
                item.symbol,
                item.ordinal,
                _endpoint_subsystem(item.dll),
                _endpoint_mock_status(item.dll, item.symbol, item.ordinal),
            ),
        )
        endpoint_id = int(
            conn.execute(
                """
                SELECT id FROM platform_endpoints
                WHERE lower(dll) = lower(?)
                  AND COALESCE(symbol, '') = COALESCE(?, '')
                  AND COALESCE(ordinal, -1) = COALESCE(?, -1)
                """,
                (item.dll, item.symbol, item.ordinal),
            ).fetchone()["id"]
        )
        rows.append((binary_id, endpoint_id, item.thunk_rva))
    conn.executemany(
        """
        INSERT OR IGNORE INTO binary_platform_endpoints(binary_id, endpoint_id, thunk_rva)
        VALUES (?, ?, ?)
        """,
        rows,
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
    binary_label = module_label(info.relative_path, info.sha256)
    rows = []
    for section in info.sections:
        if not section.executable:
            continue
        rva_start = section.virtual_address
        mapped_size = mapped_section_size(section.virtual_size, section.raw_size)
        rva_end = section.virtual_address + mapped_size
        label = executable_range_label(binary_label, rva_start, rva_end, classification)
        ensure_label(conn, label, "executable_range", f"{binary_label}:{section.name}", evidence)
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="executable_range",
            binary_id=binary_id,
            module_sha256=info.sha256,
            rva_start=rva_start,
            rva_end=rva_end,
            private={"section": section.name, "classification": classification},
        )
        rows.append(
            (
                label,
                binary_id,
                rva_start,
                rva_end,
                section.raw_pointer,
                section.raw_pointer + min(section.raw_size, mapped_size),
                classification,
                evidence,
            )
        )
    conn.executemany(
        """
        INSERT OR IGNORE INTO executable_ranges(
          label, binary_id, rva_start, rva_end, file_offset_start, file_offset_end, classification, evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def _insert_function_seeds(conn: sqlite3.Connection, binary_id: int, info: Any) -> None:
    binary_label = module_label(info.relative_path, info.sha256)
    rows = []
    for seed in info.function_seeds:
        label = function_label(binary_label, seed.rva, seed.source, seed.name)
        ensure_label(conn, label, "function", f"{binary_label}:{seed.name}", f"{seed.source} function seed")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="function",
            binary_id=binary_id,
            module_sha256=info.sha256,
            rva_start=seed.rva,
            rva_end=None,
            private={"name": seed.name, "source": seed.source},
        )
        rows.append((label, binary_id, seed.rva, seed.name, seed.source, seed.confidence))
    conn.executemany(
        """
        INSERT OR IGNORE INTO functions(
          label, binary_id, rva, name, source, confidence, test_status, clean_room_status
        )
        VALUES (?, ?, ?, ?, ?, ?, 'untested', 'needs-spec')
        """,
        rows,
    )


def _insert_blocks(conn: sqlite3.Connection, binary_id: int, blocks: list[Any]) -> int:
    binary_label, module_sha = _binary_identity(conn, binary_id)
    rows = []
    for block in blocks:
        label = basic_block_label(binary_label, block.rva_start, block.rva_end, block.source)
        ensure_label(conn, label, "basic_block", f"{binary_label}:block", f"{block.source} basic block")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="basic_block",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=block.rva_start,
            rva_end=block.rva_end,
            private={"source": block.source, "classification": block.classification},
        )
        rows.append(
            (
                label,
                binary_id,
                block.rva_start,
                block.rva_end,
                block.rva_end - block.rva_start,
                block.source,
                block.classification,
                block.confidence,
            )
        )
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO basic_blocks(
          label, binary_id, rva_start, rva_end, size, source, classification, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    return conn.total_changes - before


def _insert_edges(conn: sqlite3.Connection, binary_id: int, edges: list[Any]) -> int:
    binary_label, module_sha = _binary_identity(conn, binary_id)
    rows = []
    for edge in edges:
        label = cfg_edge_label(binary_label, edge.from_rva, edge.to_rva, edge.edge_type, edge.source)
        ensure_label(conn, label, "cfg_edge", f"{binary_label}:cfg", f"{edge.source} {edge.edge_type} edge")
        ensure_oracle_mapping(
            conn,
            label=label,
            entity_type="cfg_edge",
            binary_id=binary_id,
            module_sha256=module_sha,
            rva_start=edge.from_rva,
            rva_end=edge.to_rva,
            private={"source": edge.source, "edge_type": edge.edge_type},
        )
        rows.append((label, binary_id, edge.from_rva, edge.to_rva, edge.edge_type, edge.source, edge.confidence))
    before = conn.total_changes
    conn.executemany(
        """
        INSERT OR IGNORE INTO cfg_edges(label, binary_id, from_rva, to_rva, edge_type, source, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
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
    return sum(mapped_section_size(section.virtual_size, section.raw_size) for section in info.sections if section.executable)


def _binary_identity(conn: sqlite3.Connection, binary_id: int) -> tuple[str, str]:
    row = conn.execute("SELECT label, sha256 FROM binaries WHERE id = ?", (binary_id,)).fetchone()
    if row is None:
        raise ValueError(f"unknown binary id {binary_id}")
    return str(row["label"]), str(row["sha256"])


def _endpoint_subsystem(dll: str) -> str:
    return endpoint_subsystem(dll)


def _endpoint_mock_status(dll: str, symbol: str | None = None, ordinal: int | None = None) -> str:
    return endpoint_mock_status(dll, symbol, ordinal)
