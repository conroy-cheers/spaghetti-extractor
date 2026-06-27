from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .db import connect
from .util import write_json


def generate_reports(db_path: Path, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    manifest = manifest_json(conn)
    coverage = coverage_json(conn)
    gates = gates_json(conn, coverage)

    manifest_path = out_dir / "manifest.json"
    coverage_path = out_dir / "coverage.json"
    gates_path = out_dir / "gates.json"
    catalog_md_path = out_dir / "catalog.md"
    coverage_md_path = out_dir / "coverage.md"

    write_json(manifest_path, manifest)
    write_json(coverage_path, coverage)
    write_json(gates_path, gates)
    catalog_md_path.write_text(catalog_markdown(manifest, gates), encoding="utf-8")
    coverage_md_path.write_text(coverage_markdown(coverage, gates), encoding="utf-8")

    return {
        "manifest_json": manifest_path,
        "coverage_json": coverage_path,
        "gates_json": gates_path,
        "catalog_markdown": catalog_md_path,
        "coverage_markdown": coverage_md_path,
    }


def manifest_json(conn: sqlite3.Connection) -> dict[str, Any]:
    metadata = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM metadata ORDER BY key")}
    binaries = []
    for binary in conn.execute("SELECT b.* FROM binaries b ORDER BY b.scope, b.path"):
        counts = {
            "sections": _count_for_binary(conn, "sections", binary["id"]),
            "imports": _count_for_binary(conn, "imports", binary["id"]),
            "exports": _count_for_binary(conn, "exports", binary["id"]),
            "resources": _count_for_binary(conn, "resources", binary["id"]),
            "executable_ranges": _count_for_binary(conn, "executable_ranges", binary["id"]),
            "functions": _count_for_binary(conn, "functions", binary["id"]),
            "basic_blocks": _count_for_binary(conn, "basic_blocks", binary["id"]),
        }
        imports = [
            row["dll"]
            for row in conn.execute(
                "SELECT DISTINCT dll FROM imports WHERE binary_id = ? ORDER BY lower(dll)",
                (binary["id"],),
            )
        ]
        sections = [
            {
                "name": row["name"],
                "rva_start": row["virtual_address"],
                "rva_end": row["virtual_address"] + max(row["virtual_size"], row["raw_size"]),
                "flags": row["flags"],
                "sha256": row["sha256"],
            }
            for row in conn.execute(
                "SELECT name, virtual_address, virtual_size, raw_size, flags, sha256 FROM sections WHERE binary_id = ?",
                (binary["id"],),
            )
        ]
        binaries.append(
            {
                "path": binary["path"],
                "filename": binary["filename"],
                "sha256": binary["sha256"],
                "size": binary["size"],
                "kind": binary["kind"],
                "machine": binary["machine"],
                "image_base": binary["image_base"],
                "entrypoint_rva": binary["entrypoint_rva"],
                "size_of_image": binary["size_of_image"],
                "subsystem": binary["subsystem"],
                "role": binary["role"],
                "scope": binary["scope"],
                "role_reason": binary["role_reason"],
                "counts": counts,
                "import_dlls": imports,
                "sections": sections,
            }
        )

    return {
        "metadata": metadata,
        "summary": _catalog_summary(conn),
        "binaries": binaries,
    }


def coverage_json(conn: sqlite3.Connection) -> dict[str, Any]:
    static_blocks = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM basic_blocks bb
        JOIN binaries b ON b.id = bb.binary_id
        WHERE b.scope = 'included'
        """
    ).fetchone()["count"]
    covered_static_blocks = conn.execute(
        """
        SELECT COUNT(DISTINCT bb.id) AS count
        FROM basic_blocks bb
        JOIN binaries b ON b.id = bb.binary_id
        JOIN coverage_blocks cb
          ON cb.binary_id = bb.binary_id
         AND cb.rva_start <= bb.rva_start
         AND cb.rva_end >= bb.rva_end
        WHERE b.scope = 'included'
        """
    ).fetchone()["count"]
    dynamic_blocks = conn.execute("SELECT COUNT(*) AS count FROM coverage_blocks").fetchone()["count"]
    dynamic_edges = conn.execute("SELECT COUNT(*) AS count FROM coverage_edges").fetchone()["count"]
    unresolved_modules = [
        dict(row)
        for row in conn.execute(
            """
            SELECT tr.test_id, om.drcov_module_id, om.path, om.sha256
            FROM observed_modules om
            JOIN test_runs tr ON tr.id = om.test_run_id
            WHERE om.binary_id IS NULL
            ORDER BY tr.test_id, om.drcov_module_id
            """
        )
    ]
    by_binary = [
        dict(row)
        for row in conn.execute(
            """
            SELECT b.path, b.sha256, b.scope,
                   COUNT(DISTINCT bb.id) AS static_blocks,
                   COUNT(DISTINCT cb.id) AS covered_blocks
            FROM binaries b
            LEFT JOIN basic_blocks bb ON bb.binary_id = b.id
            LEFT JOIN coverage_blocks cb ON cb.binary_id = b.id
            WHERE b.scope IN ('included', 'candidate')
            GROUP BY b.id
            ORDER BY b.scope, b.path
            """
        )
    ]
    return {
        "static_blocks": static_blocks,
        "covered_static_blocks": covered_static_blocks,
        "dynamic_blocks": dynamic_blocks,
        "dynamic_edges": dynamic_edges,
        "coverage_percent": (covered_static_blocks / static_blocks * 100.0) if static_blocks else 0.0,
        "unresolved_modules": unresolved_modules,
        "by_binary": by_binary,
    }


def gates_json(conn: sqlite3.Connection, coverage: dict[str, Any] | None = None) -> dict[str, Any]:
    if coverage is None:
        coverage = coverage_json(conn)
    unknown_exec_bytes = conn.execute(
        """
        SELECT COALESCE(SUM(x.rva_end - x.rva_start), 0) AS bytes
        FROM executable_ranges x
        JOIN binaries b ON b.id = x.binary_id
        WHERE b.scope IN ('included', 'candidate') AND x.classification = 'unknown'
        """
    ).fetchone()["bytes"]
    unknown_functions = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM functions f
        JOIN binaries b ON b.id = f.binary_id
        WHERE b.scope IN ('included', 'candidate')
          AND (f.subsystem = 'unknown' OR f.purity = 'unknown' OR f.side_effects = 'unknown')
        """
    ).fetchone()["count"]
    waivers = conn.execute("SELECT COUNT(*) AS count FROM waivers").fetchone()["count"]
    interface_imports = conn.execute(
        """
        SELECT COUNT(DISTINCT lower(i.dll) || ':' || COALESCE(i.symbol, '#' || i.ordinal)) AS count
        FROM imports i
        JOIN binaries b ON b.id = i.binary_id
        WHERE b.scope IN ('included', 'candidate')
        """
    ).fetchone()["count"]

    return {
        "catalog-complete": {
            "status": "pass" if unknown_exec_bytes == 0 and unknown_functions == 0 else "open",
            "unknown_executable_bytes": unknown_exec_bytes,
            "unclassified_functions": unknown_functions,
            "waivers": waivers,
        },
        "coverage-complete": {
            "status": "pass"
            if coverage["static_blocks"] and coverage["covered_static_blocks"] == coverage["static_blocks"]
            else "open",
            "static_blocks": coverage["static_blocks"],
            "covered_static_blocks": coverage["covered_static_blocks"],
            "unresolved_dynamic_modules": len(coverage["unresolved_modules"]),
        },
        "interface-complete": {
            "status": "open",
            "observed_static_import_endpoints": interface_imports,
            "note": "mock/spec completeness is tracked in public interface specs and oracle tests",
        },
        "data-state-complete": {
            "status": "open",
            "note": "map/profile/save/packet fixtures are scaffolded and must be filled from behavior traces",
        },
        "oracle-complete": {
            "status": "open",
            "note": "original binaries must pass the public process suite plus private harness suite",
        },
        "mutation-effective": {
            "status": "open",
            "note": "mutation checks start once clean-room implementation candidates exist",
        },
        "reproducible": {
            "status": "pass",
            "note": "reports include binary hashes, catalog version, tool versions, and install-root provenance",
        },
    }


def catalog_markdown(manifest: dict[str, Any], gates: dict[str, Any]) -> str:
    summary = manifest["summary"]
    lines = [
        "# Halo CE Runtime Catalog",
        "",
        "This report contains hashes, PE metadata, role dispositions, and discovered addresses only.",
        "It intentionally excludes original binaries, decompiled bodies, pseudocode, assets, and keys.",
        "",
        "## Summary",
        "",
        f"- Catalog version: `{manifest['metadata'].get('catalog_version', 'unknown')}`",
        f"- Install root: `{manifest['metadata'].get('install_root', 'unknown')}`",
        f"- Binaries: {summary['binaries']}",
        f"- Included runtime binaries: {summary['included']}",
        f"- Candidate runtime binaries: {summary['candidate']}",
        f"- Excluded binaries: {summary['excluded']}",
        f"- Executable ranges: {summary['executable_ranges']}",
        f"- Seeded/static functions: {summary['functions']}",
        f"- Capstone block candidates: {summary['basic_blocks']}",
        "",
        "## Gates",
        "",
    ]
    for name, data in gates.items():
        lines.append(f"- `{name}`: **{data['status']}**")
    lines.extend(["", "## Binaries", ""])
    for binary in manifest["binaries"]:
        lines.append(
            "- `{path}` `{scope}` `{role}` sha256 `{sha}` image_base `{base:#x}` entry `{entry:#x}`".format(
                path=binary["path"],
                scope=binary["scope"],
                role=binary["role"],
                sha=binary["sha256"],
                base=binary["image_base"] or 0,
                entry=binary["entrypoint_rva"] or 0,
            )
        )
        lines.append(f"  - {binary['role_reason']}")
    lines.append("")
    return "\n".join(lines)


def coverage_markdown(coverage: dict[str, Any], gates: dict[str, Any]) -> str:
    lines = [
        "# Halo CE Coverage Report",
        "",
        "Dynamic coverage is mapped by original module hash plus RVA when drcov module paths can be resolved.",
        "",
        "## Summary",
        "",
        f"- Static included block candidates: {coverage['static_blocks']}",
        f"- Covered static block candidates: {coverage['covered_static_blocks']}",
        f"- Coverage: {coverage['coverage_percent']:.2f}%",
        f"- Dynamic blocks ingested: {coverage['dynamic_blocks']}",
        f"- Dynamic edges ingested: {coverage['dynamic_edges']}",
        f"- Unresolved dynamic modules: {len(coverage['unresolved_modules'])}",
        "",
        "## Gate Status",
        "",
        f"- `coverage-complete`: **{gates['coverage-complete']['status']}**",
        "",
        "## By Binary",
        "",
    ]
    for item in coverage["by_binary"]:
        lines.append(
            f"- `{item['path']}` `{item['scope']}` static_blocks={item['static_blocks']} "
            f"covered_blocks={item['covered_blocks']}"
        )
    if coverage["unresolved_modules"]:
        lines.extend(["", "## Unresolved Modules", ""])
        for item in coverage["unresolved_modules"]:
            lines.append(f"- `{item['test_id']}` module {item['drcov_module_id']}: `{item['path']}`")
    lines.append("")
    return "\n".join(lines)


def _catalog_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT COUNT(*) AS binaries,
               SUM(CASE WHEN scope = 'included' THEN 1 ELSE 0 END) AS included,
               SUM(CASE WHEN scope = 'candidate' THEN 1 ELSE 0 END) AS candidate,
               SUM(CASE WHEN scope = 'excluded' THEN 1 ELSE 0 END) AS excluded
        FROM binaries
        """
    ).fetchone()
    counts = {
        "sections": "SELECT COUNT(*) AS count FROM sections",
        "imports": "SELECT COUNT(*) AS count FROM imports",
        "exports": "SELECT COUNT(*) AS count FROM exports",
        "resources": "SELECT COUNT(*) AS count FROM resources",
        "executable_ranges": "SELECT COUNT(*) AS count FROM executable_ranges",
        "functions": "SELECT COUNT(*) AS count FROM functions",
        "basic_blocks": "SELECT COUNT(*) AS count FROM basic_blocks",
        "cfg_edges": "SELECT COUNT(*) AS count FROM cfg_edges",
        "waivers": "SELECT COUNT(*) AS count FROM waivers",
    }
    summary = {
        "binaries": row["binaries"] or 0,
        "included": row["included"] or 0,
        "candidate": row["candidate"] or 0,
        "excluded": row["excluded"] or 0,
    }
    for key, query in counts.items():
        summary[key] = conn.execute(query).fetchone()["count"]
    return summary


def _count_for_binary(conn: sqlite3.Connection, table: str, binary_id: int) -> int:
    return conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE binary_id = ?", (binary_id,)).fetchone()["count"]
