from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .data_state import required_data_state_cases
from .db import connect, initialize
from .interfaces import REQUIRED_INTERFACE_CASES
from .mutation import REQUIRED_MUTATION_KINDS
from .oracle import REQUIRED_ORACLE_PRIVATE_SUITES, REQUIRED_ORACLE_PROCESS_SUITES
from .spec_generation import specs_json, specs_markdown
from .target import target_lists_from_metadata
from .util import public_text, write_json


def generate_reports(db_path: Path, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        initialize(conn)
        manifest = manifest_json(conn)
        coverage = coverage_json(conn)
        gates = gates_json(conn, coverage)
        specs = specs_json(conn)
        tests = tests_json(conn)
    finally:
        conn.close()

    manifest_path = out_dir / "manifest.json"
    coverage_path = out_dir / "coverage.json"
    gates_path = out_dir / "gates.json"
    specs_path = out_dir / "specs.json"
    tests_path = out_dir / "tests.json"
    catalog_md_path = out_dir / "catalog.md"
    coverage_md_path = out_dir / "coverage.md"
    specs_md_path = out_dir / "specs.md"
    tests_md_path = out_dir / "tests.md"

    write_json(manifest_path, manifest)
    write_json(coverage_path, coverage)
    write_json(gates_path, gates)
    write_json(specs_path, specs)
    write_json(tests_path, tests)
    catalog_md_path.write_text(catalog_markdown(manifest, gates), encoding="utf-8")
    coverage_md_path.write_text(coverage_markdown(coverage, gates), encoding="utf-8")
    specs_md_path.write_text(specs_markdown(specs), encoding="utf-8")
    tests_md_path.write_text(tests_markdown(tests, gates), encoding="utf-8")

    return {
        "manifest_json": manifest_path,
        "coverage_json": coverage_path,
        "gates_json": gates_path,
        "specs_json": specs_path,
        "tests_json": tests_path,
        "catalog_markdown": catalog_md_path,
        "coverage_markdown": coverage_md_path,
        "specs_markdown": specs_md_path,
        "tests_markdown": tests_md_path,
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
            "executable_byte_classes": _count_for_binary(conn, "executable_byte_classes", binary["id"]),
            "functions": _count_for_binary(conn, "functions", binary["id"]),
            "basic_blocks": _count_for_binary(conn, "basic_blocks", binary["id"]),
            "static_cross_checks": _count_for_binary(conn, "static_cross_checks", binary["id"]),
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
                "rva_end": row["virtual_address"] + (row["virtual_size"] if row["virtual_size"] > 0 else row["raw_size"]),
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
                "label": binary["label"],
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
        "target": _target_report(metadata),
        "summary": _catalog_summary(conn),
        "binaries": binaries,
    }


def _target_report(metadata: dict[str, str]) -> dict[str, Any]:
    config = _json_any(metadata.get("target_config_json"), {})
    if isinstance(config, dict):
        project = config.get("project", {})
        if isinstance(project, dict):
            return {
                "id": str(project.get("id") or metadata.get("target_project_id") or "unknown"),
                "name": str(project.get("name") or metadata.get("target_project_name") or "Windows Target"),
                "config": config,
            }
    return {
        "id": metadata.get("target_project_id", "legacy-halo-ce"),
        "name": metadata.get("target_project_name", "Halo CE"),
        "config": {},
    }


def coverage_json(conn: sqlite3.Connection) -> dict[str, Any]:
    static_blocks = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM basic_blocks bb
        JOIN binaries b ON b.id = bb.binary_id
        WHERE b.scope = 'included'
          AND bb.classification = 'code'
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
         AND cb.rva_end > bb.rva_start
        WHERE b.scope = 'included'
          AND bb.classification = 'code'
        """
    ).fetchone()["count"]
    dynamic_blocks = conn.execute("SELECT COUNT(*) AS count FROM coverage_blocks").fetchone()["count"]
    dynamic_edges = conn.execute("SELECT COUNT(*) AS count FROM coverage_edges").fetchone()["count"]
    dynamic_call_edges = conn.execute("SELECT COUNT(*) AS count FROM coverage_call_edges").fetchone()["count"]
    trace_probes = _trace_probe_summary(conn)
    static_cfg_edges = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM cfg_edges ce
        JOIN binaries b ON b.id = ce.binary_id
        WHERE b.scope = 'included'
          AND EXISTS (
            SELECT 1
            FROM basic_blocks bb
            WHERE bb.binary_id = ce.binary_id
              AND bb.classification = 'code'
              AND bb.rva_start <= ce.from_rva
              AND bb.rva_end > ce.from_rva
          )
        """
    ).fetchone()["count"]
    covered_static_cfg_edges = conn.execute(
        """
        SELECT COUNT(DISTINCT ce.id) AS count
        FROM cfg_edges ce
        JOIN binaries b ON b.id = ce.binary_id
        WHERE b.scope = 'included'
          AND EXISTS (
            SELECT 1
            FROM basic_blocks bb
            WHERE bb.binary_id = ce.binary_id
              AND bb.classification = 'code'
              AND bb.rva_start <= ce.from_rva
              AND bb.rva_end > ce.from_rva
          )
          AND (
            EXISTS (
              SELECT 1
              FROM coverage_edges cove
              WHERE cove.binary_id = ce.binary_id
                AND cove.from_rva = ce.from_rva
                AND cove.to_rva = ce.to_rva
            )
            OR (
              lower(ce.edge_type) LIKE '%fall%'
              AND EXISTS (
                SELECT 1
                FROM coverage_blocks cb
                WHERE cb.binary_id = ce.binary_id
                  AND cb.rva_start <= ce.from_rva
                  AND cb.rva_end > ce.from_rva
              )
            )
          )
        """
    ).fetchone()["count"]
    static_call_edges = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM call_edges ce
        JOIN binaries b ON b.id = ce.binary_id
        WHERE b.scope = 'included'
        """
    ).fetchone()["count"]
    covered_static_call_edges = conn.execute(
        """
        SELECT COUNT(DISTINCT ce.id) AS count
        FROM call_edges ce
        JOIN binaries b ON b.id = ce.binary_id
        WHERE b.scope = 'included'
          AND (
            EXISTS (
              SELECT 1
              FROM coverage_call_edges covc
              WHERE covc.binary_id = ce.binary_id
                AND covc.caller_rva = ce.caller_rva
                AND (
                  (ce.callee_rva IS NOT NULL AND covc.callee_rva = ce.callee_rva)
                  OR (ce.callee_symbol IS NOT NULL AND covc.callee_symbol = ce.callee_symbol)
                  OR (ce.callee_symbol IS NOT NULL AND covc.callee_rva IS NULL)
                )
            )
            OR (
              ce.callee_rva IS NOT NULL
              AND EXISTS (
                SELECT 1
                FROM coverage_blocks caller_block
                JOIN coverage_blocks callee_block
                  ON callee_block.binary_id = ce.binary_id
                 AND callee_block.test_run_id = caller_block.test_run_id
                 AND callee_block.rva_start <= ce.callee_rva
                 AND callee_block.rva_end > ce.callee_rva
                WHERE caller_block.binary_id = ce.binary_id
                  AND caller_block.rva_start <= ce.caller_rva
                  AND caller_block.rva_end > ce.caller_rva
              )
            )
          )
        """
    ).fetchone()["count"]
    waived_static_blocks = conn.execute(
        """
        SELECT COUNT(DISTINCT bb.id) AS count
        FROM basic_blocks bb
        JOIN binaries b ON b.id = bb.binary_id
        JOIN waivers w
          ON w.binary_id = bb.binary_id
         AND w.rva_start <= bb.rva_start
         AND w.rva_end >= bb.rva_end
        WHERE b.scope = 'included'
          AND bb.classification = 'code'
        """
    ).fetchone()["count"]
    waived_static_cfg_edges = conn.execute(
        """
        SELECT COUNT(DISTINCT ce.id) AS count
        FROM cfg_edges ce
        JOIN binaries b ON b.id = ce.binary_id
        JOIN waivers w
          ON w.binary_id = ce.binary_id
         AND w.rva_start <= ce.from_rva
         AND w.rva_end >= ce.from_rva
        WHERE b.scope = 'included'
          AND EXISTS (
            SELECT 1
            FROM basic_blocks bb
            WHERE bb.binary_id = ce.binary_id
              AND bb.classification = 'code'
              AND bb.rva_start <= ce.from_rva
              AND bb.rva_end > ce.from_rva
          )
        """
    ).fetchone()["count"]
    waived_static_call_edges = conn.execute(
        """
        SELECT COUNT(DISTINCT ce.id) AS count
        FROM call_edges ce
        JOIN binaries b ON b.id = ce.binary_id
        JOIN waivers w
          ON w.binary_id = ce.binary_id
         AND w.rva_start <= ce.caller_rva
         AND w.rva_end >= ce.caller_rva
        WHERE b.scope = 'included'
        """
    ).fetchone()["count"]
    unresolved_modules = _target_unresolved_modules(conn)
    by_binary = [
        dict(row)
        for row in conn.execute(
            """
            SELECT b.path, b.sha256, b.scope,
                   COUNT(DISTINCT CASE WHEN bb.classification = 'code' THEN bb.id END) AS static_blocks,
                   COUNT(DISTINCT cb.id) AS covered_blocks
            FROM binaries b
            LEFT JOIN basic_blocks bb ON bb.binary_id = b.id
            LEFT JOIN coverage_blocks cb
              ON cb.binary_id = b.id
             AND bb.classification = 'code'
             AND cb.rva_start <= bb.rva_start
             AND cb.rva_end > bb.rva_start
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
        "dynamic_call_edges": dynamic_call_edges,
        "trace_probes": trace_probes,
        "static_cfg_edges": static_cfg_edges,
        "covered_static_cfg_edges": covered_static_cfg_edges,
        "static_call_edges": static_call_edges,
        "covered_static_call_edges": covered_static_call_edges,
        "waived_static_blocks": waived_static_blocks,
        "waived_static_cfg_edges": waived_static_cfg_edges,
        "waived_static_call_edges": waived_static_call_edges,
        "coverage_percent": (covered_static_blocks / static_blocks * 100.0) if static_blocks else 0.0,
        "unresolved_modules": unresolved_modules,
        "by_binary": by_binary,
    }


def _target_unresolved_modules(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    roots = [
        str(row["source_root"])
        for row in conn.execute(
            """
            SELECT DISTINCT source_root
            FROM binaries
            WHERE scope IN ('included', 'candidate', 'excluded')
              AND source_root != ''
            ORDER BY source_root
            """
        )
    ]
    filenames = {
        str(row["filename"]).lower()
        for row in conn.execute(
            """
            SELECT DISTINCT filename
            FROM binaries
            WHERE scope IN ('included', 'candidate', 'excluded')
            """
        )
    }
    rows = [
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
    return [row for row in rows if _is_target_unresolved_module(str(row.get("path") or ""), roots, filenames)]


def _is_target_unresolved_module(path: str, source_roots: list[str], filenames: set[str]) -> bool:
    normalized = path.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].lower()
    if basename in filenames:
        return True
    for root in source_roots:
        normalized_root = root.replace("\\", "/").rstrip("/")
        if normalized_root and (normalized == normalized_root or normalized.startswith(f"{normalized_root}/")):
            return True
    return False


def tests_json(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return a reproducible report of behavior and oracle test evidence.

    This report deliberately summarizes dynamic coverage by test-run label and
    counts. The private coverage/oracle tables remain the source of raw
    module-hash/RVA mappings.
    """

    return {
        "schema_version": 1,
        "summary": {
            "test_runs": _count(conn, "test_runs"),
            "interface_test_cases": _count(conn, "interface_test_cases"),
            "data_state_test_cases": _count(conn, "data_state_test_cases"),
            "oracle_test_cases": _count(conn, "oracle_test_cases"),
            "behavior_contracts": _count(conn, "behavior_contracts"),
            "behavior_observations": _count(conn, "behavior_observations"),
            "process_behavior_observations": _count(conn, "process_behavior_observations"),
            "internal_routine_contracts": _count(conn, "internal_routine_contracts"),
            "private_artifact_bundles": _count(conn, "private_artifact_bundles"),
            "private_artifacts": _count(conn, "private_artifacts"),
            "internal_harnesses": _count(conn, "internal_harnesses"),
            "internal_harness_runs": _count(conn, "internal_harness_runs"),
            "mutation_test_cases": _count(conn, "mutation_test_cases"),
            "trace_probe_results": _count(conn, "trace_probe_results"),
            "status_counts": {
                "test_runs": _status_counts(conn, "test_runs", "status"),
                "interface_test_cases": _status_counts(conn, "interface_test_cases", "status"),
                "data_state_test_cases": _status_counts(conn, "data_state_test_cases", "status"),
                "oracle_test_cases": _status_counts(conn, "oracle_test_cases", "status"),
                "behavior_observations": _status_counts(conn, "behavior_observations", "status"),
                "process_behavior_observations": _status_counts(conn, "process_behavior_observations", "status"),
                "internal_harness_runs": _status_counts(conn, "internal_harness_runs", "status"),
                "mutation_test_cases": _status_counts(conn, "mutation_test_cases", "status"),
                "trace_probe_results": _status_counts(conn, "trace_probe_results", "status"),
            },
        },
        "test_runs": _test_runs(conn),
        "interface_test_cases": _interface_test_cases(conn),
        "data_state_test_cases": _data_state_test_cases(conn),
        "oracle_test_cases": _oracle_test_cases(conn),
        "behavior_contracts": _behavior_contracts(conn),
        "behavior_observations": _behavior_observations(conn),
        "process_behavior_observations": _process_behavior_observations(conn),
        "internal_harnesses": _internal_harnesses(conn),
        "mutation_test_cases": _mutation_test_cases(conn),
        "trace_probe_results": _trace_probe_test_rows(conn),
    }


def _trace_probe_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN status = 'pass' THEN 1 ELSE 0 END) AS passed,
               SUM(CASE WHEN status <> 'pass' THEN 1 ELSE 0 END) AS failed
        FROM trace_probe_results
        """
    ).fetchone()
    samples = []
    for sample in conn.execute(
        """
        SELECT label, probe_id, probe_kind, command, status, started_at, finished_at,
               trace_log, expected_filename, expected_sha256, returncode, timed_out,
               raw_trace_json, mapped_json, failures_json, provenance_json
        FROM trace_probe_results
        ORDER BY started_at DESC, id DESC
        LIMIT 20
        """
    ):
        provenance = _json_any(sample["provenance_json"], {})
        samples.append(
            {
                "label": sample["label"],
                "probe_id": sample["probe_id"],
                "probe_kind": sample["probe_kind"],
                "command": sample["command"],
                "status": sample["status"],
                "started_at": sample["started_at"],
                "finished_at": sample["finished_at"],
                "trace_log": sample["trace_log"],
                "expected_filename": sample["expected_filename"],
                "expected_sha256": sample["expected_sha256"],
                "returncode": sample["returncode"],
                "timed_out": bool(sample["timed_out"]),
                "raw_trace": _json_any(sample["raw_trace_json"], {}),
                "mapped": _json_any(sample["mapped_json"], {}),
                "failures": _json_any(sample["failures_json"], []),
                "direct_launch": provenance.get("direct_launch", {}) if isinstance(provenance, dict) else {},
            }
        )
    return {
        "total": int(row["total"] or 0),
        "passed": int(row["passed"] or 0),
        "failed": int(row["failed"] or 0),
        "samples": samples,
    }


def gates_json(conn: sqlite3.Connection, coverage: dict[str, Any] | None = None) -> dict[str, Any]:
    if coverage is None:
        coverage = coverage_json(conn)
    metadata = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM metadata ORDER BY key")}
    unknown_exec_bytes = conn.execute(
        """
        SELECT COALESCE(SUM(x.rva_end - x.rva_start), 0) AS bytes
        FROM executable_byte_classes x
        JOIN binaries b ON b.id = x.binary_id
        WHERE b.scope IN ('included', 'candidate')
          AND x.classification = 'unknown'
          AND x.source <> 'waiver'
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
    unlabeled = _unlabeled_entity_count(conn)
    partition_issues = _executable_partition_issues(conn)
    static_cross_check_gate = _static_cross_check_gate(conn)
    interface_gate = _interface_gate(conn)
    data_state_gate = _data_state_gate(conn, metadata)
    oracle_gate = _oracle_gate(conn, metadata)
    mutation_gate = _mutation_gate(conn, metadata)
    private_artifact_gate = _private_artifact_gate(conn)
    dirty_reimplementation_gate = _dirty_reimplementation_gate(conn, private_artifact_gate)
    publication_clean_gate = _publication_clean_gate(conn)
    reproducible_gate = _reproducible_gate(conn)

    covered_or_waived_blocks = coverage["covered_static_blocks"] + coverage["waived_static_blocks"]
    covered_or_waived_cfg_edges = coverage["covered_static_cfg_edges"] + coverage["waived_static_cfg_edges"]
    covered_or_waived_call_edges = coverage["covered_static_call_edges"] + coverage["waived_static_call_edges"]
    has_static_control_flow = coverage["static_blocks"] > 0 and coverage["static_cfg_edges"] > 0
    call_edges_complete = (
        coverage["static_call_edges"] == 0 or covered_or_waived_call_edges >= coverage["static_call_edges"]
    )
    coverage_complete = (
        has_static_control_flow
        and covered_or_waived_blocks >= coverage["static_blocks"]
        and covered_or_waived_cfg_edges >= coverage["static_cfg_edges"]
        and call_edges_complete
        and len(coverage["unresolved_modules"]) == 0
    )

    return {
        "catalog-complete": {
            "status": "pass"
            if (
                unknown_exec_bytes == 0
                and unknown_functions == 0
                and unlabeled == 0
                and partition_issues == []
                and static_cross_check_gate["status"] == "pass"
            )
            else "open",
            "unknown_executable_bytes": unknown_exec_bytes,
            "unclassified_functions": unknown_functions,
            "unlabeled_entities": unlabeled,
            "executable_partition_issues": partition_issues,
            "static_cross_checks": static_cross_check_gate,
            "waivers": waivers,
        },
        "coverage-complete": {
            "status": "pass" if coverage_complete else "open",
            "static_blocks": coverage["static_blocks"],
            "covered_static_blocks": coverage["covered_static_blocks"],
            "waived_static_blocks": coverage["waived_static_blocks"],
            "static_cfg_edges": coverage["static_cfg_edges"],
            "covered_static_cfg_edges": coverage["covered_static_cfg_edges"],
            "waived_static_cfg_edges": coverage["waived_static_cfg_edges"],
            "static_call_edges": coverage["static_call_edges"],
            "covered_static_call_edges": coverage["covered_static_call_edges"],
            "waived_static_call_edges": coverage["waived_static_call_edges"],
            "unresolved_dynamic_modules": len(coverage["unresolved_modules"]),
            "trace_probe_attempts": coverage["trace_probes"]["total"],
            "passing_trace_probes": coverage["trace_probes"]["passed"],
        },
        "interface-complete": interface_gate,
        "data-state-complete": data_state_gate,
        "oracle-complete": oracle_gate,
        "mutation-effective": mutation_gate,
        "private-artifact-complete": private_artifact_gate,
        "dirty-reimplementation-ready": dirty_reimplementation_gate,
        "publication-clean": publication_clean_gate,
        "reproducible": reproducible_gate,
    }


def catalog_markdown(manifest: dict[str, Any], gates: dict[str, Any]) -> str:
    summary = manifest["summary"]
    target = manifest.get("target", {})
    project_name = target.get("name") or "Windows Target"
    lines = [
        f"# {project_name} Runtime Catalog",
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
        f"- Executable byte-class partitions: {summary['executable_byte_classes']}",
        f"- Seeded/static functions: {summary['functions']}",
        f"- Internal routine contracts: {summary['internal_routine_contracts']}",
        f"- Private artifact bundles: {summary['private_artifact_bundles']}",
        f"- Private artifact packets: {summary['private_artifacts']}",
        f"- Capstone block candidates: {summary['basic_blocks']}",
        f"- Static cross-checks: {summary['static_cross_checks']}",
        f"- Trace compatibility probes: {summary['trace_probe_results']}",
        "",
        "## Gates",
        "",
    ]
    for name, data in gates.items():
        lines.append(f"- `{name}`: **{data['status']}**")
    lines.extend(["", "## Binaries", ""])
    for binary in manifest["binaries"]:
        lines.append(
            "- `{label}` `{path}` `{scope}` `{role}` sha256 `{sha}` image_base `{base:#x}` entry `{entry:#x}`".format(
                label=binary["label"],
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
        "# Runtime Coverage Report",
        "",
        "Dynamic coverage is mapped by original module hash plus RVA when drcov module paths can be resolved.",
        "",
        "## Summary",
        "",
        f"- Static included block candidates: {coverage['static_blocks']}",
        f"- Covered static block candidates: {coverage['covered_static_blocks']}",
        f"- Coverage: {coverage['coverage_percent']:.2f}%",
        f"- Dynamic blocks ingested: {coverage['dynamic_blocks']}",
        f"- Dynamic CFG edges ingested: {coverage['dynamic_edges']}",
        f"- Dynamic call edges ingested: {coverage['dynamic_call_edges']}",
        f"- Trace compatibility probes: {coverage['trace_probes']['total']} "
        f"({coverage['trace_probes']['passed']} pass, {coverage['trace_probes']['failed']} fail)",
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
    if coverage["trace_probes"]["samples"]:
        lines.extend(["", "## Trace Compatibility Probes", ""])
        lines.append("These rows are diagnostic evidence only; they do not count as dynamic coverage.")
        lines.append("")
        for item in coverage["trace_probes"]["samples"]:
            failures = item["failures"] if isinstance(item["failures"], list) else []
            failure_text = "; ".join(str(failure) for failure in failures[:2]) if failures else "none"
            lines.append(
                f"- `{item['probe_id']}` `{item['status']}` kind `{item['probe_kind']}` "
                f"returncode={item['returncode']} timeout={item['timed_out']} trace `{item['trace_log']}`"
            )
            lines.append(f"  - failures: {failure_text}")
    lines.append("")
    return "\n".join(lines)


def tests_markdown(tests: dict[str, Any], gates: dict[str, Any]) -> str:
    summary = tests["summary"]
    lines = [
        "# Test Evidence Report",
        "",
        "This report summarizes recorded behavior/oracle evidence by stable labels and test IDs.",
        "Raw module-hash/RVA coverage mappings remain in the private catalog tables.",
        "",
        "## Summary",
        "",
        f"- Test runs: {summary['test_runs']}",
        f"- Interface test cases: {summary['interface_test_cases']}",
        f"- Data/state test cases: {summary['data_state_test_cases']}",
        f"- Oracle test cases: {summary['oracle_test_cases']}",
        f"- Behavior contracts: {summary['behavior_contracts']}",
        f"- Behavior observations: {summary['behavior_observations']}",
        f"- Process behavior observations: {summary.get('process_behavior_observations', 0)}",
        f"- Internal routine contracts: {summary.get('internal_routine_contracts', 0)}",
        f"- Private artifact bundles: {summary.get('private_artifact_bundles', 0)}",
        f"- Private artifact packets: {summary.get('private_artifacts', 0)}",
        f"- Internal harnesses: {summary['internal_harnesses']}",
        f"- Internal harness runs: {summary['internal_harness_runs']}",
        f"- Mutation test cases: {summary['mutation_test_cases']}",
        f"- Trace compatibility probes: {summary['trace_probe_results']}",
        "",
        "## Gate Status",
        "",
        f"- `interface-complete`: **{gates['interface-complete']['status']}**",
        f"- `data-state-complete`: **{gates['data-state-complete']['status']}**",
        f"- `oracle-complete`: **{gates['oracle-complete']['status']}**",
        f"- `mutation-effective`: **{gates['mutation-effective']['status']}**",
        f"- `private-artifact-complete`: **{gates['private-artifact-complete']['status']}**",
        f"- `dirty-reimplementation-ready`: **{gates['dirty-reimplementation-ready']['status']}**",
        f"- `publication-clean`: **{gates['publication-clean']['status']}**",
        f"- `reproducible`: **{gates['reproducible']['status']}**",
        "",
    ]
    if tests["test_runs"]:
        lines.extend(["## Test Runs", ""])
        for item in tests["test_runs"][:100]:
            lines.append(
                f"- `{item['label']}` test_id=`{item['test_id']}` suite=`{item['suite']}` "
                f"status=`{item['status']}` modules={item['observed_modules']} "
                f"blocks={item['coverage_blocks']} cfg_edges={item['coverage_edges']} "
                f"call_edges={item['coverage_call_edges']}"
            )
    if tests["oracle_test_cases"]:
        lines.extend(["", "## Oracle Tests", ""])
        for item in tests["oracle_test_cases"][:100]:
            lines.append(
                f"- `{item['label']}` suite=`{item['suite_id']}` test_id=`{item['test_id']}` "
                f"case=`{item['case_kind']}` status=`{item['status']}`"
            )
    if tests["behavior_contracts"]:
        lines.extend(["", "## Behavior Contracts", ""])
        for item in tests["behavior_contracts"][:100]:
            lines.append(
                f"- `{item['label']}` contract=`{item['contract_id']}` "
                f"version=`{item['version']}` observations={item['observations']}"
            )
    if tests["behavior_observations"]:
        lines.extend(["", "## Behavior Observations", ""])
        for item in tests["behavior_observations"][:100]:
            lines.append(
                f"- `{item['label']}` contract=`{item['contract_id']}` test_id=`{item['test_id']}` "
                f"status=`{item['status']}` sha256=`{item['observed_sha256']}`"
            )
    if tests.get("process_behavior_observations"):
        lines.extend(["", "## Process Behavior Observations", ""])
        for item in tests["process_behavior_observations"][:100]:
            lines.append(
                f"- `{item['label']}` contract=`{item['contract_id']}` test_id=`{item['test_id']}` "
                f"status=`{item['status']}` returncode={item['returncode']} "
                f"stdout_bytes={item['stdout_bytes']} stderr_bytes={item['stderr_bytes']}"
            )
    if tests["interface_test_cases"]:
        lines.extend(["", "## Interface Tests", ""])
        for item in tests["interface_test_cases"][:100]:
            lines.append(
                f"- `{item['label']}` endpoint=`{item['endpoint_label']}` "
                f"case=`{item['case_kind']}` status=`{item['status']}`"
            )
    if tests["data_state_test_cases"]:
        lines.extend(["", "## Data/State Tests", ""])
        for item in tests["data_state_test_cases"][:100]:
            lines.append(
                f"- `{item['label']}` structure=`{item['data_structure_label']}` "
                f"case=`{item['case_kind']}` status=`{item['status']}`"
            )
    if tests["mutation_test_cases"]:
        lines.extend(["", "## Mutation Tests", ""])
        for item in tests["mutation_test_cases"][:100]:
            lines.append(
                f"- `{item['label']}` kind=`{item['mutation_kind']}` "
                f"test_id=`{item['test_id']}` status=`{item['status']}`"
            )
    if tests["trace_probe_results"]:
        lines.extend(["", "## Trace Compatibility Probes", ""])
        lines.append("Probe rows are compatibility diagnostics and do not count as dynamic coverage.")
        lines.append("")
        for item in tests["trace_probe_results"][:100]:
            direct = item.get("direct_launch") if isinstance(item.get("direct_launch"), dict) else {}
            direct_status = "pass" if direct.get("ok") else "fail"
            lines.append(
                f"- `{item['label']}` probe_id=`{item['probe_id']}` status=`{item['status']}` "
                f"direct=`{direct_status}` mapped_blocks={item['counts']['mapped_blocks']} "
                f"failures={item['counts']['failures']}"
            )
    lines.append("")
    return "\n".join(lines)


def _test_runs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT tr.id, tr.label, tr.test_id, tr.suite, tr.status,
               tr.started_at, tr.finished_at, tr.tool_versions_json, tr.provenance_json,
               (SELECT COUNT(*) FROM observed_modules om WHERE om.test_run_id = tr.id) AS observed_modules,
               (SELECT COUNT(*) FROM coverage_blocks cb WHERE cb.test_run_id = tr.id) AS coverage_blocks,
               (SELECT COUNT(*) FROM coverage_edges ce WHERE ce.test_run_id = tr.id) AS coverage_edges,
               (SELECT COUNT(*) FROM coverage_call_edges cce WHERE cce.test_run_id = tr.id) AS coverage_call_edges
        FROM test_runs tr
        ORDER BY tr.started_at, tr.id
        """
    ):
        rows.append(
            {
                "label": row["label"],
                "test_id": row["test_id"],
                "suite": row["suite"],
                "status": row["status"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "observed_modules": int(row["observed_modules"] or 0),
                "coverage_blocks": int(row["coverage_blocks"] or 0),
                "coverage_edges": int(row["coverage_edges"] or 0),
                "coverage_call_edges": int(row["coverage_call_edges"] or 0),
            }
        )
    return rows


def _interface_test_cases(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT itc.label, pe.label AS endpoint_label, pe.dll, pe.symbol, pe.ordinal,
                   pe.subsystem, itc.case_kind, itc.test_id, itc.status,
                   itc.evidence
            FROM interface_test_cases itc
            JOIN platform_endpoints pe ON pe.id = itc.endpoint_id
            ORDER BY lower(pe.dll), COALESCE(pe.symbol, ''), itc.case_kind, itc.test_id
            """
        )
    ]
    _sanitize_public_evidence(rows)
    return rows


def _data_state_test_cases(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT dst.label, ds.label AS data_structure_label, ds.name,
                   ds.structure_kind, dst.case_kind, dst.test_id, dst.status,
                   dst.evidence
            FROM data_state_test_cases dst
            JOIN data_structures ds ON ds.id = dst.data_structure_id
            ORDER BY ds.structure_kind, ds.name, dst.case_kind, dst.test_id
            """
        )
    ]
    _sanitize_public_evidence(rows)
    return rows


def _oracle_test_cases(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT label, suite_id, test_id, case_kind, status, evidence, created_at
            FROM oracle_test_cases
            ORDER BY suite_id, case_kind, test_id
            """
        )
    ]
    _sanitize_public_evidence(rows)
    return rows


def _behavior_contracts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        {
            **dict(row),
            "observations": int(row["observations"] or 0),
            "process_observations": int(row["process_observations"] or 0),
        }
        for row in conn.execute(
            """
            SELECT bc.label, bc.contract_id, bc.title, bc.scope, bc.version,
                   bc.evidence,
                   COUNT(DISTINCT bo.id) AS observations,
                   COUNT(DISTINCT pbo.id) AS process_observations
            FROM behavior_contracts bc
            LEFT JOIN behavior_observations bo ON bo.behavior_contract_id = bc.id
            LEFT JOIN process_behavior_observations pbo ON pbo.behavior_contract_id = bc.id
            GROUP BY bc.id
            ORDER BY bc.contract_id, bc.version
            """
        )
    ]


def _behavior_observations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT bo.label, bc.label AS behavior_contract_label, bc.contract_id,
                   bo.test_id, bo.status, bo.observed_sha256,
                   bo.evidence, bo.created_at
            FROM behavior_observations bo
            JOIN behavior_contracts bc ON bc.id = bo.behavior_contract_id
            ORDER BY bc.contract_id, bo.test_id
            """
        )
    ]
    _sanitize_public_evidence(rows)
    return rows


def _process_behavior_observations(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = []
    for row in conn.execute(
        """
        SELECT pbo.label, bc.label AS behavior_contract_label, bc.contract_id,
               pbo.test_id, pbo.status, pbo.input_json, pbo.observed_json,
               pbo.observed_sha256, pbo.evidence, pbo.created_at
        FROM process_behavior_observations pbo
        JOIN behavior_contracts bc ON bc.id = pbo.behavior_contract_id
        ORDER BY bc.contract_id, pbo.test_id
        """
    ):
        observed = _json_any(row["observed_json"], {})
        rows.append(
            {
                "label": row["label"],
                "behavior_contract_label": row["behavior_contract_label"],
                "contract_id": row["contract_id"],
                "test_id": row["test_id"],
                "status": row["status"],
                "input": _json_any(row["input_json"], {}),
                "returncode": observed.get("returncode") if isinstance(observed, dict) else None,
                "timed_out": bool(observed.get("timed_out")) if isinstance(observed, dict) else False,
                "stdout_bytes": len(str(observed.get("stdout", "")).encode("utf-8", errors="replace"))
                if isinstance(observed, dict)
                else 0,
                "stderr_bytes": len(str(observed.get("stderr", "")).encode("utf-8", errors="replace"))
                if isinstance(observed, dict)
                else 0,
                "observed_sha256": row["observed_sha256"],
                "evidence": row["evidence"],
                "created_at": row["created_at"],
            }
        )
    _sanitize_public_evidence(rows)
    return rows


def _internal_harnesses(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    harnesses = [
        dict(row)
        for row in conn.execute(
            """
            SELECT label, target_label, harness_id, harness_kind,
                   input_contract, expected_observation, risk, created_at
            FROM internal_harnesses
            ORDER BY target_label, harness_id
            """
        )
    ]
    for harness in harnesses:
        harness["runs"] = [
            dict(row)
            for row in conn.execute(
                """
                SELECT ihr.label, ihr.test_id, ihr.status, ihr.evidence,
                       ihr.returncode, ihr.created_at
                FROM internal_harness_runs ihr
                JOIN internal_harnesses ih ON ih.id = ihr.internal_harness_id
                WHERE ih.label = ?
                ORDER BY ihr.test_id
                """,
                (harness["label"],),
            )
        ]
        _sanitize_public_evidence(harness["runs"])
    return harnesses


def _mutation_test_cases(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = [
        dict(row)
        for row in conn.execute(
            """
            SELECT label, mutation_kind, target_label, test_id, status, evidence, created_at
            FROM mutation_test_cases
            ORDER BY mutation_kind, COALESCE(target_label, ''), test_id
            """
        )
    ]
    _sanitize_public_evidence(rows)
    return rows


def _trace_probe_test_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT label, probe_id, probe_kind, status, started_at, finished_at,
               expected_filename, returncode, timed_out, raw_trace_json,
               mapped_json, failures_json, tool_versions_json, provenance_json
        FROM trace_probe_results
        ORDER BY started_at, id
        """
    ):
        raw = _json_any(row["raw_trace_json"], {})
        mapped = _json_any(row["mapped_json"], {})
        failures = _json_any(row["failures_json"], [])
        provenance = _json_any(row["provenance_json"], {})
        rows.append(
            {
                "label": row["label"],
                "probe_id": row["probe_id"],
                "probe_kind": row["probe_kind"],
                "status": row["status"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "expected_filename": row["expected_filename"],
                "returncode": row["returncode"],
                "timed_out": bool(row["timed_out"]),
                "direct_launch": _public_direct_launch(provenance),
                "counts": {
                    "raw_modules": _int_from_mapping(raw, "modules"),
                    "raw_blocks": _int_from_mapping(raw, "blocks"),
                    "raw_cfg_edges": _int_from_mapping(raw, "cfg_edges"),
                    "raw_call_edges": _int_from_mapping(raw, "call_edges"),
                    "raw_expected_modules": _int_from_mapping(raw, "expected_modules"),
                    "mapped_blocks": _int_from_mapping(mapped, "blocks"),
                    "mapped_cfg_edges": _int_from_mapping(mapped, "cfg_edges"),
                    "mapped_call_edges": _int_from_mapping(mapped, "call_edges"),
                    "failures": len(failures) if isinstance(failures, list) else 0,
                },
                "module_samples": raw.get("module_samples") if isinstance(raw.get("module_samples"), list) else [],
                "failures": failures if isinstance(failures, list) else [],
            }
        )
    return rows


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
        "executable_byte_classes": "SELECT COUNT(*) AS count FROM executable_byte_classes",
        "functions": "SELECT COUNT(*) AS count FROM functions",
        "internal_routine_contracts": "SELECT COUNT(*) AS count FROM internal_routine_contracts",
        "private_artifact_bundles": "SELECT COUNT(*) AS count FROM private_artifact_bundles",
        "private_artifacts": "SELECT COUNT(*) AS count FROM private_artifacts",
        "basic_blocks": "SELECT COUNT(*) AS count FROM basic_blocks",
        "function_semantics": "SELECT COUNT(*) AS count FROM function_semantics",
        "block_semantics": "SELECT COUNT(*) AS count FROM block_semantics",
        "cfg_edges": "SELECT COUNT(*) AS count FROM cfg_edges",
        "waivers": "SELECT COUNT(*) AS count FROM waivers",
        "test_runs": "SELECT COUNT(*) AS count FROM test_runs",
        "trace_probe_results": "SELECT COUNT(*) AS count FROM trace_probe_results",
        "labels": "SELECT COUNT(*) AS count FROM labels",
        "oracle_mappings": "SELECT COUNT(*) AS count FROM oracle_mappings",
        "oracle_test_cases": "SELECT COUNT(*) AS count FROM oracle_test_cases",
        "internal_harnesses": "SELECT COUNT(*) AS count FROM internal_harnesses",
        "internal_harness_runs": "SELECT COUNT(*) AS count FROM internal_harness_runs",
        "mutation_test_cases": "SELECT COUNT(*) AS count FROM mutation_test_cases",
        "static_cross_checks": "SELECT COUNT(*) AS count FROM static_cross_checks",
        "platform_endpoints": "SELECT COUNT(*) AS count FROM platform_endpoints",
        "interface_test_cases": "SELECT COUNT(*) AS count FROM interface_test_cases",
        "data_state_test_cases": "SELECT COUNT(*) AS count FROM data_state_test_cases",
        "value_traces": "SELECT COUNT(*) AS count FROM value_traces",
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


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"] or 0)


def _status_counts(conn: sqlite3.Connection, table: str, column: str) -> dict[str, int]:
    return {
        str(row[column]): int(row["count"] or 0)
        for row in conn.execute(
            f"""
            SELECT {column}, COUNT(*) AS count
            FROM {table}
            GROUP BY {column}
            ORDER BY {column}
            """
        )
    }


def _unlabeled_entity_count(conn: sqlite3.Connection) -> int:
    total = 0
    for table in [
        "binaries",
        "executable_ranges",
        "executable_byte_classes",
        "functions",
        "internal_routine_contracts",
        "basic_blocks",
        "cfg_edges",
        "call_edges",
        "data_refs",
        "waivers",
        "test_runs",
        "coverage_blocks",
        "coverage_edges",
        "coverage_call_edges",
        "trace_probe_results",
        "value_traces",
        "private_artifact_bundles",
        "private_artifacts",
        "oracle_test_cases",
        "internal_harnesses",
        "internal_harness_runs",
        "mutation_test_cases",
        "static_cross_checks",
        "platform_endpoints",
        "interface_test_cases",
        "data_structures",
        "data_state_test_cases",
        "globals",
    ]:
        total += conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM {table} t
            LEFT JOIN labels l ON l.label = t.label
            WHERE l.label IS NULL
            """
        ).fetchone()["count"]
    return total


def _executable_partition_issues(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    sections = conn.execute(
        """
        SELECT b.id AS binary_id, b.label AS binary_label, b.path, s.name, s.virtual_address,
               s.virtual_address + CASE WHEN s.virtual_size > 0 THEN s.virtual_size ELSE s.raw_size END AS section_end
        FROM sections s
        JOIN binaries b ON b.id = s.binary_id
        WHERE b.scope IN ('included', 'candidate') AND instr(s.flags, 'execute') > 0
        ORDER BY b.id, s.virtual_address
        """
    ).fetchall()
    for section in sections:
        cursor = int(section["virtual_address"])
        section_end = int(section["section_end"])
        ranges = conn.execute(
            """
            SELECT rva_start, rva_end, classification, label
            FROM executable_ranges
            WHERE binary_id = ?
              AND rva_start < ?
              AND rva_end > ?
            ORDER BY rva_start, rva_end
            """,
            (section["binary_id"], section_end, section["virtual_address"]),
        ).fetchall()
        for item in ranges:
            start = max(int(item["rva_start"]), int(section["virtual_address"]))
            end = min(int(item["rva_end"]), section_end)
            if start > cursor:
                issues.append(
                    {
                        "partition": "executable_ranges",
                        "kind": "gap",
                        "module": section["binary_label"],
                        "section": section["name"],
                        "rva_start": cursor,
                        "rva_end": start,
                    }
                )
            if start < cursor:
                issues.append(
                    {
                        "partition": "executable_ranges",
                        "kind": "overlap",
                        "module": section["binary_label"],
                        "section": section["name"],
                        "range": item["label"],
                        "rva_start": start,
                        "rva_end": min(cursor, end),
                    }
                )
            cursor = max(cursor, end)
        if cursor < section_end:
            issues.append(
                {
                    "partition": "executable_ranges",
                    "kind": "gap",
                    "module": section["binary_label"],
                    "section": section["name"],
                    "rva_start": cursor,
                    "rva_end": section_end,
                }
            )

    executable_ranges = conn.execute(
        """
        SELECT x.id, x.label, x.binary_id, x.rva_start, x.rva_end, b.label AS binary_label
        FROM executable_ranges x
        JOIN binaries b ON b.id = x.binary_id
        WHERE b.scope IN ('included', 'candidate')
        ORDER BY x.binary_id, x.rva_start, x.rva_end
        """
    ).fetchall()
    for executable_range in executable_ranges:
        cursor = int(executable_range["rva_start"])
        range_end = int(executable_range["rva_end"])
        byte_classes = conn.execute(
            """
            SELECT label, rva_start, rva_end, classification, source
            FROM executable_byte_classes
            WHERE binary_id = ?
              AND rva_start < ?
              AND rva_end > ?
            ORDER BY rva_start, rva_end
            """,
            (executable_range["binary_id"], range_end, executable_range["rva_start"]),
        ).fetchall()
        for item in byte_classes:
            start = max(int(item["rva_start"]), int(executable_range["rva_start"]))
            end = min(int(item["rva_end"]), range_end)
            if start > cursor:
                issues.append(
                    {
                        "partition": "executable_byte_classes",
                        "kind": "gap",
                        "module": executable_range["binary_label"],
                        "range": executable_range["label"],
                        "rva_start": cursor,
                        "rva_end": start,
                    }
                )
            if start < cursor:
                issues.append(
                    {
                        "partition": "executable_byte_classes",
                        "kind": "overlap",
                        "module": executable_range["binary_label"],
                        "range": executable_range["label"],
                        "byte_class": item["label"],
                        "rva_start": start,
                        "rva_end": min(cursor, end),
                    }
                )
            cursor = max(cursor, end)
        if cursor < range_end:
            issues.append(
                {
                    "partition": "executable_byte_classes",
                    "kind": "gap",
                    "module": executable_range["binary_label"],
                    "range": executable_range["label"],
                    "rva_start": cursor,
                    "rva_end": range_end,
                }
            )

    out_of_range = conn.execute(
        """
        SELECT c.label, c.rva_start, c.rva_end, b.label AS binary_label
        FROM executable_byte_classes c
        JOIN binaries b ON b.id = c.binary_id
        WHERE b.scope IN ('included', 'candidate')
          AND NOT EXISTS (
            SELECT 1
            FROM executable_ranges x
            WHERE x.binary_id = c.binary_id
              AND x.rva_start <= c.rva_start
              AND x.rva_end >= c.rva_end
          )
        ORDER BY b.label, c.rva_start, c.rva_end
        LIMIT 100
        """
    ).fetchall()
    for item in out_of_range:
        issues.append(
            {
                "partition": "executable_byte_classes",
                "kind": "outside-executable-range",
                "module": item["binary_label"],
                "byte_class": item["label"],
                "rva_start": item["rva_start"],
                "rva_end": item["rva_end"],
            }
        )
    return issues[:100]


def _static_cross_check_gate(conn: sqlite3.Connection) -> dict[str, Any]:
    binaries = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, label, path, scope
            FROM binaries
            WHERE scope IN ('included', 'candidate')
            ORDER BY scope, path
            """
        )
    ]
    latest_checks = [
        dict(row)
        for row in conn.execute(
            """
            SELECT s.id, s.label, s.binary_id, b.label AS module, b.path, s.tool, s.status,
                   s.checked_at, s.evidence_json
            FROM static_cross_checks s
            JOIN binaries b ON b.id = s.binary_id
            WHERE b.scope IN ('included', 'candidate')
              AND NOT EXISTS (
                SELECT 1
                FROM static_cross_checks newer
                WHERE newer.binary_id = s.binary_id
                  AND newer.tool = s.tool
                  AND (
                    newer.checked_at > s.checked_at
                    OR (newer.checked_at = s.checked_at AND newer.id > s.id)
                  )
              )
            ORDER BY b.scope, b.path, s.tool
            """
        )
    ]
    passed_by_binary: dict[int, set[str]] = {int(row["id"]): set() for row in binaries}
    for row in latest_checks:
        binary_id = int(row["binary_id"])
        if binary_id in passed_by_binary and str(row["status"]) == "pass":
            passed_by_binary[binary_id].add(str(row["tool"]))

    missing: list[dict[str, Any]] = []
    for binary in binaries:
        binary_id = int(binary["id"])
        passed = passed_by_binary[binary_id]
        if "llvm-readobj" not in passed:
            missing.append(
                {
                    "module": binary["label"],
                    "path": binary["path"],
                    "required_family": "llvm-readobj",
                }
            )
        if not (passed & {"rizin", "r2", "radare2"}):
            missing.append(
                {
                    "module": binary["label"],
                    "path": binary["path"],
                    "required_family": "rizin-or-radare2",
                }
            )

    failure_samples = [row for row in latest_checks if str(row["status"]) != "pass"]
    failure_samples.sort(key=lambda row: (str(row["checked_at"]), int(row["id"])), reverse=True)
    failure_samples = failure_samples[:20]
    for sample in failure_samples:
        evidence = _json_object(sample.get("evidence_json"), f"static_cross_check.{sample['label']}.evidence_json", [])
        sample["summary"] = evidence.get("summary", "") if isinstance(evidence, dict) else ""
        sample.pop("id", None)
        sample.pop("binary_id", None)
        del sample["evidence_json"]

    passed_binaries = sum(
        1
        for binary in binaries
        if "llvm-readobj" in passed_by_binary[int(binary["id"])]
        and bool(passed_by_binary[int(binary["id"])] & {"rizin", "r2", "radare2"})
    )
    total_checks = conn.execute("SELECT COUNT(*) AS count FROM static_cross_checks").fetchone()["count"]
    return {
        "status": "pass" if bool(binaries) and not missing else "open",
        "required_binaries": len(binaries),
        "passed_binaries": passed_binaries,
        "missing_required_checks": len(missing),
        "missing_required_check_samples": missing[:20],
        "static_cross_checks": total_checks,
        "latest_static_cross_checks": len(latest_checks),
        "failure_samples": failure_samples,
    }


def _interface_gate(conn: sqlite3.Connection) -> dict[str, Any]:
    endpoints = [
        dict(row)
        for row in conn.execute(
            """
            SELECT DISTINCT pe.id, pe.label, pe.dll, pe.symbol, pe.ordinal, pe.subsystem,
                   pe.mock_status, pe.test_status
            FROM platform_endpoints pe
            JOIN binary_platform_endpoints bpe ON bpe.endpoint_id = pe.id
            JOIN binaries b ON b.id = bpe.binary_id
            WHERE b.scope IN ('included', 'candidate')
            ORDER BY lower(pe.dll), COALESCE(pe.symbol, ''), COALESCE(pe.ordinal, -1)
            """
        )
    ]
    endpoint_ids = [int(row["id"]) for row in endpoints]
    complete_mock_statuses = {"complete"}
    incomplete_mock_endpoints = [
        _endpoint_summary(row) for row in endpoints if str(row["mock_status"]) not in complete_mock_statuses
    ]

    passed_cases: set[tuple[int, str]] = set()
    if endpoint_ids:
        placeholders = ",".join("?" for _ in endpoint_ids)
        for row in conn.execute(
            f"""
            SELECT endpoint_id, case_kind
            FROM interface_test_cases
            WHERE status = 'pass'
              AND endpoint_id IN ({placeholders})
            """,
            endpoint_ids,
        ):
            passed_cases.add((int(row["endpoint_id"]), str(row["case_kind"])))

    missing_cases: list[dict[str, Any]] = []
    for endpoint in endpoints:
        endpoint_id = int(endpoint["id"])
        for case_kind in REQUIRED_INTERFACE_CASES:
            if (endpoint_id, case_kind) not in passed_cases:
                item = _endpoint_summary(endpoint)
                item["case_kind"] = case_kind
                missing_cases.append(item)

    total_required_cases = len(endpoints) * len(REQUIRED_INTERFACE_CASES)
    passed_required_cases = total_required_cases - len(missing_cases)
    complete = bool(endpoints) and not incomplete_mock_endpoints and not missing_cases
    return {
        "status": "pass" if complete else "open",
        "observed_endpoints": len(endpoints),
        "complete_mock_endpoints": len(endpoints) - len(incomplete_mock_endpoints),
        "incomplete_mock_endpoints": len(incomplete_mock_endpoints),
        "required_test_cases": total_required_cases,
        "passed_required_test_cases": passed_required_cases,
        "missing_required_test_cases": len(missing_cases),
        "required_case_kinds": list(REQUIRED_INTERFACE_CASES),
        "incomplete_mock_samples": incomplete_mock_endpoints[:20],
        "missing_test_case_samples": missing_cases[:20],
    }


def _endpoint_summary(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    symbol = row["symbol"] if row["symbol"] is not None else f"#{row['ordinal']}"
    return {
        "label": row["label"],
        "endpoint": f"{row['dll']}!{symbol}",
        "subsystem": row["subsystem"],
        "mock_status": row["mock_status"],
        "test_status": row["test_status"],
    }


def _data_state_gate(conn: sqlite3.Connection, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    metadata = metadata or {}
    round_trip = set(
        target_lists_from_metadata(
            metadata,
            "data_state_round_trip_kinds_json",
            tuple(sorted({"map", "profile", "save", "packet", "config", "codec", "serializer"})),
        )
    )
    transition = set(
        target_lists_from_metadata(metadata, "data_state_transition_kinds_json", ("state_machine",))
    )
    structures = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, label, name, structure_kind, spec_status, fixture_status, description
            FROM data_structures
            ORDER BY structure_kind, name
            """
        )
    ]
    incomplete_specs = [
        _data_structure_summary(row) for row in structures if str(row["spec_status"]) != "complete"
    ]
    incomplete_fixtures = [
        _data_structure_summary(row) for row in structures if str(row["fixture_status"]) != "complete"
    ]

    structure_ids = [int(row["id"]) for row in structures]
    passed_cases: set[tuple[int, str]] = set()
    if structure_ids:
        placeholders = ",".join("?" for _ in structure_ids)
        for row in conn.execute(
            f"""
            SELECT data_structure_id, case_kind
            FROM data_state_test_cases
            WHERE status = 'pass'
              AND data_structure_id IN ({placeholders})
            """,
            structure_ids,
        ):
            passed_cases.add((int(row["data_structure_id"]), str(row["case_kind"])))

    missing_cases: list[dict[str, Any]] = []
    total_required_cases = 0
    for structure in structures:
        structure_id = int(structure["id"])
        required_cases = required_data_state_cases(
            str(structure["structure_kind"]),
            round_trip_kinds=round_trip,
            transition_kinds=transition,
        )
        total_required_cases += len(required_cases)
        for case_kind in required_cases:
            if (structure_id, case_kind) not in passed_cases:
                item = _data_structure_summary(structure)
                item["case_kind"] = case_kind
                missing_cases.append(item)

    passed_required_cases = total_required_cases - len(missing_cases)
    complete = bool(structures) and not incomplete_specs and not incomplete_fixtures and not missing_cases
    return {
        "status": "pass" if complete else "open",
        "known_data_structures": len(structures),
        "complete_specs": len(structures) - len(incomplete_specs),
        "complete_fixtures": len(structures) - len(incomplete_fixtures),
        "incomplete_specs": len(incomplete_specs),
        "incomplete_fixtures": len(incomplete_fixtures),
        "required_test_cases": total_required_cases,
        "passed_required_test_cases": passed_required_cases,
        "missing_required_test_cases": len(missing_cases),
        "incomplete_spec_samples": incomplete_specs[:20],
        "incomplete_fixture_samples": incomplete_fixtures[:20],
        "missing_test_case_samples": missing_cases[:20],
    }


def _data_structure_summary(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {
        "label": row["label"],
        "name": row["name"],
        "structure_kind": row["structure_kind"],
        "spec_status": row["spec_status"],
        "fixture_status": row["fixture_status"],
    }


def _oracle_gate(conn: sqlite3.Connection, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    metadata = metadata or {}
    required_process_suites = target_lists_from_metadata(
        metadata,
        "required_oracle_process_suites_json",
        REQUIRED_ORACLE_PROCESS_SUITES,
    )
    required_private_suites = target_lists_from_metadata(
        metadata,
        "required_oracle_private_suites_json",
        REQUIRED_ORACLE_PRIVATE_SUITES,
    )
    passed_suites: set[tuple[str, str]] = set()
    incomplete_passing: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT label, suite_id, test_id, case_kind, evidence, command, fixture_path, trace_log
        FROM oracle_test_cases
        WHERE status = 'pass'
        ORDER BY suite_id, case_kind, test_id
        """
    ):
        if _oracle_pass_is_auditable(row):
            passed_suites.add((str(row["suite_id"]), str(row["case_kind"])))
        else:
            incomplete_passing.append(dict(row))

    missing_process = [
        suite_id
        for suite_id in required_process_suites
        if (suite_id, "black_box_process") not in passed_suites
    ]
    missing_private = [
        suite_id
        for suite_id in required_private_suites
        if (suite_id, "private_harness") not in passed_suites
    ]
    total_cases = conn.execute("SELECT COUNT(*) AS count FROM oracle_test_cases").fetchone()["count"]
    passing_cases = conn.execute(
        "SELECT COUNT(*) AS count FROM oracle_test_cases WHERE status = 'pass'"
    ).fetchone()["count"]
    failed_or_planned = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM oracle_test_cases
        WHERE status <> 'pass'
        """
    ).fetchone()["count"]
    samples = [
        dict(row)
        for row in conn.execute(
            """
            SELECT suite_id, test_id, case_kind, status, evidence
            FROM oracle_test_cases
            WHERE status <> 'pass'
            ORDER BY suite_id, case_kind, test_id
            LIMIT 20
            """
        )
    ]
    complete = not missing_process and not missing_private
    return {
        "status": "pass" if complete else "open",
        "required_black_box_suites": len(required_process_suites),
        "passed_black_box_suites": len(required_process_suites) - len(missing_process),
        "missing_black_box_suites": missing_process,
        "required_private_harness_suites": len(required_private_suites),
        "passed_private_harness_suites": len(required_private_suites) - len(missing_private),
        "missing_private_harness_suites": missing_private,
        "oracle_test_cases": total_cases,
        "passing_cases": passing_cases,
        "auditable_passing_cases": passing_cases - len(incomplete_passing),
        "incomplete_passing_cases": len(incomplete_passing),
        "incomplete_passing_samples": incomplete_passing[:20],
        "failed_or_planned_cases": failed_or_planned,
        "failed_or_planned_samples": samples,
    }


def _oracle_pass_is_auditable(row: sqlite3.Row) -> bool:
    evidence = bool(str(row["evidence"] or "").strip())
    command = bool(str(row["command"] or "").strip())
    artifact = bool(str(row["fixture_path"] or "").strip() or str(row["trace_log"] or "").strip())
    case_kind = str(row["case_kind"])
    if case_kind == "black_box_process":
        return evidence and command and artifact
    if case_kind == "private_harness":
        return evidence and (command or artifact)
    return False


def _mutation_gate(conn: sqlite3.Connection, metadata: dict[str, str] | None = None) -> dict[str, Any]:
    metadata = metadata or {}
    required_mutation_kinds = target_lists_from_metadata(
        metadata,
        "required_mutation_kinds_json",
        REQUIRED_MUTATION_KINDS,
    )
    killed_kinds = {
        str(row["mutation_kind"])
        for row in conn.execute(
            """
            SELECT DISTINCT mutation_kind
            FROM mutation_test_cases
            WHERE status = 'killed'
            """
        )
    }
    missing_kinds = [mutation_kind for mutation_kind in required_mutation_kinds if mutation_kind not in killed_kinds]
    total_cases = conn.execute("SELECT COUNT(*) AS count FROM mutation_test_cases").fetchone()["count"]
    killed_cases = conn.execute(
        "SELECT COUNT(*) AS count FROM mutation_test_cases WHERE status = 'killed'"
    ).fetchone()["count"]
    unresolved_cases = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM mutation_test_cases
        WHERE status <> 'killed'
        """
    ).fetchone()["count"]
    samples = [
        dict(row)
        for row in conn.execute(
            """
            SELECT mutation_kind, target_label, test_id, status, evidence
            FROM mutation_test_cases
            WHERE status <> 'killed'
            ORDER BY mutation_kind, COALESCE(target_label, ''), test_id
            LIMIT 20
            """
        )
    ]
    return {
        "status": "pass" if not missing_kinds else "open",
        "required_mutation_kinds": list(required_mutation_kinds),
        "covered_mutation_kinds": sorted(killed_kinds & set(required_mutation_kinds)),
        "missing_mutation_kinds": missing_kinds,
        "mutation_test_cases": total_cases,
        "killed_cases": killed_cases,
        "unresolved_cases": unresolved_cases,
        "unresolved_samples": samples,
    }


def _private_artifact_gate(conn: sqlite3.Connection) -> dict[str, Any]:
    latest_bundle = conn.execute(
        """
        SELECT id, label, artifact_set_id, root_path, format_version, created_at, summary_json
        FROM private_artifact_bundles
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """
    ).fetchone()
    bundle_count = _count(conn, "private_artifact_bundles")
    packet_count = _count(conn, "private_artifacts")
    required_modules = [
        dict(row)
        for row in conn.execute(
            """
            SELECT id, label, path, sha256
            FROM binaries
            WHERE scope IN ('included', 'candidate')
            ORDER BY scope, path
            """
        )
    ]
    required_functions = [
        dict(row)
        for row in conn.execute(
            """
            SELECT f.id, f.label, f.name, b.path AS module_path
            FROM functions f
            JOIN binaries b ON b.id = f.binary_id
            WHERE b.scope IN ('included', 'candidate')
            ORDER BY b.scope, b.path, f.rva, f.name
            """
        )
    ]
    required_blocks = [
        dict(row)
        for row in conn.execute(
            """
            SELECT bb.id, bb.label, bb.rva_start, bb.rva_end, b.path AS module_path
            FROM basic_blocks bb
            JOIN binaries b ON b.id = bb.binary_id
            WHERE b.scope IN ('included', 'candidate')
            ORDER BY b.scope, b.path, bb.rva_start, bb.rva_end
            """
        )
    ]
    required_review_packets = _required_review_packet_rows(conn)
    if latest_bundle is None:
        return {
            "status": "open",
            "bundles": bundle_count,
            "private_artifacts": packet_count,
            "latest_bundle": None,
            "required_modules": len(required_modules),
            "module_packets": 0,
            "missing_module_packets": len(required_modules),
            "missing_module_samples": required_modules[:20],
            "required_functions": len(required_functions),
            "routine_packets": 0,
            "routine_dirty_contract_drafts": 0,
            "required_basic_blocks": len(required_blocks),
            "block_packets": 0,
            "block_disassembly_packets": 0,
            "block_context_packets": 0,
            "block_clean_templates": 0,
            "required_review_packets": len(required_review_packets),
            "dirty_spec_suites": 0,
            "dirty_test_suites": 0,
            "review_dirty_packets": 0,
            "review_clean_templates": 0,
            "missing_routine_packets": len(required_functions),
            "missing_routine_samples": required_functions[:20],
            "missing_block_packets": len(required_blocks),
            "missing_block_disassembly_packets": len(required_blocks),
            "missing_block_context_packets": len(required_blocks),
            "missing_block_clean_templates": len(required_blocks),
            "missing_block_samples": required_blocks[:20],
            "missing_review_packet_samples": required_review_packets[:20],
            "missing_review_template_samples": required_review_packets[:20],
        }

    bundle_id = int(latest_bundle["id"])
    module_packet_ids = {
        int(row["binary_id"])
        for row in conn.execute(
            """
            SELECT DISTINCT binary_id
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = 'module_manifest'
              AND binary_id IS NOT NULL
            """,
            (bundle_id,),
        )
    }
    routine_packet_labels = {
        str(row["entity_label"])
        for row in conn.execute(
            """
            SELECT DISTINCT entity_label
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = 'routine_manifest'
              AND entity_type = 'function'
              AND entity_label IS NOT NULL
            """,
            (bundle_id,),
        )
    }
    routine_dirty_contract_labels = {
        str(row["entity_label"])
        for row in conn.execute(
            """
            SELECT DISTINCT entity_label
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = 'routine_dirty_contract_draft'
              AND entity_type = 'function'
              AND entity_label IS NOT NULL
            """,
            (bundle_id,),
        )
    }
    module_disassembly_ids = {
        int(row["binary_id"])
        for row in conn.execute(
            """
            SELECT DISTINCT binary_id
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = 'module_disassembly'
              AND binary_id IS NOT NULL
            """,
            (bundle_id,),
        )
    }
    block_packet_labels = _private_artifact_entity_labels(conn, bundle_id, "block_manifest", "basic_block")
    block_disassembly_labels = _private_artifact_entity_labels(conn, bundle_id, "block_disassembly", "basic_block")
    block_context_labels = _private_artifact_entity_labels(conn, bundle_id, "block_context", "basic_block")
    block_clean_template_labels = _private_artifact_entity_labels(
        conn,
        bundle_id,
        "block_clean_template",
        "basic_block_contract",
    )
    review_dirty_packet_labels = {
        str(row["entity_label"])
        for row in conn.execute(
            """
            SELECT DISTINCT entity_label
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = 'review_dirty_packet'
              AND entity_label IS NOT NULL
            """,
            (bundle_id,),
        )
    }
    review_clean_template_labels = {
        str(row["entity_label"])
        for row in conn.execute(
            """
            SELECT DISTINCT entity_label
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = 'review_clean_template'
              AND entity_label IS NOT NULL
            """,
            (bundle_id,),
        )
    }
    dirty_spec_suites = _private_artifact_kind_count(conn, bundle_id, "dirty_spec_suite")
    dirty_test_suites = _private_artifact_kind_count(conn, bundle_id, "dirty_test_suite")
    missing_modules = [row for row in required_modules if int(row["id"]) not in module_packet_ids]
    missing_module_disassembly = [row for row in required_modules if int(row["id"]) not in module_disassembly_ids]
    missing_routines = [row for row in required_functions if str(row["label"]) not in routine_packet_labels]
    missing_dirty_drafts = [row for row in required_functions if str(row["label"]) not in routine_dirty_contract_labels]
    missing_blocks = [row for row in required_blocks if str(row["label"]) not in block_packet_labels]
    missing_block_disassembly = [row for row in required_blocks if str(row["label"]) not in block_disassembly_labels]
    missing_block_context = [row for row in required_blocks if str(row["label"]) not in block_context_labels]
    missing_block_templates = [row for row in required_blocks if str(row["label"]) not in block_clean_template_labels]
    missing_review_packets = [
        row for row in required_review_packets if str(row["label"]) not in review_dirty_packet_labels
    ]
    missing_review_templates = [
        row for row in required_review_packets if str(row["label"]) not in review_clean_template_labels
    ]
    complete = (
        bool(required_modules)
        and bool(required_functions)
        and not missing_modules
        and not missing_module_disassembly
        and not missing_routines
        and not missing_dirty_drafts
        and not missing_blocks
        and not missing_block_disassembly
        and not missing_block_context
        and not missing_block_templates
        and not missing_review_packets
        and not missing_review_templates
        and dirty_spec_suites > 0
        and dirty_test_suites > 0
    )
    return {
        "status": "pass" if complete else "open",
        "bundles": bundle_count,
        "private_artifacts": packet_count,
        "latest_bundle": {
            "label": latest_bundle["label"],
            "artifact_set_id": latest_bundle["artifact_set_id"],
            "root_path": latest_bundle["root_path"],
            "format_version": latest_bundle["format_version"],
            "created_at": latest_bundle["created_at"],
            "summary": _json_any(latest_bundle["summary_json"], {}),
        },
        "required_modules": len(required_modules),
        "module_packets": len(module_packet_ids),
        "module_disassembly_packets": len(module_disassembly_ids),
        "missing_module_packets": len(missing_modules),
        "missing_module_disassembly_packets": len(missing_module_disassembly),
        "missing_module_samples": missing_modules[:20],
        "missing_module_disassembly_samples": missing_module_disassembly[:20],
        "required_functions": len(required_functions),
        "routine_packets": len(routine_packet_labels),
        "routine_dirty_contract_drafts": len(routine_dirty_contract_labels),
        "required_basic_blocks": len(required_blocks),
        "block_packets": len(block_packet_labels),
        "block_disassembly_packets": len(block_disassembly_labels),
        "block_context_packets": len(block_context_labels),
        "block_clean_templates": len(block_clean_template_labels),
        "required_review_packets": len(required_review_packets),
        "dirty_spec_suites": dirty_spec_suites,
        "dirty_test_suites": dirty_test_suites,
        "review_dirty_packets": len(review_dirty_packet_labels),
        "review_clean_templates": len(review_clean_template_labels),
        "missing_routine_packets": len(missing_routines),
        "missing_routine_dirty_contract_drafts": len(missing_dirty_drafts),
        "missing_block_packets": len(missing_blocks),
        "missing_block_disassembly_packets": len(missing_block_disassembly),
        "missing_block_context_packets": len(missing_block_context),
        "missing_block_clean_templates": len(missing_block_templates),
        "missing_review_packets": len(missing_review_packets),
        "missing_review_templates": len(missing_review_templates),
        "missing_routine_samples": missing_routines[:20],
        "missing_routine_dirty_contract_samples": missing_dirty_drafts[:20],
        "missing_block_samples": missing_blocks[:20],
        "missing_block_disassembly_samples": missing_block_disassembly[:20],
        "missing_block_context_samples": missing_block_context[:20],
        "missing_block_clean_template_samples": missing_block_templates[:20],
        "missing_review_packet_samples": missing_review_packets[:20],
        "missing_review_template_samples": missing_review_templates[:20],
    }


def _dirty_reimplementation_gate(
    conn: sqlite3.Connection,
    private_artifact_gate: dict[str, Any],
) -> dict[str, Any]:
    latest = private_artifact_gate.get("latest_bundle") if isinstance(private_artifact_gate.get("latest_bundle"), dict) else None
    if not latest:
        return {
            "status": "open",
            "reason": "no private dirty corpus bundle has been exported",
            "missing_files": ["manifest.json"],
            "missing_artifact_kinds": [],
            "unlinked_task_evidence": 0,
        }
    root = Path(str(latest.get("root_path") or ""))
    required_files = [
        "reimplementation-plan.json",
        "reimplementation-plan.md",
        "cli-index.json",
        "review-html/index.html",
        "review-html/search-index.json",
    ]
    missing_files = [rel for rel in required_files if not (root / rel).exists()]
    bundle_row = conn.execute(
        """
        SELECT id
        FROM private_artifact_bundles
        WHERE root_path = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (str(root),),
    ).fetchone()
    bundle_id = int(bundle_row["id"]) if bundle_row else None
    required_kinds = [
        "routine_semantics",
        "routine_decompiler_status",
        "routine_pcode",
        "block_instruction_metadata",
        "block_pcode",
        "block_data_flow",
        "block_xrefs",
        "block_semantic_summary",
        "dirty_corpus_cli_index",
        "dirty_corpus_review_html",
        "reimplementation_plan_json",
    ]
    missing_kinds: list[str] = []
    kind_counts: dict[str, int] = {}
    if bundle_id is None:
        missing_kinds = required_kinds[:]
    else:
        for kind in required_kinds:
            count = _private_artifact_kind_count(conn, bundle_id, kind)
            kind_counts[kind] = count
            if count == 0:
                missing_kinds.append(kind)
    unlinked_task_evidence = 0
    task_count = 0
    plan_errors: list[str] = []
    try:
        plan = json.loads((root / "reimplementation-plan.json").read_text(encoding="utf-8"))
        tasks = plan.get("tasks") if isinstance(plan.get("tasks"), list) else []
        task_count = len(tasks)
        for task in tasks:
            links = task.get("private_evidence_links") if isinstance(task, dict) else None
            if not isinstance(links, list) or not links:
                unlinked_task_evidence += 1
    except FileNotFoundError:
        plan_errors.append("reimplementation-plan.json is missing")
    except json.JSONDecodeError as exc:
        plan_errors.append(f"reimplementation-plan.json is invalid JSON: {exc}")

    ready = (
        private_artifact_gate.get("status") == "pass"
        and not missing_files
        and not missing_kinds
        and not unlinked_task_evidence
        and not plan_errors
        and task_count > 0
    )
    return {
        "status": "pass" if ready else "open",
        "latest_bundle": latest,
        "task_count": task_count,
        "missing_files": missing_files,
        "artifact_kind_counts": kind_counts,
        "missing_artifact_kinds": missing_kinds,
        "unlinked_task_evidence": unlinked_task_evidence,
        "plan_errors": plan_errors,
        "private_artifact_gate_status": private_artifact_gate.get("status"),
    }


def _private_artifact_kind_count(conn: sqlite3.Connection, bundle_id: int, artifact_kind: str) -> int:
    return int(
        conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = ?
            """,
            (bundle_id, artifact_kind),
        ).fetchone()["count"]
        or 0
    )


def _private_artifact_entity_labels(
    conn: sqlite3.Connection,
    bundle_id: int,
    artifact_kind: str,
    entity_type: str,
) -> set[str]:
    return {
        str(row["entity_label"])
        for row in conn.execute(
            """
            SELECT DISTINCT entity_label
            FROM private_artifacts
            WHERE bundle_id = ?
              AND artifact_kind = ?
              AND entity_type = ?
              AND entity_label IS NOT NULL
            """,
            (bundle_id, artifact_kind, entity_type),
        )
    }


def _required_review_packet_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    query = """
        SELECT label, 'behavior_contract' AS entity_type, contract_id AS test_surface
        FROM behavior_contracts
        UNION ALL
        SELECT label, 'behavior_observation' AS entity_type, test_id AS test_surface
        FROM behavior_observations
        UNION ALL
        SELECT label, 'process_behavior_observation' AS entity_type, test_id AS test_surface
        FROM process_behavior_observations
        UNION ALL
        SELECT label, 'internal_routine_contract' AS entity_type, public_name AS test_surface
        FROM internal_routine_contracts
        UNION ALL
        SELECT label, 'oracle_test_case' AS entity_type, suite_id || ':' || case_kind || ':' || test_id AS test_surface
        FROM oracle_test_cases
        UNION ALL
        SELECT label, 'interface_test_case' AS entity_type, case_kind || ':' || test_id AS test_surface
        FROM interface_test_cases
        UNION ALL
        SELECT label, 'data_state_test_case' AS entity_type, case_kind || ':' || test_id AS test_surface
        FROM data_state_test_cases
        UNION ALL
        SELECT label, 'mutation_test_case' AS entity_type, mutation_kind || ':' || test_id AS test_surface
        FROM mutation_test_cases
        UNION ALL
        SELECT label, 'internal_harness' AS entity_type, harness_id AS test_surface
        FROM internal_harnesses
        UNION ALL
        SELECT label, 'internal_harness_run' AS entity_type, test_id AS test_surface
        FROM internal_harness_runs
        ORDER BY entity_type, test_surface, label
    """
    return [dict(row) for row in conn.execute(query)]


def _publication_clean_gate(conn: sqlite3.Connection) -> dict[str, Any]:
    public_contracts = [
        dict(row)
        for row in conn.execute(
            """
            SELECT irc.label, irc.public_name, irc.taint_level, irc.review_status, l.private
            FROM internal_routine_contracts irc
            JOIN labels l ON l.label = irc.label
            WHERE irc.taint_level <> 'private_only'
              AND irc.review_status <> 'rejected_for_publication'
            ORDER BY irc.public_name, irc.label
            """
        )
    ]
    unreviewed_public = [row for row in public_contracts if str(row["review_status"]) != "reviewed"]
    private_public_labels = [row for row in public_contracts if int(row["private"] or 0) != 0]
    reviewed_public = [
        row
        for row in public_contracts
        if str(row["review_status"]) == "reviewed" and int(row["private"] or 0) == 0
    ]
    private_only_contracts = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM internal_routine_contracts
        WHERE taint_level = 'private_only'
           OR review_status = 'rejected_for_publication'
        """
    ).fetchone()["count"]
    complete = not unreviewed_public and not private_public_labels
    return {
        "status": "pass" if complete else "open",
        "public_contract_candidates": len(public_contracts),
        "reviewed_public_contracts": len(reviewed_public),
        "private_only_or_rejected_contracts": int(private_only_contracts or 0),
        "unreviewed_public_candidates": len(unreviewed_public),
        "private_public_labels": len(private_public_labels),
        "unreviewed_public_samples": unreviewed_public[:20],
        "private_public_label_samples": private_public_labels[:20],
    }


REQUIRED_REPRODUCIBLE_METADATA = (
    "catalog_version",
    "created_at",
    "install_root",
    "tool_versions",
    "nix_haloce_reference_package",
    "nix_haloce_source_info",
)

REQUIRED_GENERIC_REPRODUCIBLE_METADATA = (
    "catalog_version",
    "created_at",
    "install_root",
    "tool_versions",
    "target_project_id",
    "target_config_json",
)

REQUIRED_TOOL_VERSION_KEYS = (
    "wincr",
    "haloce_catalog",
    "python",
    "llvm-objdump",
    "rizin",
    "radare2",
    "drrun",
    "wincr-trace-run",
    "halo-trace-run",
    "wine",
    "ghidra_analyzeHeadless",
    "frida",
    "sqlite3",
)


def _reproducible_gate(conn: sqlite3.Connection) -> dict[str, Any]:
    metadata = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM metadata ORDER BY key")}
    is_target_catalog = bool(str(metadata.get("target_project_id", "")).strip())
    required_metadata = (
        REQUIRED_GENERIC_REPRODUCIBLE_METADATA if is_target_catalog else REQUIRED_REPRODUCIBLE_METADATA
    )
    missing_metadata = [key for key in required_metadata if not str(metadata.get(key, "")).strip()]

    metadata_json_issues: list[str] = []
    tool_versions = _json_object(metadata.get("tool_versions"), "metadata.tool_versions", metadata_json_issues)
    source_key = "source_info" if is_target_catalog else "nix_haloce_source_info"
    if source_key in metadata:
        source_info = _json_object(metadata.get(source_key), f"metadata.{source_key}", metadata_json_issues)
        if source_info == {}:
            metadata_json_issues.append(f"metadata.{source_key} is empty")

    missing_tool_versions = [
        key
        for key in REQUIRED_TOOL_VERSION_KEYS
        if not _usable_version_value(tool_versions.get(key) if tool_versions is not None else None)
    ]

    binary_rows = conn.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN sha256 IS NULL OR sha256 = '' THEN 1 ELSE 0 END) AS missing_hashes
        FROM binaries
        """
    ).fetchone()
    binary_count = int(binary_rows["total"] or 0)
    missing_binary_hashes = int(binary_rows["missing_hashes"] or 0)

    test_runs = [
        dict(row)
        for row in conn.execute(
            """
            SELECT label, test_id, suite, tool_versions_json, provenance_json
            FROM test_runs
            ORDER BY started_at, id
            """
        )
    ]
    test_run_issues: list[dict[str, str]] = []
    for row in test_runs:
        row_issues: list[str] = []
        row_tools = _json_object(row.get("tool_versions_json"), f"test_run.{row['label']}.tool_versions_json", row_issues)
        row_provenance = _json_object(row.get("provenance_json"), f"test_run.{row['label']}.provenance_json", row_issues)
        if row_tools is not None:
            missing = [
                key
                for key in ("wincr" if "wincr" in row_tools else "haloce_catalog", "python")
                if not _usable_version_value(row_tools.get(key))
            ]
            if missing:
                row_issues.append(f"missing test-run tool versions: {', '.join(missing)}")
        if row_provenance == {}:
            row_issues.append("empty provenance_json")
        for issue in row_issues:
            test_run_issues.append(
                {
                    "label": str(row["label"]),
                    "test_id": str(row["test_id"]),
                    "suite": str(row["suite"]),
                    "issue": issue,
                }
            )

    complete = (
        not missing_metadata
        and not metadata_json_issues
        and not missing_tool_versions
        and binary_count > 0
        and missing_binary_hashes == 0
        and len(test_runs) > 0
        and not test_run_issues
    )
    return {
        "status": "pass" if complete else "open",
        "required_metadata": list(required_metadata),
        "missing_metadata": missing_metadata,
        "metadata_json_issues": metadata_json_issues,
        "required_tool_versions": list(REQUIRED_TOOL_VERSION_KEYS),
        "missing_tool_versions": missing_tool_versions,
        "binary_hashes": binary_count,
        "missing_binary_hashes": missing_binary_hashes,
        "test_runs": len(test_runs),
        "missing_test_runs": len(test_runs) == 0,
        "test_run_issues": test_run_issues[:20],
    }


def _json_object(value: object, name: str, issues: list[str]) -> dict[str, Any] | None:
    if value is None or str(value).strip() == "":
        issues.append(f"{name} is missing")
        return None
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError as exc:
        issues.append(f"{name} is not valid JSON: {exc.msg}")
        return None
    if not isinstance(parsed, dict):
        issues.append(f"{name} is not a JSON object")
        return None
    return parsed


def _json_any(value: object, default: Any) -> Any:
    if value is None or str(value).strip() == "":
        return default
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return default


def _int_from_mapping(value: object, key: str) -> int:
    if not isinstance(value, dict):
        return 0
    try:
        return int(value.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _sanitize_public_evidence(rows: list[dict[str, Any]]) -> None:
    for row in rows:
        if "evidence" in row:
            row["evidence"] = public_text(row.get("evidence"))


def _public_direct_launch(provenance: Any) -> dict[str, Any]:
    if not isinstance(provenance, dict):
        return {}
    direct = provenance.get("direct_launch")
    if not isinstance(direct, dict):
        return {}
    return {
        "ok": bool(direct.get("ok")),
        "returncode": direct.get("returncode"),
        "timed_out": bool(direct.get("timed_out")),
    }


def _usable_version_value(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return bool(normalized) and normalized != "not found"
