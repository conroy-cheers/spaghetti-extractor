from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .catalog import build_catalog, resolve_install_root
from .coverage import doctor_drcov, ingest_drcov, run_drcov
from .db import connect, initialize
from .ghidra import import_ghidra_json
from .reports import generate_reports
from .util import utc_now


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="haloce-catalog")
    subcommands = parser.add_subparsers(dest="command", required=True)

    build = subcommands.add_parser("build", help="build SQLite catalog and generated reports")
    build.add_argument("--install-root", help="Halo CE install root, usually nix-haloce result/basePackage")
    build.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    build.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    build.add_argument("--static-depth", choices=["none", "included", "candidate", "all"], default="none")
    build.add_argument(
        "--max-disassembly-bytes",
        type=int,
        default=6 * 1024 * 1024,
        help="per-binary Capstone byte cap for optional block discovery; 0 means unlimited",
    )
    build.set_defaults(func=_cmd_build)

    report = subcommands.add_parser("report", help="regenerate JSON/Markdown reports from a catalog database")
    report.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    report.add_argument("--out-dir", type=Path, default=Path("build/reports"))
    report.set_defaults(func=_cmd_report)

    ingest = subcommands.add_parser("ingest-drcov", help="ingest a DynamoRIO drcov log")
    ingest.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    ingest.add_argument("--log", type=Path, required=True)
    ingest.add_argument("--test-id", required=True)
    ingest.add_argument("--suite", default="drcov")
    ingest.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    ingest.set_defaults(func=_cmd_ingest_drcov)

    run = subcommands.add_parser("run-drcov", help="run an application under DynamoRIO drcov")
    run.add_argument("--log-dir", type=Path, default=Path("build/drcov"))
    run.add_argument("--timeout-seconds", type=int)
    run.add_argument("app", nargs=argparse.REMAINDER)
    run.set_defaults(func=_cmd_run_drcov)

    doctor = subcommands.add_parser("doctor-drcov", help="smoke-test the local drrun/drcov installation")
    doctor.set_defaults(func=_cmd_doctor_drcov)

    ghidra = subcommands.add_parser("import-ghidra", help="import metadata JSON exported by tools/ghidra")
    ghidra.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    ghidra.add_argument("--json", type=Path, required=True)
    ghidra.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    ghidra.set_defaults(func=_cmd_import_ghidra)

    waiver = subcommands.add_parser("add-waiver", help="add an auditable coverage/catalog waiver")
    waiver.add_argument("--db", type=Path, default=Path("build/catalog/catalog.db"))
    waiver.add_argument("--binary-sha256", required=True)
    waiver.add_argument("--rva-start", required=True, type=_parse_int)
    waiver.add_argument("--rva-end", required=True, type=_parse_int)
    waiver.add_argument("--category", required=True)
    waiver.add_argument("--reason", required=True)
    waiver.add_argument("--evidence", required=True)
    waiver.add_argument("--reviewer", required=True)
    waiver.add_argument("--revalidation-trigger", required=True)
    waiver.add_argument("--report-dir", type=Path, default=Path("build/reports"))
    waiver.set_defaults(func=_cmd_add_waiver)

    args = parser.parse_args(argv)
    return int(args.func(args))


def _cmd_build(args: Any) -> int:
    root = resolve_install_root(args.install_root)
    result = build_catalog(
        root,
        args.db,
        static_depth=args.static_depth,
        max_disassembly_bytes=args.max_disassembly_bytes,
    )
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"catalog": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0 if not result["errors"] else 1


def _cmd_report(args: Any) -> int:
    reports = generate_reports(args.db, args.out_dir)
    _print_json({key: str(value) for key, value in reports.items()})
    return 0


def _cmd_ingest_drcov(args: Any) -> int:
    result = ingest_drcov(args.db, args.log, args.test_id, suite=args.suite)
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"coverage": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_run_drcov(args: Any) -> int:
    app = args.app
    if app and app[0] == "--":
        app = app[1:]
    if not app:
        raise SystemExit("run-drcov requires an application after --")
    proc = run_drcov(args.log_dir, app, timeout_seconds=args.timeout_seconds)
    _print_json(
        {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "log_dir": str(args.log_dir),
        }
    )
    return proc.returncode


def _cmd_doctor_drcov(args: Any) -> int:
    result = doctor_drcov()
    _print_json(result)
    return 0 if result["ok"] else 1


def _cmd_import_ghidra(args: Any) -> int:
    result = import_ghidra_json(args.db, args.json)
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"ghidra": result, "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _cmd_add_waiver(args: Any) -> int:
    conn = connect(args.db)
    initialize(conn)
    binary = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (args.binary_sha256,)).fetchone()
    if binary is None:
        raise SystemExit(f"unknown binary sha256: {args.binary_sha256}")
    with conn:
        conn.execute(
            """
            INSERT INTO waivers(
              binary_id, rva_start, rva_end, category, reason, evidence,
              reviewer, revalidation_trigger, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(binary["id"]),
                args.rva_start,
                args.rva_end,
                args.category,
                args.reason,
                args.evidence,
                args.reviewer,
                args.revalidation_trigger,
                utc_now(),
            ),
        )
    reports = generate_reports(args.db, args.report_dir)
    _print_json({"waiver": "added", "reports": {key: str(value) for key, value in reports.items()}})
    return 0


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _parse_int(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)
