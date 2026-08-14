"""Single command-line interface for test planning and developer tooling."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Mapping

from .diagnostics import TestkitError
from .discovery import build_impact_index
from .doctor import run_doctor
from .fixtures import FixtureCatalog
from .io import load_index, load_plan, write_manifest
from .model import INDEX_FORMAT, PLAN_FORMAT, canonical_json
from .planning import MODES, build_suite_plan, changed_paths_from_git
from .rebuild import explain_index_rebuild, explain_plan_rebuild
from .scaffold import apply_scaffold_plan, plan_fixture_scaffold, plan_phase_scaffold, plan_test_scaffold
from .static_manifest import refresh_repository_metadata


def _repository(value: str) -> Path:
    return Path(value).resolve()


def _print_human_diagnostics(rows: list[Mapping[str, object]]) -> None:
    for row in rows:
        location = f"{row.get('location')}: " if row.get("location") else ""
        print(f"{location}{row['severity']}[{row['code']}]: {row['message']}")
        if row.get("remediation"):
            print(f"  fix: {row['remediation']}")
        if row.get("example"):
            print(f"  example: {row['example']}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-dev",
        description="Plan and diagnose cached Spaghetti Extractor tests.",
    )
    parser.add_argument("--repository", default=".", help="repository root (default: current directory)")
    subcommands = parser.add_subparsers(dest="command", required=True)

    index = subcommands.add_parser("index", help="generate the import-based impact index")
    index.add_argument("--out", type=Path, default=Path("-"))
    index.add_argument("--shards", type=int, default=32)

    refresh = subcommands.add_parser(
        "refresh", help="refresh both checked repository metadata manifests"
    )
    refresh.add_argument(
        "--check", action="store_true", help="fail if either checked manifest is stale"
    )

    plan = subcommands.add_parser("plan", help="create an execution plan")
    plan.add_argument("mode", choices=sorted(MODES))
    plan.add_argument("--index", type=Path)
    plan.add_argument("--out", type=Path, default=Path("-"))
    plan.add_argument("--changed", action="append", default=[])
    plan.add_argument("--base", default="HEAD")
    plan.add_argument("--shards", type=int, default=32)

    fixtures = subcommands.add_parser("fixtures", help="list or inspect shared fixtures")
    fixtures.add_argument("fixture_id", nargs="?")
    fixtures.add_argument("--json", action="store_true")

    doctor = subcommands.add_parser("doctor", help="check the local test environment")
    doctor.add_argument("--json", action="store_true")

    explain = subcommands.add_parser("explain-rebuild", help="compare two indexes or plans")
    explain.add_argument("--before", type=Path, required=True)
    explain.add_argument("--after", type=Path, required=True)
    explain.add_argument("--artifact")

    scaffold = subcommands.add_parser("scaffold", help="create convention-correct files")
    scaffold.add_argument("kind", choices=("test", "phase", "fixture"))
    scaffold.add_argument("first", help="subsystem, phase kind, or fixture kind")
    scaffold.add_argument("second", help="new item name")
    scaffold.add_argument("--tier", default="unit")
    scaffold.add_argument("--capability")
    scaffold.add_argument("--json", action="store_true")
    scaffold.add_argument("--dry-run", action="store_true", help="render files without creating them")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    repository = _repository(args.repository)
    try:
        if args.command == "index":
            index = build_impact_index(repository, shard_count=args.shards)
            write_manifest(args.out, index)
            return 0
        if args.command == "refresh":
            changed = refresh_repository_metadata(repository, check=args.check)
            if args.check or not changed:
                print("current repository metadata")
            else:
                for path in changed:
                    print(f"updated {path.relative_to(repository)}")
            return 0
        if args.command == "plan":
            index = load_index(args.index) if args.index else build_impact_index(repository, shard_count=args.shards)
            changed = tuple(args.changed)
            if args.mode == "affected" and not changed:
                changed = changed_paths_from_git(repository, base=args.base)
            plan = build_suite_plan(index, mode=args.mode, changed_paths=changed)
            write_manifest(args.out, plan)
            return 0
        if args.command == "fixtures":
            catalog = FixtureCatalog.from_environment(os.environ, repository=repository)
            rows = [catalog.describe(args.fixture_id)] if args.fixture_id else [catalog.describe(row.id) for row in catalog.definitions()]
            if args.json:
                print(canonical_json({"format": "spaghetti-extractor-fixture-catalog-v1", "fixtures": rows}), end="")
            else:
                for row in rows:
                    status = row["path"] or "not realized"
                    print(f"{row['id']}: {row['description']} [{status}]")
                    if not row["available"]:
                        print(f"  provide Nix attribute: {row['nix_attribute']}")
            return 0
        if args.command == "doctor":
            report = run_doctor(repository, environment=os.environ)
            if args.json:
                print(canonical_json(report.as_dict()), end="")
            else:
                print(f"testkit doctor: {report.status}")
                _print_human_diagnostics([row.as_dict() for row in report.checks])
            return 1 if report.status == "error" else 0
        if args.command == "explain-rebuild":
            before_payload = json.loads(args.before.read_text(encoding="utf-8"))
            after_payload = json.loads(args.after.read_text(encoding="utf-8"))
            if before_payload.get("format") != after_payload.get("format"):
                parser.error("before and after manifests use different formats")
            if before_payload.get("format") == PLAN_FORMAT:
                explanation = explain_plan_rebuild(load_plan(args.before), load_plan(args.after), artifact=args.artifact)
            elif before_payload.get("format") == INDEX_FORMAT:
                explanation = explain_index_rebuild(load_index(args.before), load_index(args.after))
            else:
                parser.error("explain-rebuild accepts test impact indexes or suite plans")
            print(canonical_json(explanation), end="")
            return 0
        if args.kind == "test":
            scaffold_plan = plan_test_scaffold(subsystem=args.first, name=args.second, tier=args.tier, capability=args.capability)
        elif args.kind == "phase":
            scaffold_plan = plan_phase_scaffold(phase_kind=args.first, name=args.second)
        else:
            scaffold_plan = plan_fixture_scaffold(fixture_kind=args.first, name=args.second)
        if args.json:
            print(canonical_json(scaffold_plan.as_dict()), end="")
        elif args.dry_run:
            print(scaffold_plan.render(), end="")
        else:
            created = apply_scaffold_plan(repository, scaffold_plan)
            for path in created:
                print(f"created {path.relative_to(repository)}")
            for command in scaffold_plan.next_commands:
                print(f"then: {command}")
        return 0
    except TestkitError as exc:
        print(str(exc), file=sys.stderr)
        return 2


__all__ = ["main"]
