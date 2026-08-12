"""Nix-first interactive test runner over stable content-addressed shards."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Callable, Sequence

from .diagnostics import Diagnostic, TestkitError
from .discovery import build_impact_index
from .planning import build_suite_plan, changed_paths_from_git


Run = Callable[[Sequence[str], Path], int]


def _run(command: Sequence[str], repository: Path) -> int:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="spaghetti-nix-config-") as temporary:
        config = Path(temporary) / "config.nix"
        config.write_text("{}\n", encoding="ascii")
        environment["NIXPKGS_CONFIG"] = str(config)
        return subprocess.run(
            command, cwd=repository, check=False, env=environment
        ).returncode


def build_commands(
    repository: Path,
    *,
    mode: str,
    target: str | None = None,
    changed: tuple[str, ...] = (),
) -> tuple[tuple[str, ...], ...]:
    source_expression = _source_expression(repository)
    if mode in {"full", "smoke", "benchmark"}:
        expression = _flake_selection(source_expression, f'packages.x86_64-linux."test-{mode}"')
        return (("nix", "build", "--impure", "--expr", expression, "--no-link"),)
    index = build_impact_index(repository)
    if mode == "affected":
        changed_paths = changed or changed_paths_from_git(repository)
        if not changed_paths:
            expression = _flake_selection(source_expression, 'packages.x86_64-linux."test-smoke"')
            return (("nix", "build", "--impure", "--expr", expression, "--no-link"),)
        plan = build_suite_plan(index, mode=mode, changed_paths=changed_paths)
    elif mode == "target":
        plan = build_suite_plan(index, mode=mode, target=target)
    else:
        raise TestkitError(
            Diagnostic(
                "error",
                "unknown_test_mode",
                f"unsupported test mode {mode!r}",
                remediation="Choose smoke, affected, full, target, or benchmark.",
            )
        )
    attributes = " ".join(
        f'flake.checks.x86_64-linux."test-shard-{shard.id}"'
        for shard in plan.shards
    )
    if not attributes:
        return ()
    expression = _flake_expression(source_expression, f"[ {attributes} ]")
    return (("nix", "build", "--impure", "--expr", expression, "--no-link"),)


def _source_expression(repository: Path) -> str:
    root = json.dumps(str(repository.resolve()))
    return f'''builtins.path {{
      path = builtins.toPath {root};
      name = "spaghetti-extractor-worktree";
      filter = path: type:
        let name = builtins.baseNameOf path;
        in !(builtins.elem name [ ".git" ".mypy_cache" ".pytest_cache" "__pycache__" "build" "private" "result" ])
           && !(builtins.match ".*\\\\.py[co]" name != null);
    }}'''


def _flake_expression(source_expression: str, result: str) -> str:
    return f'''let
      source = {source_expression};
      flake = builtins.getFlake (builtins.unsafeDiscardStringContext "path:${{source}}");
    in {result}'''


def _flake_selection(source_expression: str, attribute: str) -> str:
    return _flake_expression(source_expression, f"flake.{attribute}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-test",
        description="Run cached Spaghetti Extractor validation through Nix.",
    )
    parser.add_argument("mode", choices=("affected", "benchmark", "full", "smoke", "target"))
    parser.add_argument("target", nargs="?")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--changed", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None, *, run: Run = _run) -> int:
    args = _parser().parse_args(argv)
    repository = args.repository.resolve()
    try:
        commands = build_commands(
            repository,
            mode=args.mode,
            target=args.target,
            changed=tuple(args.changed),
        )
        for command in commands:
            if args.dry_run:
                print(" ".join(command))
                continue
            result = run(command, repository)
            if result != 0:
                return result
        return 0
    except TestkitError as exc:
        print(str(exc), file=sys.stderr)
        return 2


__all__ = ["build_commands", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
