"""Nix-first interactive test runner over stable content-addressed shards."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable, Sequence

from .diagnostics import Diagnostic, TestkitError
from .discovery import build_impact_index
from .evaluation_receipts import evaluation_receipt_directory
from .planning import build_suite_plan, changed_paths_from_git


Run = Callable[[Sequence[str], Path], int]

_SOURCE_EXCLUDED_NAMES = frozenset(
    {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "build", "private", "result"}
)
_DERIVATION_PATH = re.compile(r"/nix/store/[0-9a-z]{32}-[^\x00\n]+[.]drv")
_EVALUATION_RECEIPT_FORMAT = "spaghetti-extractor-nix-evaluation-receipt-v1"


def _run(command: Sequence[str], repository: Path) -> int:
    environment = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="spaghetti-nix-config-") as temporary:
        config = Path(temporary) / "config.nix"
        config.write_text("{}\n", encoding="ascii")
        environment["NIXPKGS_CONFIG"] = str(config)
        if _cacheable_nix_expression(command):
            cached = _run_cached_nix_expression(
                command, repository=repository, environment=environment
            )
            if cached is not None:
                return cached
        return subprocess.run(
            command, cwd=repository, check=False, env=environment
        ).returncode


def _cacheable_nix_expression(command: Sequence[str]) -> bool:
    return (
        len(command) >= 5
        and tuple(command[:2]) == ("nix", "build")
        and "--expr" in command
        and "--impure" in command
    )


def _filtered_source_sha256(repository: Path) -> str | None:
    """Hash exactly the source shape admitted by ``_source_expression``.

    The hash is only an evaluator-cache key. Nix still builds and validates the
    selected derivations. If the tree changes while it is read, return ``None``
    and use the ordinary uncached command.
    """

    digest = hashlib.sha256()
    try:
        for root_text, directories, files in os.walk(
            repository, topdown=True, followlinks=False
        ):
            root = Path(root_text)
            directories[:] = sorted(
                name
                for name in directories
                if name not in _SOURCE_EXCLUDED_NAMES
                and re.fullmatch(r".*[.]py[co]", name) is None
            )
            names = sorted(
                name
                for name in (*directories, *files)
                if name not in _SOURCE_EXCLUDED_NAMES
                and re.fullmatch(r".*[.]py[co]", name) is None
            )
            for name in names:
                path = root / name
                relative = path.relative_to(repository).as_posix().encode("utf-8")
                before = path.lstat()
                mode = stat.S_IMODE(before.st_mode)
                if stat.S_ISLNK(before.st_mode):
                    kind = b"symlink"
                    content = os.readlink(path).encode("utf-8")
                elif stat.S_ISDIR(before.st_mode):
                    kind = b"directory"
                    content = b""
                elif stat.S_ISREG(before.st_mode):
                    kind = b"file"
                    file_digest = hashlib.sha256()
                    with path.open("rb") as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            file_digest.update(chunk)
                    content = file_digest.digest()
                else:
                    return None
                after = path.lstat()
                if (
                    before.st_mode != after.st_mode
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    return None
                for value in (relative, kind, str(mode).encode("ascii"), content):
                    digest.update(len(value).to_bytes(8, "big"))
                    digest.update(value)
        return digest.hexdigest()
    except OSError:
        return None


def _nix_identity(environment: dict[str, str], repository: Path) -> tuple[str, str] | None:
    executable = shutil.which("nix")
    if executable is None:
        return None
    result = subprocess.run(
        (executable, "--version"),
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip(), os.path.realpath(executable)


def _receipt_core(
    *,
    key: str,
    source_sha256: str,
    expression_sha256: str,
    nix_version: str,
    nix_executable: str,
    derivations: Sequence[str],
) -> dict[str, object]:
    return {
        "format": _EVALUATION_RECEIPT_FORMAT,
        "key": key,
        "source_sha256": source_sha256,
        "expression_sha256": expression_sha256,
        "nix_version": nix_version,
        "nix_executable": nix_executable,
        "system": os.uname().machine,
        "derivations": list(derivations),
    }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _read_evaluation_receipt(
    path: Path, *, expected_core: dict[str, object]
) -> tuple[str, ...] | None:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or set(value) != {*expected_core, "receipt_sha256"}:
        return None
    derivations = value.get("derivations")
    if not isinstance(derivations, list) or not derivations:
        return None
    if any(
        not isinstance(item, str)
        or _DERIVATION_PATH.fullmatch(item) is None
        or not Path(item).is_file()
        for item in derivations
    ):
        return None
    observed_core = {key: value[key] for key in expected_core}
    if observed_core != {**expected_core, "derivations": derivations}:
        return None
    if value["receipt_sha256"] != hashlib.sha256(
        _canonical_json(observed_core)
    ).hexdigest():
        return None
    return tuple(derivations)


def _write_evaluation_receipt(path: Path, core: dict[str, object]) -> None:
    payload = {
        **core,
        "receipt_sha256": hashlib.sha256(_canonical_json(core)).hexdigest(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", prefix=f".{path.name}.", dir=path.parent, delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(_canonical_json(payload) + b"\n")
    temporary.replace(path)


def _evaluate_derivations(
    expression: str,
    *,
    repository: Path,
    environment: dict[str, str],
) -> tuple[str, ...] | None:
    wrapped = (
        "let value = (" + expression + "); "
        "values = if builtins.isList value then value else [ value ]; "
        "in map (item: item.drvPath) values"
    )
    result = subprocess.run(
        ("nix", "eval", "--impure", "--json", "--expr", wrapped),
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return None
    try:
        values = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if (
        not isinstance(values, list)
        or not values
        or any(
            not isinstance(value, str)
            or _DERIVATION_PATH.fullmatch(value) is None
            or not Path(value).is_file()
            for value in values
        )
    ):
        return None
    return tuple(values)


def _realise_derivations(
    derivations: Sequence[str],
    command: Sequence[str],
    *,
    repository: Path,
    environment: dict[str, str],
) -> int:
    expression_index = command.index("--expr")
    retained = [
        item
        for item in command[expression_index + 2 :]
        if item not in {"--impure", "--expr"}
    ]
    realise = (
        "nix",
        "build",
        *(f"{path}^*" for path in derivations),
        *retained,
    )
    return subprocess.run(
        realise, cwd=repository, check=False, env=environment
    ).returncode


def _run_cached_nix_expression(
    command: Sequence[str], *, repository: Path, environment: dict[str, str]
) -> int | None:
    source_sha256 = _filtered_source_sha256(repository)
    nix_identity = _nix_identity(environment, repository)
    if source_sha256 is None or nix_identity is None:
        return None
    nix_version, nix_executable = nix_identity
    expression_index = command.index("--expr")
    try:
        expression = command[expression_index + 1]
    except IndexError:
        return None
    expression_sha256 = hashlib.sha256(expression.encode("utf-8")).hexdigest()
    key_core = {
        "source_sha256": source_sha256,
        "expression_sha256": expression_sha256,
        "nix_version": nix_version,
        "nix_executable": nix_executable,
        "system": os.uname().machine,
    }
    key = hashlib.sha256(_canonical_json(key_core)).hexdigest()
    expected_core = _receipt_core(
        key=key,
        source_sha256=source_sha256,
        expression_sha256=expression_sha256,
        nix_version=nix_version,
        nix_executable=nix_executable,
        derivations=(),
    )
    receipt_path = evaluation_receipt_directory() / f"{key}.json"
    derivations = _read_evaluation_receipt(
        receipt_path, expected_core=expected_core
    )
    if derivations is None:
        print(
            f"spaghetti-extractor: evaluating Nix graph for receipt {key[:12]}",
            file=sys.stderr,
        )
        derivations = _evaluate_derivations(
            expression, repository=repository, environment=environment
        )
        if derivations is None:
            return None
        # Do not persist a receipt if a concurrent edit crossed the evaluator
        # snapshot.  Without this second read, reverting that edit later could
        # associate an old source hash with derivations from the changed tree.
        if _filtered_source_sha256(repository) == source_sha256:
            _write_evaluation_receipt(
                receipt_path,
                _receipt_core(
                    key=key,
                    source_sha256=source_sha256,
                    expression_sha256=expression_sha256,
                    nix_version=nix_version,
                    nix_executable=nix_executable,
                    derivations=derivations,
                ),
            )
        else:
            print(
                "spaghetti-extractor: source changed during evaluation; receipt not cached",
                file=sys.stderr,
            )
    else:
        print(
            f"spaghetti-extractor: reusing checked Nix evaluation receipt {key[:12]}",
            file=sys.stderr,
        )
    return _realise_derivations(
        derivations, command, repository=repository, environment=environment
    )


def build_commands(
    repository: Path,
    *,
    mode: str,
    target: str | None = None,
    changed: tuple[str, ...] = (),
) -> tuple[tuple[str, ...], ...]:
    source_expression = _source_expression(repository)
    if mode == "target":
        available = tuple(
            path.parent.name
            for path in sorted((repository / "targets").glob("*/target.json"))
        )
        if not target or target not in available:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "unknown_test_target",
                    f"unknown validation target {target!r}",
                    remediation=f"Choose one of: {', '.join(available) or 'none'}.",
                )
            )
    if mode in {"full", "smoke", "benchmark", "target"}:
        suffix = mode if mode != "target" else f"target-{target or ''}"
        expression = _flake_selection(
            source_expression,
            f'legacyPackages.x86_64-linux."test-{suffix}"',
        )
        builder_arguments = _builder_arguments(
            repository, remote=mode in {"full", "target"}
        )
        command = (
            "nix",
            "build",
            "--impure",
            "--expr",
            expression,
            *builder_arguments,
            "--keep-going",
            "--no-link",
        )
        if mode == "smoke":
            return (command,)
        smoke = _flake_selection(
            source_expression, 'legacyPackages.x86_64-linux."test-smoke"'
        )
        return (
            ("nix", "build", "--impure", "--expr", smoke, "--builders", "", "--no-link"),
            command,
        )
    index = build_impact_index(repository)
    if mode == "affected":
        changed_paths = changed or changed_paths_from_git(repository)
        if not changed_paths:
            expression = _flake_selection(
                source_expression,
                'legacyPackages.x86_64-linux."test-smoke"',
            )
            return (("nix", "build", "--impure", "--expr", expression, "--keep-going", "--no-link"),)
        plan = build_suite_plan(index, mode=mode, changed_paths=changed_paths)
    else:
        raise TestkitError(
            Diagnostic(
                "error",
                "unknown_test_mode",
                f"unsupported test mode {mode!r}",
                remediation="Choose smoke, affected, full, target, or benchmark.",
            )
        )
    selected_shards = tuple(
        shard for shard in plan.shards if shard.id != "smoke"
    )
    attributes = " ".join((
        *(
            f'flake.legacyPackages.x86_64-linux.test-shards."{shard.id}"'
            for shard in selected_shards
        ),
        *(
            f'flake.checks.x86_64-linux."{check}"'
            for check in plan.nix_checks
        ),
    ))
    if not attributes:
        smoke = _flake_selection(
            source_expression, 'legacyPackages.x86_64-linux."test-smoke"'
        )
        return (("nix", "build", "--impure", "--expr", smoke, "--builders", "", "--no-link"),)
    expression = _flake_expression(source_expression, f"[ {attributes} ]")
    builder_arguments = _builder_arguments(
        repository,
        remote=(
            len(selected_shards) + len(plan.nix_checks) >= 8
            or any(shard.resource_class != "small" for shard in selected_shards)
        ),
    )
    smoke = _flake_selection(
        source_expression, 'legacyPackages.x86_64-linux."test-smoke"'
    )
    return (
        ("nix", "build", "--impure", "--expr", smoke, "--builders", "", "--no-link"),
        ("nix", "build", "--impure", "--expr", expression, *builder_arguments, "--no-link"),
    )


def _builder_arguments(repository: Path, *, remote: bool) -> tuple[str, ...]:
    if not remote:
        return ("--builders", "")
    machines = repository / "nix" / "stage-a-builders"
    if not machines.is_file():
        return ()
    return (
        "--builders",
        f"@{machines.resolve()}",
        "--option",
        "builders-use-substitutes",
        "true",
    )


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
        if args.mode == "target" and not args.target:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "target_required",
                    "target mode requires an ID",
                    remediation="Pass an ID declared by targets/*/target.json.",
                )
            )
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
