"""Deterministic smoke, affected, full, target, and benchmark planning."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path, PurePosixPath
import subprocess
from typing import Iterable

from .diagnostics import Diagnostic, TestkitError
from .model import ImpactIndex, PlannedShard, SuitePlan, TestRecord, canonical_sha256, safe_relative_path


MODES = frozenset({"smoke", "affected", "full", "target", "benchmark"})
_INTERNAL_MODES = MODES | {"catalog"}
RESOURCE_CLASS_ORDER = {"small": 0, "medium": 1, "large": 2, "oracle": 3}
CAPABILITY_RESOURCE_CLASS = {
    "benchmark": "large",
    "bochs": "oracle",
    "compiler": "medium",
    "isa": "large",
    "lean": "large",
    "native": "medium",
    "nix": "medium",
    "wine": "oracle",
}
NIX_TEST_CHECKS = {
    "nix/tests/analysis-v3-machine-ir-input.nix": "analysis-v3-machine-ir-input",
    "nix/tests/artifact-seed-v3.nix": "artifact-seed-v3",
    "nix/tests/machine-import-control-profile.nix": "machine-import-control-profile",
}
NIX_TEST_DIRECTORY_CHECKS = {
    "tests/unit/nix_v3/": "authority-graph-v3",
}


def _owned_nix_checks(changed_paths: tuple[str, ...]) -> tuple[str, ...]:
    checks: set[str] = set()
    for changed in changed_paths:
        direct = NIX_TEST_CHECKS.get(changed)
        if direct is not None:
            checks.add(direct)
        for prefix, check in NIX_TEST_DIRECTORY_CHECKS.items():
            if changed.startswith(prefix):
                checks.add(check)
    return tuple(sorted(checks))


def _resource_class(tests: Iterable[TestRecord]) -> str:
    result = "small"
    for test in tests:
        for capability in test.capabilities:
            candidate = CAPABILITY_RESOURCE_CLASS.get(capability, "small")
            if RESOURCE_CLASS_ORDER[candidate] > RESOURCE_CLASS_ORDER[result]:
                result = candidate
    return result


def changed_paths_from_git(repository: Path, *, base: str = "HEAD") -> tuple[str, ...]:
    repository = repository.resolve()
    if not (repository / ".git").exists():
        raise TestkitError(
            Diagnostic(
                "error",
                "git_metadata_unavailable",
                "affected planning needs explicit changed paths outside a Git checkout",
                location=str(repository),
                remediation="Pass one or more `--changed path/to/file` arguments.",
            )
        )
    commands = (
        ("git", "diff", "--name-only", "--relative", base, "--"),
        ("git", "ls-files", "--others", "--exclude-standard"),
    )
    changed: set[str] = set()
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=repository,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "git_diff_failed",
                    completed.stderr.strip() or "git could not determine changed paths",
                    remediation="Pass explicit `--changed` paths or repair the Git worktree.",
                    example="nix run .#dev -- plan affected --changed src/spaghetti_extractor/control.py",
                )
            )
        changed.update(line for line in completed.stdout.splitlines() if line)
    return tuple(sorted(safe_relative_path(path, field_name="changed path") for path in changed))


def _select_affected(
    index: ImpactIndex,
    changed_paths: tuple[str, ...],
) -> tuple[set[str], dict[str, set[str]], list[Diagnostic]]:
    selected = {test.id for test in index.tests if test.tier == "smoke"}
    reasons: dict[str, set[str]] = defaultdict(set)
    diagnostics: list[Diagnostic] = []
    for test in index.tests:
        if test.tier == "smoke":
            reasons[test.id].add("mandatory smoke gate")
    known_paths = {module.path for module in index.modules}
    known_paths.update(test.path for test in index.tests)
    broad_change = False
    for changed in changed_paths:
        matched = False
        owned_nix_checks = _owned_nix_checks((changed,))
        if owned_nix_checks:
            matched = True
        if changed.startswith("src/spaghetti_extractor/testkit/") or changed in {
            "nix/test-suite-fixtures.nix",
            "nix/test-suite-plan.nix",
            "nix/test-suite-shard.nix",
            "nix/test-suite.nix",
        }:
            broad_change = True
            matched = True
        for test in index.tests:
            if changed == test.path:
                selected.add(test.id)
                reasons[test.id].add(f"test changed: {changed}")
                matched = True
            elif changed in test.dependency_paths:
                selected.add(test.id)
                reasons[test.id].add(f"import dependency changed: {changed}")
                matched = True
            elif changed in test.resources or any(
                changed.startswith(f"{resource.rstrip('/')}/") for resource in test.resources
            ):
                selected.add(test.id)
                reasons[test.id].add(f"declared resource changed: {changed}")
                matched = True
        parts = PurePosixPath(changed).parts
        suffix = PurePosixPath(changed).suffix
        if changed in {"flake.nix", "flake.lock", "pyproject.toml"}:
            broad_change = True
            matched = True
        elif parts and parts[0] == "nix" and not owned_nix_checks:
            for test in index.tests:
                if "nix" in test.capabilities:
                    selected.add(test.id)
                    reasons[test.id].add(f"Nix infrastructure changed: {changed}")
            matched = True
        elif suffix == ".lean" or (parts and parts[0] == "isa-catalogs"):
            for test in index.tests:
                if "lean" in test.capabilities or "isa" in test.capabilities:
                    selected.add(test.id)
                    reasons[test.id].add(f"formal semantics input changed: {changed}")
            matched = True
        elif len(parts) >= 2 and parts[0] == "targets":
            target = parts[1]
            for test in index.tests:
                if test.target == target:
                    selected.add(test.id)
                    reasons[test.id].add(f"target input changed: {changed}")
            matched = True
        elif parts and parts[0] in {"docs", ".github"}:
            matched = True
        if not matched and changed not in known_paths:
            broad_change = True
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "unknown_change_uses_full_gate",
                    "no checked dependency maps this path, so affected mode conservatively selects the full generic suite",
                    location=changed,
                    remediation="Declare the resource in TESTKIT when the change has a narrower test dependency.",
                    example='TESTKIT = {"resources": ["profiles/example.json"]}',
                )
            )
    if broad_change:
        for test in index.tests:
            if test.tier not in {"target", "benchmark"}:
                selected.add(test.id)
                reasons[test.id].add("conservative full-suite dependency")
    return selected, reasons, diagnostics


def build_suite_plan(
    index: ImpactIndex,
    *,
    mode: str,
    target: str | None = None,
    changed_paths: Iterable[str] = (),
) -> SuitePlan:
    if mode not in _INTERNAL_MODES:
        raise TestkitError(
            Diagnostic(
                "error",
                "unknown_plan_mode",
                f"unsupported mode {mode!r}",
                remediation=f"Choose one of: {', '.join(sorted(MODES))}.",
            )
        )
    changed = tuple(sorted(set(safe_relative_path(path, field_name="changed path") for path in changed_paths)))
    reasons: dict[str, set[str]] = defaultdict(set)
    diagnostics: list[Diagnostic] = list(index.diagnostics)
    if mode == "catalog":
        selected = {test.id for test in index.tests}
        for test_id in selected:
            reasons[test_id].add("complete internal shard catalog")
    elif mode == "smoke":
        selected = {test.id for test in index.tests if test.tier == "smoke"}
        for test_id in selected:
            reasons[test_id].add("smoke convention")
    elif mode == "full":
        selected = {test.id for test in index.tests if test.tier not in {"target", "benchmark"}}
        for test_id in selected:
            reasons[test_id].add("complete generic gate")
    elif mode == "benchmark":
        selected = {test.id for test in index.tests if test.tier == "benchmark"}
        for test_id in selected:
            reasons[test_id].add("benchmark convention")
    elif mode == "target":
        if not target:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "target_required",
                    "target planning requires a target name",
                    remediation="Pass `--target <name>`.",
                    example="nix run .#dev -- plan target --target <id>",
                )
            )
        available = sorted({test.target for test in index.tests if test.target})
        if target not in available:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "unknown_test_target",
                    f"no convention-classified tests exist for target {target!r}",
                    remediation=f"Create tests under tests/targets/{target}/; available targets: {', '.join(available) or 'none'}.",
                )
            )
        selected = {
            test.id for test in index.tests if test.target == target or test.tier == "smoke"
        }
        for test in index.tests:
            if test.id in selected:
                reasons[test.id].add("mandatory smoke gate" if test.tier == "smoke" else f"target qualification: {target}")
    else:
        if not changed:
            raise TestkitError(
                Diagnostic(
                    "error",
                    "changed_paths_required",
                    "affected planning requires at least one changed path",
                    remediation="Allow the CLI to inspect Git, or pass `--changed` explicitly.",
                )
            )
        selected, reasons, affected_diagnostics = _select_affected(index, changed)
        diagnostics.extend(affected_diagnostics)
    selected_rows = [test for test in index.tests if test.id in selected]
    if not selected_rows:
        diagnostics.append(
            Diagnostic(
                "warning",
                "empty_test_plan",
                f"{mode} mode selected no tests",
                remediation="Add a convention-classified test with the scaffolder.",
            )
        )
    by_shard: dict[str, list[TestRecord]] = defaultdict(list)
    for test in selected_rows:
        by_shard[test.shard].append(test)
    shards: list[PlannedShard] = []
    for shard_id, rows in sorted(by_shard.items()):
        rows.sort(key=lambda row: row.id)
        resource_roots = {resource.rstrip("/") for row in rows for resource in row.resources}
        candidate_files = {
            path
            for row in rows
            for path in (row.path, *row.dependency_paths, *row.resources)
        }
        files = sorted(
            path
            for path in candidate_files
            if not any(
                root != path and path.startswith(f"{root}/")
                for root in resource_roots
            )
        )
        fixtures = sorted({fixture for row in rows for fixture in row.fixtures})
        shards.append(
            PlannedShard(
                id=shard_id,
                resource_class=_resource_class(rows),
                tests=tuple(row.id for row in rows),
                test_paths=tuple(row.path for row in rows),
                files=tuple(files),
                fixtures=tuple(fixtures),
                input_sha256=canonical_sha256(
                    {
                        "tests": [{"id": row.id, "input_sha256": row.input_sha256} for row in rows],
                        "fixtures": fixtures,
                    }
                ),
            )
        )
    return SuitePlan(
        mode=mode,
        index_identity=index.identity,
        target=target,
        changed_paths=changed,
        selected_tests=tuple(row.id for row in selected_rows),
        selection_reasons=tuple(
            (test_id, tuple(sorted(reasons[test_id]))) for test_id in sorted(selected)
        ),
        shards=tuple(shards),
        nix_checks=(
            _owned_nix_checks(changed) if mode == "affected" else ()
        ),
        diagnostics=tuple(sorted(diagnostics)),
    )


__all__ = ["MODES", "build_suite_plan", "changed_paths_from_git"]
