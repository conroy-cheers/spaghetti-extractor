"""Checked, evaluation-time test topology for the Nix test DAG."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Mapping

from .diagnostics import Diagnostic, TestkitError
from .discovery import build_impact_index
from .model import PlannedShard, SuitePlan, canonical_json, canonical_sha256
from .planning import build_suite_plan


STATIC_MANIFEST_FORMAT = "spaghetti-extractor-static-test-manifest-v1"
STATIC_MODES = ("benchmark", "catalog", "full", "smoke")
DEFAULT_SHARD_COUNT = 32
_GENERIC_SUITE_INCLUDED_ROOTS = frozenset(
    {
        "README.md",
        "REPOSITORY_MAP.md",
        "docs",
        "fixtures",
        "flake.lock",
        "flake.nix",
        "isa-catalogs",
        "nix",
        "profiles",
        "pyproject.toml",
        "src",
        "tests",
        "tools",
    }
)


def _generic_suite_file(path: str) -> bool:
    root = path.split("/", 1)[0]
    return root in _GENERIC_SUITE_INCLUDED_ROOTS


def _static_shard(shard: PlannedShard) -> dict[str, object]:
    core: dict[str, object] = {
        "id": shard.id,
        "resource_class": shard.resource_class,
        "tests": list(shard.tests),
        "test_paths": list(shard.test_paths),
        "files": [path for path in shard.files if _generic_suite_file(path)],
        "fixtures": list(shard.fixtures),
    }
    return {**core, "input_sha256": canonical_sha256(core)}


def nix_execution_plan_payload(
    plan: SuitePlan,
    *,
    excluded_shards: frozenset[str] = frozenset(),
) -> dict[str, object]:
    """Render a live plan without target-only resources or prebuilt shards."""

    payload = plan.as_dict()
    payload["shards"] = [
        {
            **row,
            "files": [path for path in row["files"] if _generic_suite_file(path)],
        }
        for row in payload["shards"]
        if row["id"] not in excluded_shards
    ]
    payload["identity"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "identity"}
    )
    return payload


def build_static_test_manifest(
    repository: Path,
    *,
    shard_count: int = DEFAULT_SHARD_COUNT,
) -> dict[str, object]:
    """Build the content-independent topology consumed during Nix evaluation."""

    index = build_impact_index(repository, shard_count=shard_count)
    plans = {
        mode: build_suite_plan(index, mode=mode)
        for mode in STATIC_MODES
    }
    catalog_shards = {
        shard.id: _static_shard(shard)
        for shard in plans["catalog"].shards
    }
    modes: dict[str, object] = {}
    for mode, plan in sorted(plans.items()):
        shard_ids = [shard.id for shard in plan.shards]
        for shard in plan.shards:
            normalized = _static_shard(shard)
            if catalog_shards.get(shard.id) != normalized:
                raise TestkitError(
                    Diagnostic(
                        "error",
                        "noncanonical_static_shard",
                        f"{mode} changes the contents of catalog shard {shard.id}",
                        remediation="Assign tests from different modes to distinct stable shards.",
                    )
                )
        mode_core = {
            "shard_ids": shard_ids,
            "selected_test_count": len(plan.selected_tests),
        }
        identity_payload = {
            **mode_core,
            "shard_inputs": [catalog_shards[shard_id]["input_sha256"] for shard_id in shard_ids],
        }
        modes[mode] = {**mode_core, "identity": canonical_sha256(identity_payload)}

    core: dict[str, object] = {
        "format": STATIC_MANIFEST_FORMAT,
        "shard_count": shard_count,
        "shards": [catalog_shards[key] for key in sorted(catalog_shards)],
        "modes": modes,
    }
    return {**core, "identity": canonical_sha256(core)}


def load_static_test_manifest(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TestkitError(
            Diagnostic(
                "error",
                "static_test_manifest_unreadable",
                str(exc),
                location=str(path),
                remediation=_refresh_command(path),
            )
        ) from exc
    if not isinstance(payload, Mapping):
        raise TestkitError(
            Diagnostic("error", "invalid_static_test_manifest", "manifest must be an object")
        )
    if payload.get("format") != STATIC_MANIFEST_FORMAT:
        raise TestkitError(
            Diagnostic(
                "error",
                "unsupported_static_test_manifest",
                f"expected {STATIC_MANIFEST_FORMAT}",
                location=str(path),
                remediation=_refresh_command(path),
            )
        )
    identity = payload.get("identity")
    core = {key: value for key, value in payload.items() if key != "identity"}
    if identity != canonical_sha256(core):
        raise TestkitError(
            Diagnostic(
                "error",
                "static_test_manifest_identity_mismatch",
                "manifest content does not match its identity",
                location=str(path),
                remediation=_refresh_command(path),
            )
        )
    return payload


def _refresh_command(path: Path) -> str:
    rendered = (
        "nix/test-suite-manifest.json"
        if path.name == "test-suite-manifest.json"
        else path.as_posix()
    )
    return (
        "Run `nix develop --command python -m "
        "spaghetti_extractor.testkit.static_manifest "
        f"--repository . --manifest {rendered}`."
    )


def check_static_test_manifest(
    repository: Path,
    manifest_path: Path,
    *,
    shard_count: int = DEFAULT_SHARD_COUNT,
) -> None:
    actual = load_static_test_manifest(manifest_path)
    expected = build_static_test_manifest(repository, shard_count=shard_count)
    if actual == expected:
        return

    actual_shards = {
        str(row.get("id")): row
        for row in actual.get("shards", [])
        if isinstance(row, Mapping)
    }
    expected_shards = {
        str(row.get("id")): row
        for row in expected["shards"]
        if isinstance(row, Mapping)
    }
    added = sorted(expected_shards.keys() - actual_shards.keys())
    removed = sorted(actual_shards.keys() - expected_shards.keys())
    changed = sorted(
        key
        for key in expected_shards.keys() & actual_shards.keys()
        if expected_shards[key] != actual_shards[key]
    )
    details = []
    if added:
        details.append(f"added shards: {', '.join(added[:8])}")
    if removed:
        details.append(f"removed shards: {', '.join(removed[:8])}")
    if changed:
        details.append(f"changed shards: {', '.join(changed[:8])}")
    suffix = f" ({'; '.join(details)})" if details else ""
    raise TestkitError(
        Diagnostic(
            "error",
            "stale_static_test_manifest",
            f"checked test topology does not match repository discovery{suffix}",
            location=str(manifest_path),
            remediation=_refresh_command(manifest_path),
        )
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Refresh or check the static Nix test manifest.")
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--shards", type=int, default=DEFAULT_SHARD_COUNT)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository = args.repository.resolve()
    manifest = args.manifest
    if not manifest.is_absolute():
        manifest = repository / manifest
    try:
        if args.check:
            check_static_test_manifest(repository, manifest, shard_count=args.shards)
        else:
            manifest.parent.mkdir(parents=True, exist_ok=True)
            manifest.write_text(
                canonical_json(build_static_test_manifest(repository, shard_count=args.shards)),
                encoding="utf-8",
            )
        return 0
    except TestkitError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_SHARD_COUNT",
    "STATIC_MANIFEST_FORMAT",
    "STATIC_MODES",
    "build_static_test_manifest",
    "check_static_test_manifest",
    "load_static_test_manifest",
    "main",
    "nix_execution_plan_payload",
]
