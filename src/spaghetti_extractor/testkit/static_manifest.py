"""Checked, evaluation-time test topology for the Nix test DAG."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Mapping

from ..python_module_index import render_python_module_index
from .diagnostics import Diagnostic, TestkitError
from .discovery import build_impact_index
from .model import PlannedShard, SuitePlan, canonical_json, canonical_sha256
from .planning import build_suite_plan


STATIC_MANIFEST_FORMAT = "spaghetti-extractor-static-test-manifest-v1"
STATIC_MODES = ("benchmark", "catalog", "full", "smoke")
DEFAULT_SHARD_COUNT = 32
PYTHON_MODULE_INDEX_PATH = Path("nix/python-module-index.json")
STATIC_TEST_MANIFEST_PATH = Path("nix/test-suite-manifest.json")
REPOSITORY_METADATA_REMEDIATION = "Run `nix run .#dev -- refresh`."
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
    del path
    return REPOSITORY_METADATA_REMEDIATION


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


def _metadata_payloads(
    repository: Path,
    *,
    shard_count: int,
) -> dict[Path, str]:
    root = repository.resolve()
    try:
        python_index = render_python_module_index(root)
        test_manifest = canonical_json(
            build_static_test_manifest(root, shard_count=shard_count)
        )
    except TestkitError:
        raise
    except (OSError, SyntaxError, ValueError) as exc:
        raise TestkitError(
            Diagnostic(
                "error",
                "repository_metadata_generation_failed",
                f"could not generate checked repository metadata: {exc}",
                remediation=REPOSITORY_METADATA_REMEDIATION,
            )
        ) from exc
    return {
        root / PYTHON_MODULE_INDEX_PATH: python_index,
        root / STATIC_TEST_MANIFEST_PATH: test_manifest,
    }


def _relative_metadata_paths(repository: Path, paths: list[Path]) -> str:
    root = repository.resolve()
    rendered: list[str] = []
    for path in paths:
        try:
            rendered.append(path.relative_to(root).as_posix())
        except ValueError:
            rendered.append(path.as_posix())
    return ", ".join(rendered)


def _stale_metadata_error(repository: Path, paths: list[Path]) -> TestkitError:
    rendered = _relative_metadata_paths(repository, paths)
    return TestkitError(
        Diagnostic(
            "error",
            "stale_repository_metadata",
            f"checked repository metadata does not match discovery: {rendered}",
            location=str(repository.resolve()),
            remediation=REPOSITORY_METADATA_REMEDIATION,
        )
    )


def _replace_metadata_files(payloads: Mapping[Path, str]) -> None:
    staged: dict[Path, Path] = {}
    previous: dict[Path, bytes | None] = {}
    replaced: list[Path] = []
    try:
        for destination, content in payloads.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            previous[destination] = (
                destination.read_bytes() if destination.is_file() else None
            )
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            staged[destination] = Path(temporary)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        for destination, temporary in staged.items():
            os.replace(temporary, destination)
            replaced.append(destination)
    except OSError as exc:
        for destination in reversed(replaced):
            old_content = previous[destination]
            if old_content is None:
                destination.unlink(missing_ok=True)
                continue
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{destination.name}.rollback.",
                suffix=".tmp",
                dir=destination.parent,
            )
            rollback = Path(temporary)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(old_content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(rollback, destination)
            finally:
                rollback.unlink(missing_ok=True)
        raise TestkitError(
            Diagnostic(
                "error",
                "repository_metadata_write_failed",
                f"could not atomically publish repository metadata: {exc}",
                remediation=REPOSITORY_METADATA_REMEDIATION,
            )
        ) from exc
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)


def refresh_repository_metadata(
    repository: Path,
    *,
    check: bool = False,
    shard_count: int = DEFAULT_SHARD_COUNT,
) -> tuple[Path, ...]:
    """Refresh or jointly validate both checked repository metadata files."""

    root = repository.resolve()
    payloads = _metadata_payloads(root, shard_count=shard_count)
    stale = [
        path
        for path, expected in payloads.items()
        if not path.is_file()
        or path.read_text(encoding="utf-8", errors="replace") != expected
    ]
    if check:
        if stale:
            raise _stale_metadata_error(root, stale)
        return ()
    if not stale:
        return ()
    _replace_metadata_files({path: payloads[path] for path in stale})
    return tuple(stale)


def check_repository_metadata(
    repository: Path,
    *,
    shard_count: int = DEFAULT_SHARD_COUNT,
) -> None:
    refresh_repository_metadata(repository, check=True, shard_count=shard_count)


__all__ = [
    "DEFAULT_SHARD_COUNT",
    "PYTHON_MODULE_INDEX_PATH",
    "REPOSITORY_METADATA_REMEDIATION",
    "STATIC_MANIFEST_FORMAT",
    "STATIC_MODES",
    "STATIC_TEST_MANIFEST_PATH",
    "build_static_test_manifest",
    "check_repository_metadata",
    "check_static_test_manifest",
    "load_static_test_manifest",
    "nix_execution_plan_payload",
    "refresh_repository_metadata",
]
