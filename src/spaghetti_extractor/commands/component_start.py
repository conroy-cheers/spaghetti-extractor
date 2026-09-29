"""Transactional materialization helpers for ``component start``."""

from __future__ import annotations

import argparse
import copy
import fcntl
import json
import os
import shutil
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ..util import sha256_text


def safe_package_file(root: Path, relative: object, context: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError(f"{context} path is not text")
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError(f"{context} path is not a strict relative path")
    resolved = root.joinpath(*path.parts)
    if resolved.is_symlink() or not resolved.is_file():
        raise ValueError(f"{context} file is absent or not regular: {relative}")
    return resolved


def component_start_plan(
    *, component_id: str, package: Mapping[str, Any], target_path: str,
) -> dict[str, Any]:
    plan = {
        "authority": False,
        "kind": "component-start-plan-v1",
        "component_id": component_id,
        "work_package_sha256": package["work_package_sha256"],
        "source_transition": {
            "package_path": "src/component.c",
            "target_path": target_path,
            "include_rewrite": {
                "from": '#include "component.h"',
                "to": '#include "portable-component-implementation.h"',
            },
            "operation_symbols": {
                str(row["operation_id"]): str(row["symbol"])
                for row in package["operations"]
            },
        },
        "next_action": (
            "replace the generated #error with authored portable C, then run "
            f"component check --source for {component_id}; resolve proof obligations "
            "before the default component check"
        ),
    }
    editing_inputs = package.get('requirements', {}).get('editing_inputs')
    if editing_inputs is not None:
        plan['editing_inputs'] = sorted(name + '.json' for name in editing_inputs)
        plan['next_action'] = (
            'edit the canonical interface/binding/cutpoint inputs and ordinary C; '
            'boundary adopt --input DIR --output DIR normalizes a draft, or --apply updates configured declarations; '
            'install reviewed C in the reported target source files; '
            'check changed contracts and state transport before qualification')
    definition = package.get("requirements", {}).get("caller_definition")
    if definition is not None:
        plan["caller_definition"] = {
            "package_path": "caller-contract.json",
            "status": "declared",
            **({"suppliers": copy.deepcopy(definition['suppliers'])} if 'suppliers' in definition else {
                "supplier_service_id": definition["service_id"],
                "requested_frame_facts": definition["required_frame"]}),
            "runtime_assumptions": definition["runtime_contracts"],
            "authorizes_activation": False,
        }
        plan["next_action"] = (
            "edit caller-contract.json and ordinary C; retain the declared scope and "
            "review supplier facts and runtime assumptions, then run component check "
            "--source --local-contracts; local success does not authorize activation"
        )
    return plan


def copy_component_start_package(
    *, source: Path, output: Path, plan: Mapping[str, Any],
) -> None:
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise ValueError("component start output must be a new or empty directory")
    else:
        output.mkdir(parents=True)
    for source_path in sorted(source.rglob("*")):
        if source_path.is_symlink():
            raise ValueError("component work package contains a symbolic link")
        relative = source_path.relative_to(source)
        destination = output / relative
        if source_path.is_dir():
            destination.mkdir(exist_ok=True)
        elif source_path.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)
        else:
            raise ValueError("component work package contains an unsupported file")
    (output / "component-start-plan.json").write_text(
        json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    from ..operator.source_guidance import write_authoring_guidance

    write_authoring_guidance(output)
    for path in [output, *output.rglob("*")]:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IWUSR | (stat.S_IXUSR if path.is_dir() else 0))


def component_authoring_paths(
    args: argparse.Namespace, *, bundle: Path,
) -> tuple[Path, Path, Path]:
    from ..target_bundles.metadata import TargetMetadata

    metadata = TargetMetadata.load(bundle / "target.json")
    if metadata.identity != args.target:
        raise ValueError("local target metadata binds another target")
    paths = dict(metadata.paths)
    component_intent = paths.get("components")
    source_root = paths.get("component_sources")
    if component_intent is None:
        raise ValueError("target has no component lifting intent path")
    if source_root is None:
        raise ValueError(
            "target metadata must declare paths.component_sources before --apply"
        )
    bundle = bundle.resolve()
    intent_path = (bundle / component_intent).resolve()
    source_path = (bundle / source_root).resolve()
    if not intent_path.is_relative_to(bundle) or not source_path.is_relative_to(bundle):
        raise ValueError("component authoring paths escape the target bundle")
    if not intent_path.is_file():
        raise ValueError(f"component lifting intent does not exist: {intent_path}")
    if source_path.exists() and not source_path.is_dir():
        raise ValueError(f"component source root is not a directory: {source_path}")
    return bundle, intent_path, source_path


def adopt_caller_definition(*, draft: Path, package: Mapping[str, Any], output: Path) -> None:
    """Export edited declaration data against the current package, without proof."""
    from ..components.work_package_v6 import ComponentWorkPackageV6, caller_definition_text

    baseline = ComponentWorkPackageV6.parse(json.loads(safe_package_file(
        draft, "component-work-package-v6.json", "caller editing baseline").read_text()))
    if baseline.identity != package["work_package_sha256"]:
        raise ValueError("caller editing baseline is stale; propose a current work package before adopting")
    candidate = copy.deepcopy(dict(package))
    candidate["requirements"]["caller_definition"] = json.loads(safe_package_file(
        draft, "caller-contract.json", "edited caller definition").read_text())
    text = caller_definition_text(candidate)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".caller-adopt-", dir=output.parent) as temporary:
        staged = Path(temporary) / "caller-contract.json"
        staged.write_text(text, encoding="utf-8")
        os.replace(staged, output)


def _started_component_intent(
    *, intent_path: Path, component_id: str, package: Mapping[str, Any],
    relative_source: str,
) -> bytes:
    from ..components.lifting_intent import ComponentLiftingIntentV1

    try:
        payload = json.loads(intent_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read component lifting intent: {exc}") from exc
    intent = ComponentLiftingIntentV1.parse(payload)
    components = [dict(row) for row in intent.components]
    matches = [row for row in components if row["id"] == component_id]
    if len(matches) != 1:
        raise ValueError("component work package has no unique lifting-intent row")
    component = matches[0]
    if "source" in component:
        raise ValueError(f"component {component_id!r} already has authored source")
    component["source"] = {
        "files": [relative_source],
        "shared_inputs": [],
        "operation_symbols": {
            str(row["operation_id"]): str(row["symbol"])
            for row in package["operations"]
        },
    }
    updated = ComponentLiftingIntentV1.create(
        program_id=intent.program_id,
        components=components,
        groups=intent.groups,
        configurations=intent.configurations,
    )
    return (
        json.dumps(updated.to_payload(), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _canonical_component_source(package_root: Path) -> bytes:
    skeleton = safe_package_file(
        package_root, "src/component.c", "component skeleton"
    ).read_text(encoding="utf-8")
    package_include = '#include "component.h"'
    canonical_include = '#include "portable-component-implementation.h"'
    if skeleton.count(package_include) != 1:
        raise ValueError("component skeleton has no unique package-local include")
    return skeleton.replace(package_include, canonical_include, 1).encode("utf-8")


def _component_start_lock_path(intent_path: Path) -> Path:
    lock_root = Path(tempfile.gettempdir()) / f"spaghetti-extractor-{os.getuid()}"
    lock_root.mkdir(mode=0o700, exist_ok=True)
    lock_stat = lock_root.lstat()
    if (
        not stat.S_ISDIR(lock_stat.st_mode)
        or lock_stat.st_uid != os.getuid()
        or lock_stat.st_mode & 0o077
    ):
        raise ValueError("component transaction lock directory is not private")
    return lock_root / f"component-start-{sha256_text(str(intent_path.resolve()))}.lock"


def apply_component_start(
    *, args: argparse.Namespace, component_id: str,
    package_root: Path, package: Mapping[str, Any], bundle: Path,
) -> tuple[Path, Path]:
    bundle, intent_path, source_root = component_authoring_paths(
        args, bundle=bundle
    )
    relative_source = f"components/{component_id}.c"
    target_source = source_root / relative_source
    lock_path = _component_start_lock_path(intent_path)
    with lock_path.open("a+", encoding="ascii") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("another component start transaction is active") from exc
        if target_source.exists():
            raise ValueError(f"component source already exists: {target_source}")
        original_intent = intent_path.read_bytes()
        updated_intent = _started_component_intent(
            intent_path=intent_path,
            component_id=component_id,
            package=package,
            relative_source=relative_source,
        )
        source_bytes = _canonical_component_source(package_root)
        with tempfile.TemporaryDirectory(prefix=".component-start-", dir=bundle) as temp:
            staging = Path(temp)
            staged_source = staging / "component.c"
            staged_intent = staging / "components.json"
            staged_source.write_bytes(source_bytes)
            staged_intent.write_bytes(updated_intent)
            target_source.parent.mkdir(parents=True, exist_ok=True)
            source_installed = False
            intent_installed = False
            try:
                os.replace(staged_source, target_source)
                source_installed = True
                os.replace(staged_intent, intent_path)
                intent_installed = True
            except Exception:
                if intent_installed:
                    restore = staging / "components.original.json"
                    restore.write_bytes(original_intent)
                    os.replace(restore, intent_path)
                if source_installed and target_source.exists():
                    target_source.unlink()
                raise
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return intent_path, target_source


__all__ = [
    "apply_component_start",
    "component_start_plan",
    "copy_component_start_package",
    "safe_package_file",
]
