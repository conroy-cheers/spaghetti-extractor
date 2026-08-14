"""Source closure and compilation metadata for interpreter-native builds."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..util import sha256_file
from . import native_build
from .build_model import (
    INTERPRETER_NATIVE_SOURCE_BUNDLE_FORMAT,
    StageBInterpreterNativeBuildError,
    _Artifact,
    _C_IDENTIFIER,
    _DIAGNOSTIC_MACRO,
    _INCLUDE_DIRECTIVE,
    _Package,
    _QUOTED_INCLUDE,
    _SYSTEM_INCLUDE,
)
from .build_values import _read_json_object, _relative_path


def _compile_units(
    interpreter: _Package,
    engine: _Package,
    runtime: _Package,
    entry_symbol: str,
    region_overrides: _Package | None = None,
) -> tuple[_Artifact, ...]:
    interpreter_roles = {"interpreter_source", "program_source"}
    runtime_roles = {"native_runtime_source"}
    selected = [
        item
        for package in (
            interpreter,
            engine,
            runtime,
            *((region_overrides,) if region_overrides is not None else ()),
        )
        for item in package.artifacts
        if item.path.suffix.lower() in {".c", ".s"}
    ]
    if not interpreter_roles.issubset(
        {item.role for item in interpreter.artifacts}
    ):
        raise StageBInterpreterNativeBuildError(
            "interpreter package omits required compilation units"
        )
    if not runtime_roles.issubset({item.role for item in runtime.artifacts}):
        raise StageBInterpreterNativeBuildError(
            "native-runtime package omits its source compilation unit"
        )
    if not any(item.path.suffix.lower() == ".s" for item in engine.artifacts):
        raise StageBInterpreterNativeBuildError(
            "native-engine package has no assembly bridge source"
        )

    source_texts: list[str] = []
    for item in selected:
        try:
            text = item.path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise StageBInterpreterNativeBuildError(
                f"source is not readable ASCII: {item.relative_path}"
            ) from exc
        source_texts.append(text)
        if native_build._PLACEHOLDER_INT3.search(text):
            raise StageBInterpreterNativeBuildError(
                f"placeholder INT3 source: {item.relative_path}"
            )
    escaped = re.escape(entry_symbol)
    if not any(
        re.search(rf"(?m)^\s*_?{escaped}\s*:", text)
        or re.search(rf"\b{escaped}\s*\([^;{{}}]*\)\s*\{{", text)
        for text in source_texts
    ):
        raise StageBInterpreterNativeBuildError(
            f"native-engine package does not define payload entry {entry_symbol}"
        )

    owner_order = {
        "native_engine": 0,
        "interpreter": 1,
        "native_runtime": 2,
        "region_overrides": 3,
    }
    return tuple(
        sorted(
            selected,
            key=lambda item: (
                0 if item.path.suffix.lower() == ".s" else 1,
                owner_order[item.owner],
                item.relative_path,
            ),
        )
    )


def _canonical_source_root_label(owner: str) -> str:
    labels = {
        "interpreter": "interpreter",
        "native_engine": "engine",
        "native_runtime": "runtime",
        "region_overrides": "region-overrides",
    }
    try:
        return labels[owner]
    except KeyError as exc:
        raise StageBInterpreterNativeBuildError(
            f"unsupported native-build source owner: {owner}"
        ) from exc


def _native_bundle_path(artifact: _Artifact) -> str:
    relative = _relative_path(
        artifact.relative_path, f"{artifact.owner} bundle source path"
    )
    return (Path("roots") / artifact.owner / relative).as_posix()


def _native_row_artifacts(
    *, row: Mapping[str, Any], packages: Sequence[_Package]
) -> tuple[_Artifact, ...]:
    by_binding = {
        (artifact.owner, artifact.role, artifact.relative_path): artifact
        for package in packages
        for artifact in package.artifacts
    }
    raw = [row["source"], *row["dependencies"]]
    result: list[_Artifact] = []
    for binding in raw:
        key = (
            str(binding["owner"]),
            str(binding["role"]),
            str(binding["path"]),
        )
        artifact = by_binding.get(key)
        if artifact is None:
            raise StageBInterpreterNativeBuildError(
                "native object row references an unknown package artifact"
            )
        result.append(artifact)
    return tuple(result)


def _write_native_source_bundle(
    *, output: Path, row: Mapping[str, Any], artifacts: Sequence[_Artifact]
) -> dict[str, Any]:
    if not artifacts:
        raise StageBInterpreterNativeBuildError(
            "native source bundle has no source artifact"
        )
    unit_id = str(row["id"])
    if _C_IDENTIFIER.fullmatch(unit_id.replace("-", "_")) is None:
        raise StageBInterpreterNativeBuildError(
            "native source bundle unit ID is not path-safe"
        )
    bundle_path = Path("bundles") / unit_id
    bundle_root = output / bundle_path
    bundle_root.mkdir(parents=True, exist_ok=True)
    for artifact in artifacts:
        target = bundle_root / _native_bundle_path(artifact)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact.path, target)

    def normalized(binding: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "owner": str(binding["owner"]),
            "role": str(binding["role"]),
            "path": str(binding["path"]),
            "sha256": str(binding["sha256"]),
            "bundle_path": str(binding["bundle_path"]),
        }

    core = {
        "format": INTERPRETER_NATIVE_SOURCE_BUNDLE_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "unit_id": unit_id,
        "compile_key_sha256": str(row["compile_key_sha256"]),
        "source": normalized(row["source"]),
        "dependencies": [normalized(item) for item in row["dependencies"]],
        "language": str(row["language"]),
        "compiler": {
            key: value for key, value in row["compiler"].items() if key != "path"
        },
        "root_mappings": [dict(item) for item in row["root_mappings"]],
        "diagnostic_active": bool(row["diagnostic_active"]),
    }
    payload = {**core, "bundle_sha256": native_build._canonical_sha256(core)}
    manifest = bundle_root / "native-source-bundle.json"
    native_build._write_json(manifest, payload)
    return {
        "unit_id": unit_id,
        "compile_key_sha256": str(row["compile_key_sha256"]),
        "path": bundle_path.as_posix(),
        "manifest": manifest.name,
        "manifest_sha256": sha256_file(manifest),
        "bundle_sha256": payload["bundle_sha256"],
    }


def _load_native_source_bundle(
    value: Path | str,
) -> tuple[Path, dict[str, Any]]:
    path = Path(value)
    if path.is_dir():
        path = path / "native-source-bundle.json"
    payload = _read_json_object(path, "native source bundle")
    if payload.get("format") != INTERPRETER_NATIVE_SOURCE_BUNDLE_FORMAT:
        raise StageBInterpreterNativeBuildError(
            "unsupported native source bundle format"
        )
    core = dict(payload)
    expected = core.pop("bundle_sha256", None)
    if expected != native_build._canonical_sha256(core):
        raise StageBInterpreterNativeBuildError(
            "native source bundle self-hash is stale"
        )
    if payload.get("status") != "ready" or payload.get("executes_original_binary") is not False:
        raise StageBInterpreterNativeBuildError(
            "native source bundle is not ready"
        )
    dependencies = payload.get("dependencies")
    roots = payload.get("root_mappings")
    if not isinstance(dependencies, list) or not isinstance(roots, list) or not roots:
        raise StageBInterpreterNativeBuildError(
            "native source bundle inventories are malformed"
        )
    return path.parent, payload


def _bound_bundle_artifact(
    bundle_root: Path, binding: Mapping[str, Any], label: str
) -> Path:
    relative = _relative_path(binding.get("bundle_path"), f"{label} path")
    path = bundle_root / relative
    if not path.is_file():
        raise StageBInterpreterNativeBuildError(f"{label} is missing")
    try:
        path.resolve().relative_to(bundle_root.resolve())
    except ValueError as exc:
        raise StageBInterpreterNativeBuildError(
            f"{label} escapes its source bundle"
        ) from exc
    if sha256_file(path) != binding.get("sha256"):
        raise StageBInterpreterNativeBuildError(f"{label} binding is stale")
    return path


def _native_source_dependency_closure(
    source: _Artifact, packages: Sequence[_Package]
) -> tuple[_Artifact, ...]:
    """Resolve the exact transitive quoted-include closure for one source."""

    by_path: dict[Path, _Artifact] = {}
    roots = tuple(package.root.resolve() for package in packages)
    for package in packages:
        for artifact in package.artifacts:
            resolved = artifact.path.resolve()
            if resolved in by_path:
                raise StageBInterpreterNativeBuildError(
                    "native package artifacts resolve to the same source path"
                )
            by_path[resolved] = artifact

    dependencies: list[_Artifact] = []
    visited = {source.path.resolve()}
    pending = [source]
    while pending:
        current = pending.pop(0)
        try:
            lines = current.path.read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeError) as exc:
            raise StageBInterpreterNativeBuildError(
                f"native source is not readable ASCII: {current.relative_path}"
            ) from exc
        for line_number, line in enumerate(lines, start=1):
            directive = _INCLUDE_DIRECTIVE.match(line)
            if directive is None:
                continue
            operand = directive.group(1).strip()
            if _SYSTEM_INCLUDE.fullmatch(operand) is not None:
                continue
            quoted = _QUOTED_INCLUDE.fullmatch(operand)
            if quoted is None:
                raise StageBInterpreterNativeBuildError(
                    "native source uses an unsupported computed include at "
                    f"{current.relative_path}:{line_number}"
                )
            include = Path(quoted.group(1))
            if include.is_absolute() or ".." in include.parts:
                raise StageBInterpreterNativeBuildError(
                    "native source quoted include is not package-relative at "
                    f"{current.relative_path}:{line_number}"
                )
            candidates = (current.path.parent / include,) + tuple(
                root / include for root in roots
            )
            selected = next((path.resolve() for path in candidates if path.is_file()), None)
            if selected is None:
                raise StageBInterpreterNativeBuildError(
                    "native source quoted include is unresolved at "
                    f"{current.relative_path}:{line_number}: {include.as_posix()}"
                )
            dependency = by_path.get(selected)
            if dependency is None:
                raise StageBInterpreterNativeBuildError(
                    "native source quoted include is not content-bound by a package "
                    f"manifest: {include.as_posix()}"
                )
            if selected in visited:
                continue
            visited.add(selected)
            dependencies.append(dependency)
            pending.append(dependency)
    return tuple(dependencies)


def _uses_diagnostic_macro(artifacts: Sequence[_Artifact]) -> bool:
    for artifact in artifacts:
        try:
            if _DIAGNOSTIC_MACRO in artifact.path.read_text(encoding="ascii"):
                return True
        except (OSError, UnicodeError) as exc:
            raise StageBInterpreterNativeBuildError(
                f"native source is not readable ASCII: {artifact.relative_path}"
            ) from exc
    return False


def _native_object_graph_row(
    *,
    index: int,
    artifact: _Artifact,
    packages: Sequence[_Package],
    package_roots: Sequence[Path],
    compiler: Path,
    compiler_binding: Mapping[str, Any],
    diagnostic_failure_trap: bool,
    region_overrides: bool,
) -> dict[str, Any]:
    language = "assembler-with-cpp" if artifact.path.suffix.lower() == ".s" else "c"
    unit_id = f"{artifact.owner}-{artifact.role}"
    graph_relative = artifact.owner == "generated"
    source_argument = (
        artifact.relative_path if graph_relative else str(artifact.path)
    )
    dependencies = _native_source_dependency_closure(artifact, packages)
    diagnostic_sensitive = _uses_diagnostic_macro((artifact, *dependencies))
    diagnostic_active = diagnostic_failure_trap and diagnostic_sensitive
    compile_flags = _proof_profile_compile_flags(artifact.sha256)
    if diagnostic_active:
        compile_flags.append(f"-D{_DIAGNOSTIC_MACRO}=1")
    root_mappings = [
        {
            "owner": package.owner,
            "label": _canonical_source_root_label(package.owner),
        }
        for package in packages
    ]
    arguments = [
        "-x",
        language,
        "-c",
        source_argument,
        *sum((["-I", str(root)] for root in package_roots), []),
        *_compile_flags(
            artifact.sha256,
            package_roots,
            diagnostic_failure_trap=diagnostic_active,
        ),
    ]
    source_payload = {
        **artifact.payload(),
        "location": source_argument,
        "location_base": "graph" if graph_relative else "absolute",
        "bundle_path": _native_bundle_path(artifact),
    }
    dependency_payloads = [
        {
            **dependency.payload(),
            "location": str(dependency.path),
            "location_base": "absolute",
            "bundle_path": _native_bundle_path(dependency),
        }
        for dependency in dependencies
    ]
    compile_key_core = {
        "format": "stage-b-native-compile-key-v1",
        "source": artifact.payload(),
        "dependencies": [dependency.payload() for dependency in dependencies],
        "language": language,
        "compiler": {
            key: value
            for key, value in compiler_binding.items()
            if key != "path"
        },
        "compile_flags": compile_flags,
        "root_mappings": root_mappings,
    }
    unit_core = {
        "id": unit_id,
        "index": index,
        "source": source_payload,
        "dependencies": dependency_payloads,
        "language": language,
        "compiler": dict(compiler_binding),
        "arguments": arguments,
        "compile_flags": compile_flags,
        "root_mappings": root_mappings,
        "diagnostic_sensitive": diagnostic_sensitive,
        "diagnostic_active": diagnostic_active,
        "compile_key_sha256": native_build._canonical_sha256(compile_key_core),
        "canonical_flags": _canonical_compile_flags(
            artifact.sha256,
            diagnostic_failure_trap=diagnostic_active,
            region_overrides=region_overrides,
        ),
    }
    return {**unit_core, "unit_sha256": native_build._canonical_sha256(unit_core)}


def _native_compiler_binding(compiler: Path | str) -> dict[str, Any]:
    path = Path(compiler).resolve()
    if not path.is_file():
        raise StageBInterpreterNativeBuildError(f"native compiler does not exist: {path}")
    completed = subprocess.run(
        [str(path), "--version"], check=False, capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise StageBInterpreterNativeBuildError("native compiler version query failed")
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "version": completed.stdout.splitlines()[0].strip(),
    }


def _compile_flags(
    source_sha256: str,
    roots: Sequence[Path],
    *,
    diagnostic_failure_trap: bool = False,
) -> list[str]:
    flags = _proof_profile_compile_flags(source_sha256)
    if diagnostic_failure_trap:
        flags.append("-DSTAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP=1")
    labels = (
        "interpreter", "engine", "runtime", "region-overrides"
    )[:len(roots)]
    if len(labels) != len(roots):
        raise StageBInterpreterNativeBuildError(
            "unsupported native-build source-root inventory"
        )
    for label, root in zip(labels, roots, strict=True):
        for prefix in ("file", "debug", "macro"):
            flags.append(f"-f{prefix}-prefix-map={root}=/stage-b/{label}")
    return flags


def _canonical_compile_flags(
    source_sha256: str,
    *,
    diagnostic_failure_trap: bool = False,
    region_overrides: bool = False,
) -> list[str]:
    flags = _proof_profile_compile_flags(source_sha256)
    if diagnostic_failure_trap:
        flags.append("-DSTAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP=1")
    labels = ["interpreter", "engine", "runtime"]
    if region_overrides:
        labels.append("region-overrides")
    for label in labels:
        for prefix in ("file", "debug", "macro"):
            flags.append(
                f"-f{prefix}-prefix-map=<{label}-package>=/stage-b/{label}"
            )
    return flags


def _proof_profile_compile_flags(source_sha256: str) -> list[str]:
    """Use a deliberately transparent compiler profile for the proved baseline."""

    flags = [
        flag
        for flag in native_build._common_compile_flags(source_sha256)
        if flag != "-Os"
    ]
    flags.extend(("-O0", "-fno-inline", "-fno-omit-frame-pointer"))
    return flags
