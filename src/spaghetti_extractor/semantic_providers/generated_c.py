"""Compile immutable generated Behavioral C into one qualified provider.

This is a migration consumer of the existing Behavioral-C package.  It emits
only per-derived-function PE32 objects; dispatch and runtime support belong to
native realization and are derived later from implementation selection.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..candidate.formats import (
    BEHAVIORAL_C_BUILD_MANIFEST_FORMAT,
    BEHAVIORAL_C_LOWERING_FORMAT,
    BEHAVIORAL_C_PACKAGE_FORMAT,
    BEHAVIORAL_C_SOURCE_MAP_FORMAT,
)
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..util import sha256_file, write_json
from .qualification_v2 import write_semantic_provider_qualification_v2
from .slices_v2 import SemanticSliceV2, build_semantic_slice_v2


_QUOTED_INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"\s*$')


class GeneratedBehavioralCProviderError(ValueError):
    """Generated C cannot be bound to exact semantic definitions and objects."""


def _fail(message: str) -> None:
    raise GeneratedBehavioralCProviderError(message)


def _load(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    if not isinstance(value, dict):
        _fail(f"{context} must be an object")
    return value


def _manifest_sources(
    package: Path, manifest: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    rows = manifest.get("sources")
    if not isinstance(rows, list):
        _fail("Behavioral-C build manifest has no source inventory")
    result: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, Mapping):
            _fail("Behavioral-C source inventory is malformed")
        path = raw.get("path")
        digest = raw.get("sha256")
        role = raw.get("role")
        if (
            not isinstance(path, str) or not path
            or Path(path).name != path
            or not isinstance(digest, str)
            or not isinstance(role, str) or not role
            or path in result
        ):
            _fail("Behavioral-C source identity is malformed or duplicated")
        source = package / path
        if not source.is_file() or sha256_file(source) != digest:
            _fail(f"Behavioral-C source binding is stale: {path}")
        result[path] = dict(raw)
    return result


def _source_dependencies(
    filename: str, *, package: Path, sources: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    pending = [filename]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        row = sources.get(current)
        if row is None:
            _fail(f"generated source dependency is not content-bound: {current}")
        visited.add(current)
        for line in (package / current).read_text(encoding="ascii").splitlines():
            match = _QUOTED_INCLUDE.fullmatch(line)
            if match is None:
                continue
            dependency = match.group(1)
            if Path(dependency).name != dependency or dependency not in sources:
                _fail(
                    f"generated source include is outside its manifest: {dependency}"
                )
            pending.append(dependency)
    return sorted(str(sources[name]["sha256"]) for name in visited)


def _compile_flags(*, source_sha256: str, package: Path) -> tuple[list[str], list[str]]:
    common = [
        "-std=c11", "-g0", "-ffreestanding", "-fno-builtin", "-fno-ident",
        "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
        "-fno-stack-protector", "-fno-exceptions", "-O0", "-fno-inline",
        "-fno-omit-frame-pointer", f"-frandom-seed={source_sha256}",
    ]
    observed = [
        *common,
        f"-ffile-prefix-map={package}=/semantic-provider/generated-c",
        f"-fdebug-prefix-map={package}=/semantic-provider/generated-c",
        f"-fmacro-prefix-map={package}=/semantic-provider/generated-c",
    ]
    canonical = [
        *common,
        "-ffile-prefix-map=<behavioral-c-package>=/semantic-provider/generated-c",
        "-fdebug-prefix-map=<behavioral-c-package>=/semantic-provider/generated-c",
        "-fmacro-prefix-map=<behavioral-c-package>=/semantic-provider/generated-c",
    ]
    return observed, canonical


def _compile_function_source(
    item: tuple[str, Mapping[str, Any]], *, package: Path,
    compiler: Path, objects_root: Path,
) -> dict[str, Any]:
    filename, row = item
    object_path = objects_root / f"{Path(filename).stem}.o"
    observed_flags, canonical_flags = _compile_flags(
        source_sha256=str(row["sha256"]), package=package,
    )
    environment = dict(os.environ)
    environment.update({
        "LC_ALL": "C.UTF-8", "PYTHONHASHSEED": "0",
        "SOURCE_DATE_EPOCH": "1",
    })
    try:
        subprocess.run([
            str(compiler), "-x", "c", "-c", str(package / filename),
            "-I", str(package), "-o", str(object_path), *observed_flags,
        ], check=True, env=environment)
    except (OSError, subprocess.CalledProcessError) as exc:
        _fail(f"generated-C provider compilation failed for {filename}: {exc}")
    return {
        "source": filename,
        "source_role": row["role"],
        "source_sha256": row["sha256"],
        "object": f"objects/{object_path.name}",
        "object_sha256": sha256_file(object_path),
        "language": "c",
        "flags": canonical_flags,
    }


def _materialize_generated_functions(
    *, behavioral_c_package: Path, compiler: Path, out: Path,
    expected_symbols: set[str],
) -> dict[str, Any]:
    """Validate one package and compile exactly the requested transfer bodies."""

    package = Path(behavioral_c_package)
    manifest_path = package / "behavioral-c-build-manifest.json"
    source_map_path = package / "behavioral-c-source-map.json"
    lowering_path = package / "behavioral-c-lowering.json"
    package_path = package / "behavioral-c-package.json"
    package_payload = _load(package_path, "Behavioral-C package")
    manifest = _load(manifest_path, "Behavioral-C build manifest")
    source_map = _load(source_map_path, "Behavioral-C source map")
    lowering = _load(lowering_path, "Behavioral-C lowering")
    if (
        package_payload.get("format") != BEHAVIORAL_C_PACKAGE_FORMAT
        or package_payload.get("status") != "ready"
        or manifest.get("format") != BEHAVIORAL_C_BUILD_MANIFEST_FORMAT
        or manifest.get("status") != "complete"
        or source_map.get("format") != BEHAVIORAL_C_SOURCE_MAP_FORMAT
        or source_map.get("status") != "complete"
        or lowering.get("format") != BEHAVIORAL_C_LOWERING_FORMAT
        or lowering.get("status") != "complete"
    ):
        _fail("generated Behavioral-C inputs are incomplete")
    sources = _manifest_sources(package, manifest)
    units = source_map.get("units")
    if not isinstance(units, list):
        _fail("Behavioral-C source map has no unit inventory")
    selected_units: list[Mapping[str, Any]] = []
    for raw in units:
        if not isinstance(raw, Mapping):
            _fail("Behavioral-C source-map unit is malformed")
        unit_id = raw.get("unit_id")
        if not isinstance(unit_id, str) or not unit_id:
            _fail("Behavioral-C source-map unit identity is malformed")
        symbol_id = f"original:function:{unit_id}"
        if symbol_id not in expected_symbols:
            continue
        filename = raw.get("file")
        native_symbol = raw.get("symbol")
        if (
            not isinstance(filename, str) or filename not in sources
            or not filename.startswith("behavioral-fn-")
            or not filename.endswith(".c")
            or not isinstance(native_symbol, str) or not native_symbol
        ):
            _fail(f"generated-C source map is malformed for {symbol_id}")
        selected_units.append(raw)
    selected_ids = {
        f"original:function:{raw['unit_id']}" for raw in selected_units
    }
    if selected_ids != expected_symbols:
        _fail("generated-C provider does not cover every linked transfer definition")
    selected_filenames = {str(raw["file"]) for raw in selected_units}
    compiler_path = Path(compiler)
    if not compiler_path.is_file():
        _fail("generated-C provider compiler is unavailable")
    try:
        compiler_version = subprocess.run(
            [str(compiler_path), "--version"], check=True,
            capture_output=True, text=True,
        ).stdout.splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError) as exc:
        _fail(f"cannot identify generated-C provider compiler: {exc}")

    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    os.symlink(
        package.resolve(), output / "behavioral-c-package",
        target_is_directory=True,
    )
    objects_root = output / "objects"
    objects_root.mkdir(parents=True, exist_ok=True)
    function_sources = [
        (filename, row) for filename, row in sorted(sources.items())
        if filename in selected_filenames
    ]
    if not function_sources:
        _fail("generated-C provider compiled no behavioral functions")
    worker_count = min(len(function_sources), os.cpu_count() or 1)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        object_rows = list(executor.map(
            lambda item: _compile_function_source(
                item, package=package, compiler=compiler_path,
                objects_root=objects_root,
            ),
            function_sources,
        ))
    objects_by_source = {
        str(row["source"]): str(row["object_sha256"])
        for row in object_rows
    }
    compile_core = {
        "compiler_sha256": sha256_file(compiler_path),
        "compiler_version": compiler_version,
        "target": "i686-w64-mingw32",
        "objects": object_rows,
    }
    compile_receipt = {
        **compile_core,
        "receipt_sha256": canonical_sha256_v3(compile_core),
    }
    compile_receipt_path = output / "compile-receipt.json"
    write_json(compile_receipt_path, compile_receipt)
    compile_receipt_sha256 = sha256_file(compile_receipt_path)
    facets = [
        {
            "name": "compile", "status": "checked",
            "receipt_sha256": compile_receipt_sha256,
        },
        {
            "name": "native_objects", "status": "checked",
            "receipt_sha256": compile_receipt_sha256,
        },
        {
            "name": "ownership", "status": "checked",
            "receipt_sha256": sha256_file(source_map_path),
        },
        {
            "name": "semantic_lowering", "status": "checked",
            "receipt_sha256": sha256_file(lowering_path),
        },
        {
            "name": "source", "status": "checked",
            "receipt_sha256": sha256_file(manifest_path),
        },
    ]
    return {
        "package": package,
        "sources": sources,
        "selected_units": selected_units,
        "objects_by_source": objects_by_source,
        "facets": facets,
        "compile_receipt_sha256": compile_receipt_sha256,
        "compiler_sha256": compile_core["compiler_sha256"],
    }


def write_generated_behavioral_c_provider_v2(
    *, linked_semantic_module: Path, behavioral_c_package: Path,
    compiler: Path, provider_id: str, out: Path,
) -> dict[str, Any]:
    """Compile every conservative transfer definition into one V2 provider."""

    linked = LinkedSemanticModuleV2.load(
        Path(linked_semantic_module), require_complete=False,
    )
    definitions_by_symbol = {
        str(row["symbol_id"]): row for row in linked.payload["definitions"]
    }
    requirements = {
        str(row["symbol_id"]): row
        for row in linked.payload["definition_requirements"]
    }
    expected = {
        symbol_id for symbol_id, requirement in requirements.items()
        if "generated_behavioral_c" in requirement["allowed_provider_kinds"]
    }
    if any(
        definitions_by_symbol[symbol_id]["definition_kind"] != "transfer_v2"
        for symbol_id in expected
    ):
        _fail("generated-C V2 provider was offered a non-transfer definition")
    materialized = _materialize_generated_functions(
        behavioral_c_package=behavioral_c_package, compiler=compiler, out=out,
        expected_symbols=expected,
    )
    definition_rows: list[dict[str, Any]] = []
    definition_ids: list[str] = []
    choices: dict[str, str] = {}
    for raw in materialized["selected_units"]:
        filename = str(raw["file"])
        symbol_id = f"original:function:{raw['unit_id']}"
        definition_id = str(definitions_by_symbol[symbol_id]["definition_id"])
        definition_ids.append(definition_id)
        choices[definition_id] = provider_id
        definition_rows.append({
            "definition_id": definition_id,
            "native_symbol": str(raw["symbol"]),
            "source_sha256s": _source_dependencies(
                filename, package=materialized["package"],
                sources=materialized["sources"],
            ),
            "object_sha256s": [
                materialized["objects_by_source"][filename]
            ],
        })
    semantic_slice = SemanticSliceV2.parse(build_semantic_slice_v2(
        linked_semantic_module=linked, definition_ids=definition_ids,
    ))
    output = Path(out)
    qualification_path = output / "semantic-provider-qualification.json"
    write_semantic_provider_qualification_v2(
        semantic_slice=semantic_slice,
        provider_id=provider_id,
        provider_kind="generated_behavioral_c",
        provider_artifact_sha256=materialized["compile_receipt_sha256"],
        facets=materialized["facets"],
        definition_materializations=definition_rows,
        tool_sha256s=[materialized["compiler_sha256"]],
        out=qualification_path,
    )
    write_json(output / "definition-choices.json", choices)
    return _load(qualification_path, "generated-C V2 provider qualification")


__all__ = [
    "GeneratedBehavioralCProviderError",
    "write_generated_behavioral_c_provider_v2",
]
