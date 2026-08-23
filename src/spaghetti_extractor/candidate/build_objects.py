"""Object receipts, linked-symbol evidence, and output helpers for native builds."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from ..util import sha256_file
from . import native_build
from .build_model import (
    INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT,
    INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT,
    CandidateNativeBuildError,
    _Artifact,
    _PAYLOAD_SYMBOL,
    _Package,
)
from .build_sources import (
    _load_native_source_bundle,
    _native_compiler_binding,
    _native_object_graph_row,
)
from .build_values import (
    _file,
    _read_json_object,
    _relative_path,
    _u32,
)


def _load_native_object_graph(value: Path | str) -> tuple[Path, dict[str, Any]]:
    path = Path(value)
    if path.is_dir():
        path = path / "native-object-graph.json"
    payload = _read_json_object(path, "native object graph")
    if payload.get("format") != INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT:
        raise CandidateNativeBuildError("unsupported native object graph format")
    core = dict(payload)
    expected = core.pop("graph_sha256", None)
    if expected != native_build._canonical_sha256(core):
        raise CandidateNativeBuildError("native object graph self-hash is stale")
    units = payload.get("units")
    if not isinstance(units, list) or not units:
        raise CandidateNativeBuildError("native object graph has no compile units")
    seen: set[str] = set()
    for row in units:
        if not isinstance(row, Mapping):
            raise CandidateNativeBuildError("native object graph unit is malformed")
        unit_id = str(row.get("id"))
        if unit_id in seen:
            raise CandidateNativeBuildError("native object graph has duplicate unit IDs")
        seen.add(unit_id)
        unit_core = dict(row)
        unit_expected = unit_core.pop("unit_sha256", None)
        if unit_expected != native_build._canonical_sha256(unit_core):
            raise CandidateNativeBuildError("native object graph unit self-hash is stale")
    bundles = payload.get("bundles")
    if not isinstance(bundles, list) or len(bundles) != len(units):
        raise CandidateNativeBuildError(
            "native object graph source-bundle inventory is incomplete"
        )
    bundle_ids: set[str] = set()
    by_id = {str(row["id"]): row for row in units}
    for binding in bundles:
        if not isinstance(binding, Mapping):
            raise CandidateNativeBuildError(
                "native object graph source-bundle binding is malformed"
            )
        unit_id = str(binding.get("unit_id"))
        if unit_id in bundle_ids or unit_id not in by_id:
            raise CandidateNativeBuildError(
                "native object graph source-bundle unit binding is invalid"
            )
        bundle_ids.add(unit_id)
        if binding.get("compile_key_sha256") != by_id[unit_id]["compile_key_sha256"]:
            raise CandidateNativeBuildError(
                "native object graph source-bundle compile key is stale"
            )
        bundle_root = path.parent / _relative_path(
            binding.get("path"), "native source bundle graph path"
        )
        manifest = bundle_root / str(binding.get("manifest"))
        if (
            not manifest.is_file()
            or sha256_file(manifest) != binding.get("manifest_sha256")
        ):
            raise CandidateNativeBuildError(
                "native object graph source-bundle manifest is stale"
            )
        _, bundle = _load_native_source_bundle(manifest)
        if (
            bundle.get("unit_id") != unit_id
            or bundle.get("compile_key_sha256")
            != binding.get("compile_key_sha256")
            or bundle.get("bundle_sha256") != binding.get("bundle_sha256")
        ):
            raise CandidateNativeBuildError(
                "native object graph source-bundle content binding is stale"
            )
    return path, payload


def _load_precompiled_native_objects(
    value: Path | str,
    *,
    compile_units: Sequence[_Artifact],
    package_roots: Sequence[Path],
    package_sequence: Sequence[_Package],
    packages: Mapping[str, Any],
    compiler: Path,
    entry_symbol: str,
    relocation_digest: str,
) -> list[tuple[dict[str, Any], Path]]:
    path = Path(value)
    if path.is_dir():
        path = path / "native-object-package.json"
    payload = _read_json_object(path, "native object package")
    if payload.get("format") != INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT:
        raise CandidateNativeBuildError("unsupported native object package format")
    core = dict(payload)
    expected_hash = core.pop("package_sha256", None)
    if expected_hash != native_build._canonical_sha256(core):
        raise CandidateNativeBuildError("native object package self-hash is stale")
    if (
        payload.get("status") != "complete"
        or payload.get("executes_original_binary") is not False
        or payload.get("packages") != packages
        or payload.get("compiler") != _native_compiler_binding(compiler)
        or payload.get("entry_symbol") != entry_symbol
    ):
        raise CandidateNativeBuildError("native object package build binding is stale")
    units = payload.get("units")
    objects = payload.get("objects")
    if (
        not isinstance(units, list)
        or not isinstance(objects, list)
        or len(units) != len(compile_units) + 1
        or len(objects) != len(units)
    ):
        raise CandidateNativeBuildError("native object package inventory is incomplete")
    graph_binding = payload.get("graph")
    if not isinstance(graph_binding, Mapping):
        raise CandidateNativeBuildError("native object package graph binding is missing")
    bound_graph_path = Path(str(graph_binding.get("path"))) / str(
        graph_binding.get("manifest")
    )
    if (
        not bound_graph_path.is_file()
        or sha256_file(bound_graph_path) != graph_binding.get("manifest_sha256")
        or graph_binding.get("manifest_sha256") != payload.get("graph_artifact_sha256")
    ):
        raise CandidateNativeBuildError("native object package graph artifact is stale")
    relocation_location = Path(str(units[-1].get("source", {}).get("location")))
    graph_relocation_source = _file(
        bound_graph_path.parent / relocation_location
        if units[-1].get("source", {}).get("location_base") == "graph"
        else relocation_location,
        "cached relocation-anchor source",
    )
    if sha256_file(graph_relocation_source) != relocation_digest:
        raise CandidateNativeBuildError(
            "native object package relocation-anchor binding is stale"
        )
    expected_artifacts = [
        *compile_units,
        _Artifact(
            owner="generated",
            role="payload_relocation_anchor",
            relative_path=graph_relocation_source.name,
            sha256=relocation_digest,
            path=graph_relocation_source,
        ),
    ]
    region_overrides = packages.get("region_overrides") is not None
    compiler_binding = _native_compiler_binding(compiler)
    expected_rows = [
        _native_object_graph_row(
            index=index,
            artifact=artifact,
            packages=package_sequence,
            package_roots=package_roots,
            compiler=compiler,
            compiler_binding=compiler_binding,
            region_overrides=region_overrides,
        )
        for index, artifact in enumerate(expected_artifacts)
    ]
    if units != expected_rows:
        raise CandidateNativeBuildError(
            "native object package compile-unit definitions are stale"
        )
    package_root = path.parent
    result: list[tuple[dict[str, Any], Path]] = []
    for expected_row, object_row in zip(expected_rows, objects, strict=True):
        if (
            not isinstance(object_row, Mapping)
            or object_row.get("unit_id") != expected_row["id"]
            or object_row.get("compile_key_sha256")
            != expected_row["compile_key_sha256"]
        ):
            raise CandidateNativeBuildError("native object package unit binding is stale")
        object_path = package_root / str(object_row.get("path"))
        if not object_path.is_file() or sha256_file(object_path) != object_row.get("sha256"):
            raise CandidateNativeBuildError("native object package artifact is stale")
        result.append((expected_row, object_path))
    return result


def _payload_symbol_rvas(linker_map: Path, *, image_base: int) -> dict[str, int]:
    try:
        text = linker_map.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise CandidateNativeBuildError(
            f"cannot read payload linker map: {exc}"
        ) from exc
    result: dict[str, int] = {}
    for match in _PAYLOAD_SYMBOL.finditer(text):
        address = int(match.group(1), 16)
        if address < image_base:
            raise CandidateNativeBuildError(
                f"payload symbol {match.group(2)} lies below the image base"
            )
        name = match.group(2).removeprefix("_")
        rva = _u32(address - image_base, f"payload symbol {name} RVA")
        previous = result.setdefault(name, rva)
        if previous != rva:
            raise CandidateNativeBuildError(
                f"payload linker map gives ambiguous addresses for {name}"
            )
    return result


def _output_binding(path: Path, root: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _compiler_runtime(compiler: Path) -> Path:
    try:
        value = native_build._tool_output(
            [str(compiler), "-print-libgcc-file-name"]
        )
    except native_build.CandidateNativeBuildError as exc:
        raise CandidateNativeBuildError(
            f"cannot locate the compiler runtime: {exc}"
        ) from exc
    path = Path(value).resolve()
    if not path.is_file():
        raise CandidateNativeBuildError(
            f"compiler runtime does not exist: {path}"
        )
    return path
