"""Build a freestanding PE32 candidate from Stage B interpreter packages.

This module is candidate-generation infrastructure only.  It validates and
content-binds the semantic interpreter, native engine, and native runtime,
then uses the shared native-build qualification and PE-composition machinery.
Nothing emitted here qualifies the resulting candidate.
"""

from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import stage_b_native_build as native_build
from .artifact_formats import (
    INTERPRETER_NATIVE_BUILD_FORMAT,
    NATIVE_ENGINE_PACKAGE_FORMAT,
)
from .roundtrip_fuzz.image_contract import load_stage_a_load_image_contract
from .region_replacement import REGION_OVERRIDE_TABLE_FORMAT
from .stage_b_interpreter_backend import STAGE_B_INTERPRETER_PACKAGE_FORMAT
from .stage_b_native_runtime import (
    NATIVE_RUNTIME_MANIFEST_FILENAME,
    NATIVE_RUNTIME_PACKAGE_FORMAT,
    plan_stage_b_native_runtime,
)
from .stage_b_pe_composer import (
    CANDIDATE_FILENAME,
    COMPOSITION_MANIFEST_FILENAME,
    EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
    ExecutableAnchor,
    ExecutableAnchorManifest,
    compose_stage_b_pe,
)
from .util import sha256_file


INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME = "interpreter-native-build-manifest.json"
INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT = "stage-b-interpreter-native-object-graph-v2"
INTERPRETER_NATIVE_OBJECT_FORMAT = "stage-b-interpreter-native-object-v2"
INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT = "stage-b-interpreter-native-object-package-v2"

_INTERPRETER_MANIFEST_FILENAME = "state-machine-interpreter-package.json"
_ENGINE_MANIFEST_FILENAME = "native-engine-package.json"
_PAYLOAD_FILENAME = native_build.PAYLOAD_FILENAME
_PAYLOAD_MAP_FILENAME = native_build.PAYLOAD_MAP_FILENAME
_ENGINE_LAYOUT_FILENAME = native_build.ENGINE_LAYOUT_FILENAME
_RELOCATION_INVENTORY_FILENAME = native_build.PAYLOAD_RELOCATION_INVENTORY_FILENAME
_GENERATED_ANCHOR_FILENAME = "executable-anchor-manifest.json"
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_INCLUDE_DIRECTIVE = re.compile(r'^\s*#\s*include\s+(.+?)\s*(?://.*)?$')
_QUOTED_INCLUDE = re.compile(r'^"([^"\r\n]+)"(?:\s*/\*.*\*/\s*)?$')
_SYSTEM_INCLUDE = re.compile(r"^<[^>\r\n]+>(?:\s*/\*.*\*/\s*)?$")
_DIAGNOSTIC_MACRO = "STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP"
_PAYLOAD_SYMBOL = re.compile(
    r"(?m)^\s*(0x[0-9a-fA-F]+)\s+(_?stage_b_payload_(?:entry|callback_[0-9a-fA-F]{8}))\b"
)


class StageBInterpreterNativeBuildError(ValueError):
    """An interpreter-native candidate input or output failed validation."""


@dataclass(frozen=True)
class _Artifact:
    owner: str
    role: str
    relative_path: str
    sha256: str
    path: Path

    def payload(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "role": self.role,
            "path": self.relative_path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class _Package:
    owner: str
    root: Path
    manifest_path: Path
    manifest_sha256: str
    payload: Mapping[str, Any]
    artifacts: tuple[_Artifact, ...]

    def binding(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest_path.name,
            "manifest_sha256": self.manifest_sha256,
            "artifacts": [item.payload() for item in self.artifacts],
        }


def prepare_stage_b_interpreter_native_object_graph(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    native_runtime_package: Path | str,
    out_dir: Path | str,
    region_override_package: Path | str | None = None,
    compiler: Path | str = "i686-w64-mingw32-gcc",
    entry_symbol: str = "stage_b_payload_entry",
    diagnostic_failure_trap: bool = False,
) -> dict[str, Any]:
    """Emit a deterministic per-source compile graph for Nix CA derivations."""

    if _C_IDENTIFIER.fullmatch(entry_symbol) is None:
        raise StageBInterpreterNativeBuildError(
            "payload entry symbol is not a C identifier"
        )
    interpreter = _load_package(
        interpreter_package,
        filename=_INTERPRETER_MANIFEST_FILENAME,
        owner="interpreter",
        expected_format=STAGE_B_INTERPRETER_PACKAGE_FORMAT,
        require_roles=True,
    )
    engine = _load_package(
        native_engine_package,
        filename=_ENGINE_MANIFEST_FILENAME,
        owner="native_engine",
        expected_format=NATIVE_ENGINE_PACKAGE_FORMAT,
        require_roles=False,
    )
    runtime = _load_package(
        native_runtime_package,
        filename=NATIVE_RUNTIME_MANIFEST_FILENAME,
        owner="native_runtime",
        expected_format=NATIVE_RUNTIME_PACKAGE_FORMAT,
        require_roles=True,
    )
    _validate_package_closure(interpreter, engine, runtime)
    region_overrides = (
        None
        if region_override_package is None
        else _load_region_override_package(region_override_package)
    )
    if region_overrides is not None:
        _validate_region_override_closure(interpreter, region_overrides)
    compile_units = _compile_units(
        interpreter, engine, runtime, entry_symbol, region_overrides
    )
    toolchain = native_build._select_toolchain(compiler)
    compiler_binding = _native_compiler_binding(toolchain.compiler)
    packages = (
        interpreter,
        engine,
        runtime,
        *((region_overrides,) if region_overrides is not None else ()),
    )
    package_roots = tuple(package.root for package in packages)
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for index, artifact in enumerate(compile_units):
        rows.append(
            _native_object_graph_row(
                index=index,
                artifact=artifact,
                packages=packages,
                package_roots=package_roots,
                compiler=toolchain.compiler,
                compiler_binding=compiler_binding,
                diagnostic_failure_trap=diagnostic_failure_trap,
                region_overrides=region_overrides is not None,
            )
        )
    relocation_source = output / "payload-relocation-anchor.S"
    relocation_source.write_text(
        native_build._relocation_anchor_source(entry_symbol), encoding="ascii"
    )
    relocation_artifact = _Artifact(
        owner="generated",
        role="payload_relocation_anchor",
        relative_path=relocation_source.name,
        sha256=sha256_file(relocation_source),
        path=relocation_source,
    )
    rows.append(
        _native_object_graph_row(
            index=len(rows),
            artifact=relocation_artifact,
            packages=packages,
            package_roots=package_roots,
            compiler=toolchain.compiler,
            compiler_binding=compiler_binding,
            diagnostic_failure_trap=diagnostic_failure_trap,
            region_overrides=region_overrides is not None,
        )
    )
    core = {
        "format": INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "entry_symbol": entry_symbol,
        "diagnostic_failure_trap": diagnostic_failure_trap,
        "compiler": compiler_binding,
        "packages": {
            "interpreter": interpreter.binding(),
            "native_engine": engine.binding(),
            "native_runtime": runtime.binding(),
            "region_overrides": (
                None if region_overrides is None else region_overrides.binding()
            ),
        },
        "units": rows,
        "counts": {"compile_units": len(rows)},
    }
    payload = {**core, "graph_sha256": native_build._canonical_sha256(core)}
    native_build._write_json(output / "native-object-graph.json", payload)
    return payload


def compile_stage_b_interpreter_native_object(
    *, graph: Path | str, unit_id: str, out_dir: Path | str
) -> dict[str, Any]:
    """Compile exactly one graph unit and bind the object to its checked row."""

    graph_path, graph_payload = _load_native_object_graph(graph)
    matches = [row for row in graph_payload["units"] if row.get("id") == unit_id]
    if len(matches) != 1:
        raise StageBInterpreterNativeBuildError(
            f"native object graph has {len(matches)} matches for {unit_id}"
        )
    row = matches[0]
    source_value = Path(str(row["source"]["location"]))
    source = _file(
        graph_path.parent / source_value
        if row["source"].get("location_base") == "graph"
        else source_value,
        "native object source",
    )
    if sha256_file(source) != row["source"]["sha256"]:
        raise StageBInterpreterNativeBuildError("native object source binding is stale")
    compiler = _file(row["compiler"]["path"], "native object compiler")
    if _native_compiler_binding(compiler) != row["compiler"]:
        raise StageBInterpreterNativeBuildError("native object compiler binding is stale")
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    object_path = output / "object.o"
    command = [str(compiler), *row["arguments"], "-o", str(object_path)]
    try:
        native_build._run(
            command,
            phase=f"compile cached {row['source']['owner']}:{row['source']['role']}",
            env=native_build._deterministic_environment(),
            cwd=graph_path.parent,
        )
    except native_build.StageBNativeBuildError as exc:
        raise StageBInterpreterNativeBuildError(str(exc)) from exc
    if not object_path.is_file():
        raise StageBInterpreterNativeBuildError("compiler omitted cached native object")
    core = {
        "format": INTERPRETER_NATIVE_OBJECT_FORMAT,
        "status": "compiled",
        "executes_original_binary": False,
        "unit_id": unit_id,
        "compile_key_sha256": row["compile_key_sha256"],
        "object": {
            "path": object_path.name,
            "sha256": sha256_file(object_path),
            "size": object_path.stat().st_size,
        },
    }
    payload = {**core, "object_receipt_sha256": native_build._canonical_sha256(core)}
    native_build._write_json(output / "native-object.json", payload)
    return payload


def assemble_stage_b_interpreter_native_objects(
    *,
    graph: Path | str,
    object_packages: Sequence[Path | str],
    out_dir: Path | str,
) -> dict[str, Any]:
    """Assemble a complete ordered object package without recompilation."""

    graph_path, graph_payload = _load_native_object_graph(graph)
    receipts: dict[str, tuple[Path, dict[str, Any]]] = {}
    for value in object_packages:
        root = Path(value)
        receipt_path = root / "native-object.json" if root.is_dir() else root
        receipt = _read_json_object(receipt_path, "native object receipt")
        core = dict(receipt)
        expected = core.pop("object_receipt_sha256", None)
        if expected != native_build._canonical_sha256(core):
            raise StageBInterpreterNativeBuildError("native object receipt self-hash is stale")
        unit_id = str(receipt.get("unit_id"))
        if unit_id in receipts:
            raise StageBInterpreterNativeBuildError("duplicate native object receipt")
        if receipt.get("format") != INTERPRETER_NATIVE_OBJECT_FORMAT:
            raise StageBInterpreterNativeBuildError("unsupported native object receipt format")
        receipts[unit_id] = (receipt_path.parent, receipt)
    expected_ids = [str(row["id"]) for row in graph_payload["units"]]
    if set(receipts) != set(expected_ids):
        raise StageBInterpreterNativeBuildError(
            "native object receipts do not exactly cover the compile graph"
        )
    output = Path(out_dir)
    objects_dir = output / "objects"
    objects_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    by_id = {str(row["id"]): row for row in graph_payload["units"]}
    for index, unit_id in enumerate(expected_ids):
        root, receipt = receipts[unit_id]
        graph_row = by_id[unit_id]
        if receipt.get("compile_key_sha256") != graph_row["compile_key_sha256"]:
            raise StageBInterpreterNativeBuildError("native object compile-key binding is stale")
        source = root / str(receipt["object"]["path"])
        if not source.is_file() or sha256_file(source) != receipt["object"]["sha256"]:
            raise StageBInterpreterNativeBuildError("native object artifact binding is stale")
        target = objects_dir / f"{index:03d}.o"
        shutil.copyfile(source, target)
        rows.append(
            {
                "unit_id": unit_id,
                "compile_key_sha256": graph_row["compile_key_sha256"],
                "path": target.relative_to(output).as_posix(),
                "sha256": sha256_file(target),
                "size": target.stat().st_size,
            }
        )
    core = {
        "format": INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT,
        "status": "complete",
        "executes_original_binary": False,
        "graph_sha256": graph_payload["graph_sha256"],
        "graph_artifact_sha256": sha256_file(graph_path),
        "graph": {
            "path": str(graph_path.parent),
            "manifest": graph_path.name,
            "manifest_sha256": sha256_file(graph_path),
        },
        "compiler": graph_payload["compiler"],
        "packages": graph_payload["packages"],
        "entry_symbol": graph_payload["entry_symbol"],
        "diagnostic_failure_trap": graph_payload["diagnostic_failure_trap"],
        "units": graph_payload["units"],
        "objects": rows,
        "counts": {"objects": len(rows)},
    }
    payload = {**core, "package_sha256": native_build._canonical_sha256(core)}
    native_build._write_json(output / "native-object-package.json", payload)
    return payload


def build_stage_b_interpreter_native_candidate(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    native_runtime_package: Path | str,
    region_override_package: Path | str | None = None,
    load_image_contract: Path | str,
    out_dir: Path | str,
    anchor_manifest: Path | str | None = None,
    compiler: Path | str = "i686-w64-mingw32-gcc",
    entry_symbol: str = "stage_b_payload_entry",
    payload_rva: int | None = None,
    diagnostic_failure_trap: bool = False,
    precompiled_objects: Path | str | None = None,
) -> dict[str, Any]:
    """Compile, qualify, and compose one interpreter-backed PE32 candidate."""

    if not isinstance(diagnostic_failure_trap, bool):
        raise StageBInterpreterNativeBuildError(
            "diagnostic_failure_trap must be a boolean"
        )
    if _C_IDENTIFIER.fullmatch(entry_symbol) is None:
        raise StageBInterpreterNativeBuildError(
            "payload entry symbol is not a C identifier"
        )

    interpreter = _load_package(
        interpreter_package,
        filename=_INTERPRETER_MANIFEST_FILENAME,
        owner="interpreter",
        expected_format=STAGE_B_INTERPRETER_PACKAGE_FORMAT,
        require_roles=True,
    )
    engine = _load_package(
        native_engine_package,
        filename=_ENGINE_MANIFEST_FILENAME,
        owner="native_engine",
        expected_format=NATIVE_ENGINE_PACKAGE_FORMAT,
        require_roles=False,
    )
    runtime = _load_package(
        native_runtime_package,
        filename=NATIVE_RUNTIME_MANIFEST_FILENAME,
        owner="native_runtime",
        expected_format=NATIVE_RUNTIME_PACKAGE_FORMAT,
        require_roles=True,
    )
    runtime_plan = _validate_package_closure(interpreter, engine, runtime)
    region_overrides = (
        None
        if region_override_package is None
        else _load_region_override_package(region_override_package)
    )
    if region_overrides is not None:
        _validate_region_override_closure(interpreter, region_overrides)
    compile_units = _compile_units(
        interpreter, engine, runtime, entry_symbol, region_overrides
    )

    contract_path = _file(load_image_contract, "load-image contract")
    contract_artifact_sha256 = sha256_file(contract_path)
    contract = load_stage_a_load_image_contract(contract_path)
    native_build._require_pe32_contract(contract)
    anchor_path: Path | None = None
    anchors: ExecutableAnchorManifest | None = None
    anchor_artifact_sha256: str | None = None
    if anchor_manifest is not None:
        anchor_path = _file(anchor_manifest, "executable-anchor manifest")
        anchor_artifact_sha256 = sha256_file(anchor_path)
        try:
            anchors = ExecutableAnchorManifest.parse(
                _read_json_object(anchor_path, "executable-anchor manifest")
            )
        except Exception as exc:
            raise StageBInterpreterNativeBuildError(str(exc)) from exc
        if anchors.image_base != contract.identity.preferred_base:
            raise StageBInterpreterNativeBuildError(
                "executable-anchor manifest image base differs from the load-image contract"
            )

    header_pe = native_build._pe(
        contract.runtime_headers.data, "load-image runtime headers"
    )
    optional = native_build._optional_header(header_pe)
    candidate_dynamic_base = bool(
        int(optional.DllCharacteristics)
        & native_build._IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    )
    original_relocation_directory = optional.DATA_DIRECTORY[5]
    candidate_runtime_relocations = bool(
        int(original_relocation_directory.VirtualAddress)
        or int(original_relocation_directory.Size)
    ) and not bool(
        int(native_build._file_header(header_pe).Characteristics)
        & native_build._IMAGE_FILE_RELOCS_STRIPPED
    )
    section_alignment = int(optional.SectionAlignment)
    file_alignment = int(optional.FileAlignment)
    header_pe.close()
    minimum_rva = _align_up(contract.identity.image_size, section_alignment)
    selected_rva = minimum_rva if payload_rva is None else _u32(payload_rva, "payload RVA")
    if selected_rva < minimum_rva or selected_rva % section_alignment:
        raise StageBInterpreterNativeBuildError(
            "payload RVA must be section-aligned and outside the contracted image"
        )

    toolchain = native_build._select_toolchain(compiler)
    compiler_runtime = _compiler_runtime(toolchain.compiler)
    compiler_runtime_sha256 = sha256_file(compiler_runtime)
    output = Path(out_dir)
    objects = output / "objects"
    output.mkdir(parents=True, exist_ok=True)
    objects.mkdir(parents=True, exist_ok=True)
    environment = native_build._deterministic_environment()

    object_paths: list[Path] = []
    object_rows: list[dict[str, Any]] = []
    package_roots = (
        interpreter.root,
        engine.root,
        runtime.root,
        *((region_overrides.root,) if region_overrides is not None else ()),
    )
    package_sequence = (
        interpreter,
        engine,
        runtime,
        *((region_overrides,) if region_overrides is not None else ()),
    )
    relocation_source = output / ".payload-relocation-anchor.S"
    relocation_source.write_text(
        native_build._relocation_anchor_source(entry_symbol), encoding="ascii"
    )
    relocation_digest = sha256_file(relocation_source)
    precompiled_object_binding: dict[str, Any] | None = None
    if precompiled_objects is not None:
        precompiled_manifest = Path(precompiled_objects)
        if precompiled_manifest.is_dir():
            precompiled_manifest = precompiled_manifest / "native-object-package.json"
        cached = _load_precompiled_native_objects(
            precompiled_objects,
            compile_units=compile_units,
            package_roots=package_roots,
            package_sequence=package_sequence,
            packages={
                "interpreter": interpreter.binding(),
                "native_engine": engine.binding(),
                "native_runtime": runtime.binding(),
                "region_overrides": (
                    None if region_overrides is None else region_overrides.binding()
                ),
            },
            compiler=toolchain.compiler,
            entry_symbol=entry_symbol,
            diagnostic_failure_trap=diagnostic_failure_trap,
            relocation_digest=relocation_digest,
        )
        precompiled_object_binding = {
            "artifact_sha256": sha256_file(precompiled_manifest),
            "package_sha256": _read_json_object(
                precompiled_manifest, "native object package"
            )["package_sha256"],
        }
        for index, (source_row, cached_path) in enumerate(cached):
            object_path = objects / f"{index:03d}-{source_row['source']['owner']}.o"
            shutil.copyfile(cached_path, object_path)
            object_paths.append(object_path)
            object_rows.append(
                {
                    "source": {
                        key: source_row["source"][key]
                        for key in ("owner", "role", "path", "sha256")
                    },
                    "language": source_row["language"],
                    "object": object_path.relative_to(output).as_posix(),
                    "object_sha256": sha256_file(object_path),
                    "flags": source_row["canonical_flags"],
                    "cache": "content_addressed_precompiled_object",
                }
            )
    else:
        sources = [
            *compile_units,
            _Artifact(
                owner="generated",
                role="payload_relocation_anchor",
                relative_path=relocation_source.name,
                sha256=relocation_digest,
                path=relocation_source,
            ),
        ]
        for index, artifact in enumerate(sources):
            object_path = objects / f"{index:03d}-{artifact.owner}.o"
            language = (
                "assembler-with-cpp"
                if artifact.path.suffix.lower() == ".s"
                else "c"
            )
            dependencies = _native_source_dependency_closure(
                artifact, package_sequence
            )
            diagnostic_active = diagnostic_failure_trap and _uses_diagnostic_macro(
                (artifact, *dependencies)
            )
            flags = _compile_flags(
                artifact.sha256,
                package_roots,
                diagnostic_failure_trap=diagnostic_active,
            )
            command = [
                str(toolchain.compiler),
                "-x",
                language,
                "-c",
                str(artifact.path),
                "-o",
                str(object_path),
                *sum((["-I", str(root)] for root in package_roots), []),
                *flags,
            ]
            try:
                native_build._run(
                    command,
                    phase=f"compile {artifact.owner}:{artifact.role}",
                    env=environment,
                )
            except native_build.StageBNativeBuildError as exc:
                raise StageBInterpreterNativeBuildError(str(exc)) from exc
            if not object_path.is_file():
                raise StageBInterpreterNativeBuildError(
                    f"compiler omitted object for {artifact.owner}:{artifact.role}"
                )
            object_paths.append(object_path)
            object_rows.append(
                {
                    "source": artifact.payload(),
                    "language": language,
                    "object": object_path.relative_to(output).as_posix(),
                    "object_sha256": sha256_file(object_path),
                    "flags": _canonical_compile_flags(
                        artifact.sha256,
                        diagnostic_failure_trap=diagnostic_active,
                        region_overrides=region_overrides is not None,
                    ),
                    "cache": "compiled_in_candidate_derivation",
                }
            )

    raw_payload = output / ".payload-linked.exe"
    linker_map = output / _PAYLOAD_MAP_FILENAME
    link_flags = native_build._link_flags(
        entry_symbol=entry_symbol,
        image_base=contract.identity.preferred_base,
        payload_rva=selected_rva,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        linker_map=Path(_PAYLOAD_MAP_FILENAME),
    )
    try:
        native_build._run(
            [
                str(toolchain.compiler),
                "-nostdlib",
                *link_flags,
                "-o",
                raw_payload.name,
                *(path.relative_to(output).as_posix() for path in object_paths),
                str(compiler_runtime),
            ],
            phase="link freestanding interpreter payload",
            env=environment,
            cwd=output,
        )
    except native_build.StageBNativeBuildError as exc:
        raise StageBInterpreterNativeBuildError(str(exc)) from exc
    if not raw_payload.is_file() or not linker_map.is_file():
        raise StageBInterpreterNativeBuildError(
            "linker omitted the payload PE or linker map"
        )

    try:
        normalized = native_build._normalize_empty_import_directory(
            raw_payload.read_bytes()
        )
        payload_path = output / _PAYLOAD_FILENAME
        payload_path.write_bytes(normalized)
        unresolved = native_build._unresolved_symbols(
            toolchain.nm, payload_path, environment
        )
        if unresolved:
            raise StageBInterpreterNativeBuildError(
                "payload has unresolved CRT/helper symbols: " + ", ".join(unresolved)
            )
        payload_pe = native_build._qualify_payload_pe(
            normalized,
            image_base=contract.identity.preferred_base,
            minimum_rva=selected_rva,
            section_alignment=section_alignment,
            file_alignment=file_alignment,
        )
        layout_payload, layout, layout_location = native_build._extract_engine_layout(
            payload_pe, normalized
        )
        relocations = native_build._payload_relocation_inventory(payload_pe, normalized)
        if anchors is None:
            anchors = _generate_anchor_manifest(
                contract=contract,
                engine=engine,
                linker_map=linker_map,
            )
            anchor_path = output / _GENERATED_ANCHOR_FILENAME
            native_build._write_json(anchor_path, anchors.to_payload())
            anchor_artifact_sha256 = sha256_file(anchor_path)
        native_build._validate_anchor_routes(payload_pe, anchors)
        file_header = native_build._file_header(payload_pe)
        relocations_stripped = bool(
            int(file_header.Characteristics) & native_build._IMAGE_FILE_RELOCS_STRIPPED
        )
        payload_pe.close()
    except StageBInterpreterNativeBuildError:
        raise
    except Exception as exc:
        raise StageBInterpreterNativeBuildError(str(exc)) from exc

    layout_path = output / _ENGINE_LAYOUT_FILENAME
    layout_path.write_bytes(layout_payload)
    relocation_path = output / _RELOCATION_INVENTORY_FILENAME
    native_build._write_json(relocation_path, relocations.to_payload())
    raw_payload.unlink(missing_ok=True)

    _revalidate_package(interpreter)
    _revalidate_package(engine)
    _revalidate_package(runtime)
    if region_overrides is not None:
        _revalidate_package(region_overrides)
    if sha256_file(contract_path) != contract_artifact_sha256:
        raise StageBInterpreterNativeBuildError(
            "load-image contract changed during compilation"
        )
    assert anchor_path is not None
    assert anchors is not None
    assert anchor_artifact_sha256 is not None
    if sha256_file(anchor_path) != anchor_artifact_sha256:
        raise StageBInterpreterNativeBuildError(
            "executable-anchor manifest changed during compilation"
        )
    if sha256_file(compiler_runtime) != compiler_runtime_sha256:
        raise StageBInterpreterNativeBuildError(
            "compiler runtime changed during compilation"
        )
    composition = compose_stage_b_pe(
        load_image_contract=contract_path,
        payload_pe=payload_path,
        anchor_manifest=anchor_path,
        payload_relocation_inventory=relocations,
        out_dir=output,
    )
    composition_path = output / COMPOSITION_MANIFEST_FILENAME
    candidate_path = output / CANDIDATE_FILENAME

    core: dict[str, Any] = {
        "format": INTERPRETER_NATIVE_BUILD_FORMAT,
        "status": "candidate-generated",
        "acceptance_authority": "none",
        "assurance": "candidate static and behavioral validation required",
        "inputs": {
            "interpreter_package": interpreter.binding(),
            "native_engine_package": engine.binding(),
            "native_runtime_package": runtime.binding(),
            "region_override_package": (
                None if region_overrides is None else region_overrides.binding()
            ),
            "runtime_plan": runtime_plan.payload(),
            "precompiled_objects": precompiled_object_binding,
            "load_image_contract": {
                "artifact_sha256": contract_artifact_sha256,
                "contract_sha256": contract.hashes.contract_sha256,
                "bound_original_pe_sha256": contract.identity.pe_sha256,
            },
            "executable_anchor_manifest": {
                "artifact_sha256": anchor_artifact_sha256,
                "canonical_sha256": native_build._canonical_sha256(
                    anchors.to_payload()
                ),
            },
        },
        "toolchain": {
            **toolchain.payload(),
            "compiler_runtime": {
                "path": str(compiler_runtime),
                "sha256": compiler_runtime_sha256,
            },
        },
        "policy": {
            "architecture": "i686-pe32",
            "entry_symbol": entry_symbol,
            "image_base": contract.identity.preferred_base,
            "payload_rva": selected_rva,
            "section_alignment": section_alignment,
            "file_alignment": file_alignment,
            "freestanding": True,
            "dynamic_base": candidate_dynamic_base,
            "imports": "forbidden-in-payload",
            "unresolved_symbols": "forbidden",
            "base_relocations": (
                "complete-pe32-highlow-inventory-required"
                if candidate_runtime_relocations
                else "fixed-base-reference-policy"
            ),
            "diagnostic_failure_trap": diagnostic_failure_trap,
            "region_overrides": (
                0
                if region_overrides is None
                else len(region_overrides.payload["entries"])
            ),
            "object_compilation": (
                "content-addressed-per-source"
                if precompiled_object_binding is not None
                else "inline"
            ),
        },
        "objects": object_rows,
        "commands": {
            "compile_flags_policy": "deterministic-freestanding-proof-o0-v1",
            "link_flags": link_flags,
        },
        "outputs": {
            "candidate": _output_binding(candidate_path, output),
            "payload": _output_binding(payload_path, output),
            "linker_map": _output_binding(linker_map, output),
            "engine_layout": {
                **_output_binding(layout_path, output),
                "rva": layout_location[0],
                "section": layout_location[1],
                "state_size": layout.state_size,
                "features": int(layout.features),
                "x87_slot_count": layout.x87_slot_count,
            },
            "payload_relocation_inventory": {
                **_output_binding(relocation_path, output),
                "payload_sha256": relocations.payload_sha256,
                "count": len(relocations.relocations),
                "complete": relocations.complete,
            },
            "composition_manifest": {
                **_output_binding(composition_path, output),
                "manifest_core_sha256": composition["hashes"]["manifest_core_sha256"],
            },
        },
        "qualification": {
            "machine": "i386",
            "bitness": 32,
            "dynamic_base": candidate_dynamic_base,
            "relocations_stripped": not candidate_runtime_relocations,
            "base_relocations": (
                len(relocations.relocations)
                if candidate_runtime_relocations
                else 0
            ),
            "relocation_inventory_complete": relocations.complete,
            "payload_imports": 0,
            "unresolved_symbols": [],
            "compiler_materialized_layout_parsed": True,
            "package_closure_revalidated_after_compile": True,
        },
    }
    manifest = native_build._close_manifest(core)
    native_build._write_json(
        output / INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME, manifest
    )
    return manifest


def _load_package(
    value: Path | str,
    *,
    filename: str,
    owner: str,
    expected_format: str,
    require_roles: bool,
) -> _Package:
    manifest_path = Path(value)
    if manifest_path.is_dir():
        manifest_path = manifest_path / filename
    manifest_path = _file(manifest_path, f"{owner} package manifest")
    root = manifest_path.parent
    payload = _read_json_object(manifest_path, f"{owner} package manifest")
    if payload.get("format") != expected_format:
        raise StageBInterpreterNativeBuildError(
            f"{owner} package has an unsupported format"
        )
    if payload.get("status") != "ready":
        raise StageBInterpreterNativeBuildError(f"{owner} package is not ready")
    blockers = payload.get("blockers", [] if owner == "native_runtime" else None)
    if not isinstance(blockers, list) or blockers:
        raise StageBInterpreterNativeBuildError(
            f"{owner} package has malformed or nonempty blockers"
        )
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise StageBInterpreterNativeBuildError(
            f"{owner} package has no source inventory"
        )
    artifacts: list[_Artifact] = []
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    for index, raw in enumerate(sources):
        if not isinstance(raw, Mapping):
            raise StageBInterpreterNativeBuildError(
                f"{owner} source {index} is not an object"
            )
        role_value = raw.get("role")
        if require_roles:
            if not isinstance(role_value, str) or not role_value:
                raise StageBInterpreterNativeBuildError(
                    f"{owner} source {index} has no role"
                )
            role = role_value
        else:
            role = role_value if isinstance(role_value, str) else f"source_{index:03d}"
        artifact = _artifact(root, owner, role, raw)
        if artifact.relative_path in seen_paths or role in seen_roles:
            raise StageBInterpreterNativeBuildError(
                f"{owner} source inventory has duplicate paths or roles"
            )
        seen_paths.add(artifact.relative_path)
        seen_roles.add(role)
        artifacts.append(artifact)
    extra_bindings = (
        (("program", payload.get("program")),)
        if owner == "interpreter"
        else (("plan", payload.get("plan")),)
        if owner == "native_engine"
        else ()
    )
    for role, raw in extra_bindings:
        if not isinstance(raw, Mapping):
            raise StageBInterpreterNativeBuildError(
                f"{owner} package has no {role} binding"
            )
        artifact = _artifact(root, owner, role, raw)
        if artifact.relative_path in seen_paths or role in seen_roles:
            raise StageBInterpreterNativeBuildError(
                f"{owner} artifact inventory has duplicate paths or roles"
            )
        seen_paths.add(artifact.relative_path)
        seen_roles.add(role)
        artifacts.append(artifact)
    return _Package(
        owner=owner,
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=sha256_file(manifest_path),
        payload=payload,
        artifacts=tuple(artifacts),
    )


def _load_region_override_package(value: Path | str) -> _Package:
    manifest_path = Path(value)
    if manifest_path.is_dir():
        manifest_path = manifest_path / "region-overrides-manifest.json"
    manifest_path = _file(manifest_path, "region override package manifest")
    root = manifest_path.parent
    payload = _read_json_object(manifest_path, "region override package manifest")
    if payload.get("format") != REGION_OVERRIDE_TABLE_FORMAT:
        raise StageBInterpreterNativeBuildError(
            "region override package has an unsupported format"
        )
    if payload.get("status") != "ready":
        raise StageBInterpreterNativeBuildError(
            "region override package is not ready"
        )
    if payload.get("executes_original_binary") is not False:
        raise StageBInterpreterNativeBuildError(
            "region override package does not enforce zero original execution"
        )
    checks = payload.get("checks")
    if not isinstance(checks, Mapping) or not checks or any(
        value != "verified" for value in checks.values()
    ):
        raise StageBInterpreterNativeBuildError(
            "region override package checks are incomplete"
        )
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise StageBInterpreterNativeBuildError(
            "region override package has no entries"
        )
    artifacts_raw = payload.get("artifacts")
    if not isinstance(artifacts_raw, Mapping) or set(artifacts_raw) != {
        "header", "source"
    }:
        raise StageBInterpreterNativeBuildError(
            "region override package artifact inventory is malformed"
        )
    artifacts = [
        _artifact(root, "region_overrides", f"table_{role}", artifacts_raw[role])
        for role in ("header", "source")
    ]
    seen_paths = {item.relative_path for item in artifacts}
    seen_symbols: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise StageBInterpreterNativeBuildError(
                f"region override entry {index} is not an object"
            )
        source = entry.get("source")
        if not isinstance(source, Mapping):
            raise StageBInterpreterNativeBuildError(
                f"region override entry {index} has no source binding"
            )
        symbol = source.get("symbol")
        if not isinstance(symbol, str) or _C_IDENTIFIER.fullmatch(symbol) is None:
            raise StageBInterpreterNativeBuildError(
                f"region override entry {index} source symbol is malformed"
            )
        if symbol in seen_symbols:
            raise StageBInterpreterNativeBuildError(
                "region override package has duplicate source symbols"
            )
        seen_symbols.add(symbol)
        artifact = _artifact(
            root,
            "region_overrides",
            f"replacement_source_{index:03d}",
            source,
        )
        if artifact.relative_path in seen_paths:
            raise StageBInterpreterNativeBuildError(
                "region override package has duplicate source paths"
            )
        seen_paths.add(artifact.relative_path)
        artifacts.append(artifact)
        support_sources = entry.get("support_sources", [])
        if not isinstance(support_sources, list):
            raise StageBInterpreterNativeBuildError(
                f"region override entry {index} support sources are malformed"
            )
        for support_index, support in enumerate(support_sources):
            if not isinstance(support, Mapping):
                raise StageBInterpreterNativeBuildError(
                    f"region override entry {index} support source {support_index} "
                    "is not an object"
                )
            support_artifact = _artifact(
                root,
                "region_overrides",
                f"replacement_support_{index:03d}_{support_index:03d}",
                support,
            )
            if support_artifact.relative_path in seen_paths:
                raise StageBInterpreterNativeBuildError(
                    "region override package has duplicate source paths"
                )
            seen_paths.add(support_artifact.relative_path)
            artifacts.append(support_artifact)
    return _Package(
        owner="region_overrides",
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=sha256_file(manifest_path),
        payload=payload,
        artifacts=tuple(artifacts),
    )


def _validate_region_override_closure(
    interpreter: _Package, region_overrides: _Package
) -> None:
    machine_ir = interpreter.payload.get("machine_ir")
    if not isinstance(machine_ir, Mapping):
        raise StageBInterpreterNativeBuildError(
            "region overrides require a machine-IR interpreter package"
        )
    machine_ir_sha256 = native_build._digest(
        machine_ir.get("sha256"), "interpreter machine-IR SHA-256"
    )
    program = next(
        (item for item in interpreter.artifacts if item.role == "program"), None
    )
    if program is None:
        raise StageBInterpreterNativeBuildError(
            "interpreter package has no baseline program artifact"
        )
    if (
        region_overrides.payload.get("machine_ir_sha256") != machine_ir_sha256
        or region_overrides.payload.get("baseline_program_sha256")
        != program.sha256
    ):
        raise StageBInterpreterNativeBuildError(
            "region override package binds a different machine IR or baseline program"
        )


def _validate_package_closure(
    interpreter: _Package, engine: _Package, runtime: _Package
) -> Any:
    runtime_inputs = runtime.payload.get("inputs")
    if not isinstance(runtime_inputs, Mapping):
        raise StageBInterpreterNativeBuildError(
            "native-runtime package has malformed inputs"
        )
    external_binding = runtime_inputs.get("external_range_contracts")
    if not isinstance(external_binding, Mapping):
        raise StageBInterpreterNativeBuildError(
            "native-runtime package has no external-range contract binding"
        )
    profile_binding = external_binding.get("profile")
    profile_artifacts = [
        artifact for artifact in runtime.artifacts
        if artifact.role == "external_profile"
    ]
    external_profile: Path | None = None
    if profile_binding is None:
        if profile_artifacts:
            raise StageBInterpreterNativeBuildError(
                "native-runtime package has an unbound external profile"
            )
    else:
        if not isinstance(profile_binding, Mapping) or len(profile_artifacts) != 1:
            raise StageBInterpreterNativeBuildError(
                "native-runtime external profile binding is incomplete"
            )
        profile_artifact = profile_artifacts[0]
        if (
            profile_binding.get("path") != profile_artifact.relative_path
            or profile_binding.get("sha256") != profile_artifact.sha256
        ):
            raise StageBInterpreterNativeBuildError(
                "native-runtime external profile binding differs from its artifact"
            )
        external_profile = profile_artifact.path
    callable_binding = runtime_inputs.get("callable_external")
    callable_artifacts = [
        artifact
        for artifact in runtime.artifacts
        if artifact.role == "callable_external_contract"
    ]
    callable_contract: Path | None = None
    if callable_binding is None:
        if callable_artifacts:
            raise StageBInterpreterNativeBuildError(
                "native-runtime package has an unbound callable-external contract"
            )
    else:
        if not isinstance(callable_binding, Mapping) or len(callable_artifacts) != 1:
            raise StageBInterpreterNativeBuildError(
                "native-runtime callable-external binding is incomplete"
            )
        callable_artifact = callable_artifacts[0]
        if (
            callable_binding.get("path") != callable_artifact.relative_path
            or callable_binding.get("sha256") != callable_artifact.sha256
        ):
            raise StageBInterpreterNativeBuildError(
                "native-runtime callable-external binding differs from its artifact"
            )
        callable_contract = callable_artifact.path
    try:
        plan = plan_stage_b_native_runtime(
            interpreter_package=interpreter.root,
            native_engine_package=engine.root,
            external_profile=external_profile,
            callable_external_contract=callable_contract,
        )
    except Exception as exc:
        raise StageBInterpreterNativeBuildError(
            f"interpreter/native-engine closure is incomplete: {exc}"
        ) from exc

    program_ref = interpreter.payload.get("program")
    if not isinstance(program_ref, Mapping):
        raise StageBInterpreterNativeBuildError(
            "interpreter package has no program binding"
        )
    program = _artifact(interpreter.root, "interpreter", "program", program_ref)
    program_payload = _read_json_object(program.path, "interpreter program manifest")
    if program_payload.get("status") != "ready" or program_payload.get("blockers") != []:
        raise StageBInterpreterNativeBuildError("interpreter program is incomplete")
    counts = program_payload.get("counts")
    if not isinstance(counts, Mapping):
        raise StageBInterpreterNativeBuildError("interpreter program counts are malformed")
    transfer_count = len(plan.transfer_rvas)
    deferred_count = counts.get("deferred_transfers", 0)
    if (
        not isinstance(deferred_count, int)
        or isinstance(deferred_count, bool)
        or deferred_count < 0
    ):
        raise StageBInterpreterNativeBuildError(
            "interpreter program deferred-transfer count is malformed"
        )
    if (
        counts.get("input_transfers") != transfer_count + deferred_count
        or counts.get("transfers") != transfer_count
        or counts.get("blocked_transfers") != 0
    ):
        raise StageBInterpreterNativeBuildError(
            "interpreter program transfer coverage is incomplete"
        )
    coverage = program_payload.get("semantic_coverage")
    execution_policy = program_payload.get("execution_policy")
    deferred_rows = program_payload.get("deferred_transfers")
    if deferred_count:
        if (
            not isinstance(coverage, Mapping)
            or coverage.get("status") != "incomplete"
            or coverage.get("acceptance_authority") is not False
            or execution_policy != "fail_closed_on_deferred_potential_transfer_v1"
            or not isinstance(deferred_rows, list)
            or len(deferred_rows) != deferred_count
            or any(
                not isinstance(item, Mapping)
                or item.get("reachability") != "potential"
                or item.get("runtime_disposition")
                != "fail_closed_as_unimplemented_if_reached"
                for item in deferred_rows
            )
        ):
            raise StageBInterpreterNativeBuildError(
                "interpreter deferred-transfer policy is incomplete"
            )
    elif (
        not isinstance(coverage, Mapping)
        or coverage.get("status") != "complete"
        or execution_policy != "complete_transfer_inventory_v1"
        or deferred_rows != []
    ):
        raise StageBInterpreterNativeBuildError(
            "interpreter complete-transfer policy is malformed"
        )

    if runtime.payload.get("acceptance_authority") is not False:
        raise StageBInterpreterNativeBuildError(
            "native-runtime package has unexpected acceptance authority"
        )
    if runtime.payload.get("inputs") != plan.payload():
        raise StageBInterpreterNativeBuildError(
            "native-runtime package does not bind the exact interpreter/engine closure"
        )
    runtime_counts = runtime.payload.get("counts")
    if (
        not isinstance(runtime_counts, Mapping)
        or runtime_counts.get("transfers") != transfer_count
    ):
        raise StageBInterpreterNativeBuildError(
            "native-runtime transfer count differs from the interpreter"
        )
    return plan


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
        "compile_key_sha256": native_build._canonical_sha256(compile_key_core),
        "canonical_flags": _canonical_compile_flags(
            artifact.sha256,
            diagnostic_failure_trap=diagnostic_active,
            region_overrides=region_overrides,
        ),
    }
    return {**unit_core, "unit_sha256": native_build._canonical_sha256(unit_core)}


def _load_native_object_graph(value: Path | str) -> tuple[Path, dict[str, Any]]:
    path = Path(value)
    if path.is_dir():
        path = path / "native-object-graph.json"
    payload = _read_json_object(path, "native object graph")
    if payload.get("format") != INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT:
        raise StageBInterpreterNativeBuildError("unsupported native object graph format")
    core = dict(payload)
    expected = core.pop("graph_sha256", None)
    if expected != native_build._canonical_sha256(core):
        raise StageBInterpreterNativeBuildError("native object graph self-hash is stale")
    units = payload.get("units")
    if not isinstance(units, list) or not units:
        raise StageBInterpreterNativeBuildError("native object graph has no compile units")
    seen: set[str] = set()
    for row in units:
        if not isinstance(row, Mapping):
            raise StageBInterpreterNativeBuildError("native object graph unit is malformed")
        unit_id = str(row.get("id"))
        if unit_id in seen:
            raise StageBInterpreterNativeBuildError("native object graph has duplicate unit IDs")
        seen.add(unit_id)
        unit_core = dict(row)
        unit_expected = unit_core.pop("unit_sha256", None)
        if unit_expected != native_build._canonical_sha256(unit_core):
            raise StageBInterpreterNativeBuildError("native object graph unit self-hash is stale")
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
    diagnostic_failure_trap: bool,
    relocation_digest: str,
) -> list[tuple[dict[str, Any], Path]]:
    path = Path(value)
    if path.is_dir():
        path = path / "native-object-package.json"
    payload = _read_json_object(path, "native object package")
    if payload.get("format") != INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT:
        raise StageBInterpreterNativeBuildError("unsupported native object package format")
    core = dict(payload)
    expected_hash = core.pop("package_sha256", None)
    if expected_hash != native_build._canonical_sha256(core):
        raise StageBInterpreterNativeBuildError("native object package self-hash is stale")
    if (
        payload.get("status") != "complete"
        or payload.get("executes_original_binary") is not False
        or payload.get("packages") != packages
        or payload.get("compiler") != _native_compiler_binding(compiler)
        or payload.get("entry_symbol") != entry_symbol
        or payload.get("diagnostic_failure_trap") != diagnostic_failure_trap
    ):
        raise StageBInterpreterNativeBuildError("native object package build binding is stale")
    units = payload.get("units")
    objects = payload.get("objects")
    if (
        not isinstance(units, list)
        or not isinstance(objects, list)
        or len(units) != len(compile_units) + 1
        or len(objects) != len(units)
    ):
        raise StageBInterpreterNativeBuildError("native object package inventory is incomplete")
    graph_binding = payload.get("graph")
    if not isinstance(graph_binding, Mapping):
        raise StageBInterpreterNativeBuildError("native object package graph binding is missing")
    bound_graph_path = Path(str(graph_binding.get("path"))) / str(
        graph_binding.get("manifest")
    )
    if (
        not bound_graph_path.is_file()
        or sha256_file(bound_graph_path) != graph_binding.get("manifest_sha256")
        or graph_binding.get("manifest_sha256") != payload.get("graph_artifact_sha256")
    ):
        raise StageBInterpreterNativeBuildError("native object package graph artifact is stale")
    relocation_location = Path(str(units[-1].get("source", {}).get("location")))
    graph_relocation_source = _file(
        bound_graph_path.parent / relocation_location
        if units[-1].get("source", {}).get("location_base") == "graph"
        else relocation_location,
        "cached relocation-anchor source",
    )
    if sha256_file(graph_relocation_source) != relocation_digest:
        raise StageBInterpreterNativeBuildError(
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
            diagnostic_failure_trap=diagnostic_failure_trap,
            region_overrides=region_overrides,
        )
        for index, artifact in enumerate(expected_artifacts)
    ]
    if units != expected_rows:
        raise StageBInterpreterNativeBuildError(
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
            raise StageBInterpreterNativeBuildError("native object package unit binding is stale")
        object_path = package_root / str(object_row.get("path"))
        if not object_path.is_file() or sha256_file(object_path) != object_row.get("sha256"):
            raise StageBInterpreterNativeBuildError("native object package artifact is stale")
        result.append((expected_row, object_path))
    return result


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


def _artifact(
    root: Path, owner: str, role: str, raw: Mapping[str, Any]
) -> _Artifact:
    relative = _relative_path(raw.get("path"), f"{owner} {role} path")
    digest = native_build._digest(raw.get("sha256"), f"{owner} {role} SHA-256")
    path = root / relative
    if not path.is_file():
        raise StageBInterpreterNativeBuildError(
            f"{owner} {role} artifact is missing: {relative}"
        )
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise StageBInterpreterNativeBuildError(
            f"{owner} {role} artifact escapes its package root"
        ) from exc
    if sha256_file(path) != digest:
        raise StageBInterpreterNativeBuildError(
            f"{owner} {role} artifact SHA-256 mismatch"
        )
    return _Artifact(owner, role, relative.as_posix(), digest, path)


def _revalidate_package(package: _Package) -> None:
    if sha256_file(package.manifest_path) != package.manifest_sha256:
        raise StageBInterpreterNativeBuildError(
            f"{package.owner} manifest changed during compilation"
        )
    for item in package.artifacts:
        if not item.path.is_file() or sha256_file(item.path) != item.sha256:
            raise StageBInterpreterNativeBuildError(
                f"{package.owner} artifact changed during compilation: "
                f"{item.relative_path}"
            )


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


def _generate_anchor_manifest(
    *, contract: Any, engine: _Package, linker_map: Path
) -> ExecutableAnchorManifest:
    symbols = _payload_symbol_rvas(
        linker_map, image_base=contract.identity.preferred_base
    )
    entry_target = symbols.get("stage_b_payload_entry")
    if entry_target is None:
        raise StageBInterpreterNativeBuildError(
            "linked payload map omits stage_b_payload_entry"
        )

    callback_rows = engine.payload.get("callback_abis")
    if not isinstance(callback_rows, list):
        raise StageBInterpreterNativeBuildError(
            "native-engine callback ABI inventory is malformed"
        )
    callback_rvas: list[int] = []
    targets: dict[int, int] = {}
    for index, raw in enumerate(callback_rows):
        if not isinstance(raw, Mapping):
            raise StageBInterpreterNativeBuildError(
                f"native-engine callback ABI {index} is not an object"
            )
        callback_rva = _u32(raw.get("rva"), f"callback ABI {index} RVA")
        symbol = raw.get("symbol")
        expected_symbol = f"stage_b_payload_callback_{callback_rva:08x}"
        if symbol != expected_symbol:
            raise StageBInterpreterNativeBuildError(
                f"callback ABI {index} has a noncanonical bridge symbol"
            )
        target = symbols.get(expected_symbol)
        if target is None:
            raise StageBInterpreterNativeBuildError(
                f"linked payload map omits {expected_symbol}"
            )
        callback_rvas.append(callback_rva)
        targets[callback_rva] = target
    if len(set(callback_rvas)) != len(callback_rvas):
        raise StageBInterpreterNativeBuildError(
            "native-engine callback ABI inventory contains duplicate RVAs"
        )

    tls_rvas = tuple(
        callback.rva for callback in (() if contract.tls is None else contract.tls.callbacks)
    )
    missing_tls = sorted(set(tls_rvas) - set(callback_rvas))
    if missing_tls:
        raise StageBInterpreterNativeBuildError(
            "native-engine package omits TLS callback bridges: "
            + ", ".join(f"{rva:#x}" for rva in missing_tls)
        )
    ordinary_callbacks = tuple(sorted(set(callback_rvas) - set(tls_rvas)))
    routes = [(contract.identity.entry_rva, entry_target)]
    routes.extend((rva, targets[rva]) for rva in tls_rvas)
    routes.extend((rva, targets[rva]) for rva in ordinary_callbacks)
    anchors = tuple(
        ExecutableAnchor(
            rva=source,
            bytes=_near_jump_covering_original_relocations(
                source,
                target,
                contract.relocations,
            ),
        )
        for source, target in sorted(routes)
    )
    for left, right in zip(anchors, anchors[1:]):
        if left.end_rva > right.rva:
            raise StageBInterpreterNativeBuildError(
                "generated executable anchors overlap"
            )
    return ExecutableAnchorManifest(
        image_base=contract.identity.preferred_base,
        entry_anchor_rva=contract.identity.entry_rva,
        tls_callback_anchor_rvas=tls_rvas,
        callback_anchor_rvas=ordinary_callbacks,
        anchors=anchors,
        format=EXECUTABLE_ANCHOR_MANIFEST_FORMAT,
    )


def _near_jump_covering_original_relocations(
    source_rva: int,
    target_rva: int,
    relocation_blocks: Sequence[Any],
) -> bytes:
    """Pad a root jump so loader fixups cannot partially rewrite its bytes."""

    jump = _near_jump(source_rva, target_rva)
    end_rva = source_rva + len(jump)
    relocations = [
        relocation
        for block in relocation_blocks
        for relocation in block.relocations
        if relocation.type != 0 and relocation.target_rva is not None
    ]
    changed = True
    while changed:
        changed = False
        for relocation in relocations:
            relocation_start = relocation.target_rva
            relocation_end = relocation_start + relocation.width
            if relocation_start < end_rva and source_rva < relocation_end:
                if relocation_start < source_rva:
                    raise StageBInterpreterNativeBuildError(
                        "original relocation begins before and overlaps a generated anchor"
                    )
                if relocation_end > end_rva:
                    end_rva = relocation_end
                    changed = True
    return jump + b"\x90" * (end_rva - source_rva - len(jump))


def _payload_symbol_rvas(linker_map: Path, *, image_base: int) -> dict[str, int]:
    try:
        text = linker_map.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise StageBInterpreterNativeBuildError(
            f"cannot read payload linker map: {exc}"
        ) from exc
    result: dict[str, int] = {}
    for match in _PAYLOAD_SYMBOL.finditer(text):
        address = int(match.group(1), 16)
        if address < image_base:
            raise StageBInterpreterNativeBuildError(
                f"payload symbol {match.group(2)} lies below the image base"
            )
        name = match.group(2).removeprefix("_")
        rva = _u32(address - image_base, f"payload symbol {name} RVA")
        previous = result.setdefault(name, rva)
        if previous != rva:
            raise StageBInterpreterNativeBuildError(
                f"payload linker map gives ambiguous addresses for {name}"
            )
    return result


def _near_jump(source_rva: int, target_rva: int) -> bytes:
    displacement = target_rva - (source_rva + 5)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise StageBInterpreterNativeBuildError(
            "generated executable anchor target is outside near-jump range"
        )
    return b"\xe9" + struct.pack("<i", displacement)


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
    except native_build.StageBNativeBuildError as exc:
        raise StageBInterpreterNativeBuildError(
            f"cannot locate the compiler runtime: {exc}"
        ) from exc
    path = Path(value).resolve()
    if not path.is_file():
        raise StageBInterpreterNativeBuildError(
            f"compiler runtime does not exist: {path}"
        )
    return path


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=native_build._reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise StageBInterpreterNativeBuildError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageBInterpreterNativeBuildError(f"{label} must be a JSON object")
    return value


def _relative_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise StageBInterpreterNativeBuildError(f"{label} must be a relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise StageBInterpreterNativeBuildError(f"{label} must be a canonical relative path")
    return path


def _file(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_file():
        raise StageBInterpreterNativeBuildError(f"{label} does not exist: {path}")
    return path


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise StageBInterpreterNativeBuildError(f"{label} must be an unsigned 32-bit integer")
    return value


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


__all__ = [
    "INTERPRETER_NATIVE_BUILD_FORMAT",
    "INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME",
    "INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT",
    "INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT",
    "StageBInterpreterNativeBuildError",
    "assemble_stage_b_interpreter_native_objects",
    "build_stage_b_interpreter_native_candidate",
    "compile_stage_b_interpreter_native_object",
    "prepare_stage_b_interpreter_native_object_graph",
]
