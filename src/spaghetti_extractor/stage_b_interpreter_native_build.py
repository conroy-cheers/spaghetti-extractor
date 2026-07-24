"""Build a freestanding PE32 candidate from Stage B interpreter packages.

This module is candidate-generation infrastructure only.  It validates and
content-binds the semantic interpreter, native engine, and native runtime,
then uses the shared native-build qualification and PE-composition machinery.
Nothing emitted here has Stage A acceptance authority.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import stage_b_native_build as native_build
from .roundtrip_fuzz.image_contract import load_stage_a_load_image_contract
from .stage_b_interpreter_backend import STAGE_B_INTERPRETER_PACKAGE_FORMAT
from .stage_b_native_engine import NATIVE_ENGINE_PACKAGE_FORMAT
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


INTERPRETER_NATIVE_BUILD_FORMAT = "stage-b-interpreter-native-build-v1"
INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME = "interpreter-native-build-manifest.json"

_INTERPRETER_MANIFEST_FILENAME = "state-machine-interpreter-package.json"
_ENGINE_MANIFEST_FILENAME = "native-engine-package.json"
_PAYLOAD_FILENAME = native_build.PAYLOAD_FILENAME
_PAYLOAD_MAP_FILENAME = native_build.PAYLOAD_MAP_FILENAME
_ENGINE_LAYOUT_FILENAME = native_build.ENGINE_LAYOUT_FILENAME
_RELOCATION_INVENTORY_FILENAME = native_build.PAYLOAD_RELOCATION_INVENTORY_FILENAME
_GENERATED_ANCHOR_FILENAME = "executable-anchor-manifest.json"
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
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


def build_stage_b_interpreter_native_candidate(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    native_runtime_package: Path | str,
    load_image_contract: Path | str,
    out_dir: Path | str,
    anchor_manifest: Path | str | None = None,
    compiler: Path | str = "i686-w64-mingw32-gcc",
    entry_symbol: str = "stage_b_payload_entry",
    payload_rva: int | None = None,
) -> dict[str, Any]:
    """Compile, qualify, and compose one interpreter-backed PE32 candidate."""

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
    compile_units = _compile_units(interpreter, engine, runtime, entry_symbol)

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
    package_roots = (interpreter.root, engine.root, runtime.root)
    for index, artifact in enumerate(compile_units):
        object_path = objects / f"{index:03d}-{artifact.owner}.o"
        language = (
            "assembler-with-cpp"
            if artifact.path.suffix.lower() == ".s"
            else "c"
        )
        flags = _compile_flags(artifact.sha256, package_roots)
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
                "flags": _canonical_compile_flags(artifact.sha256),
            }
        )

    relocation_source = output / ".payload-relocation-anchor.S"
    relocation_object = objects / f"{len(object_paths):03d}-relocation-anchor.o"
    relocation_source.write_text(
        native_build._relocation_anchor_source(entry_symbol), encoding="ascii"
    )
    relocation_digest = sha256_file(relocation_source)
    try:
        native_build._run(
            [
                str(toolchain.compiler),
                "-x",
                "assembler-with-cpp",
                "-c",
                str(relocation_source),
                "-o",
                str(relocation_object),
                *_compile_flags(relocation_digest, package_roots),
            ],
            phase="compile generated relocation anchor",
            env=environment,
        )
    except native_build.StageBNativeBuildError as exc:
        raise StageBInterpreterNativeBuildError(str(exc)) from exc
    if not relocation_object.is_file():
        raise StageBInterpreterNativeBuildError(
            "compiler omitted the generated relocation-anchor object"
        )
    object_paths.append(relocation_object)
    object_rows.append(
        {
            "source": {
                "owner": "generated",
                "role": "payload_relocation_anchor",
                "path": relocation_source.name,
                "sha256": relocation_digest,
            },
            "language": "assembler-with-cpp",
            "object": relocation_object.relative_to(output).as_posix(),
            "object_sha256": sha256_file(relocation_object),
            "flags": _canonical_compile_flags(relocation_digest),
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
        "acceptance": "Stage A whole-program theorem required",
        "inputs": {
            "interpreter_package": interpreter.binding(),
            "native_engine_package": engine.binding(),
            "native_runtime_package": runtime.binding(),
            "runtime_plan": runtime_plan.payload(),
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
            "dynamic_base": True,
            "imports": "forbidden-in-payload",
            "unresolved_symbols": "forbidden",
            "base_relocations": "complete-pe32-highlow-inventory-required",
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
            "dynamic_base": True,
            "relocations_stripped": relocations_stripped,
            "base_relocations": len(relocations.relocations),
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


def _validate_package_closure(
    interpreter: _Package, engine: _Package, runtime: _Package
) -> Any:
    try:
        plan = plan_stage_b_native_runtime(
            interpreter_package=interpreter.root,
            native_engine_package=engine.root,
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
    if (
        counts.get("input_transfers") != transfer_count
        or counts.get("transfers") != transfer_count
        or counts.get("blocked_transfers") != 0
    ):
        raise StageBInterpreterNativeBuildError(
            "interpreter program transfer coverage is incomplete"
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
) -> tuple[_Artifact, ...]:
    interpreter_roles = {"interpreter_source", "program_source"}
    runtime_roles = {"native_runtime_source"}
    selected = [
        item
        for package in (interpreter, engine, runtime)
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

    owner_order = {"native_engine": 0, "interpreter": 1, "native_runtime": 2}
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


def _compile_flags(source_sha256: str, roots: Sequence[Path]) -> list[str]:
    flags = _proof_profile_compile_flags(source_sha256)
    labels = ("interpreter", "engine", "runtime")
    for label, root in zip(labels, roots, strict=True):
        for prefix in ("file", "debug", "macro"):
            flags.append(f"-f{prefix}-prefix-map={root}=/stage-b/{label}")
    return flags


def _canonical_compile_flags(source_sha256: str) -> list[str]:
    flags = _proof_profile_compile_flags(source_sha256)
    for label in ("interpreter", "engine", "runtime"):
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
    "StageBInterpreterNativeBuildError",
    "build_stage_b_interpreter_native_candidate",
]
