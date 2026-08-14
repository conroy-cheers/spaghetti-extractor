"""Top-level orchestration for deterministic interpreter-native builds."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifact_formats import (
    INTERPRETER_NATIVE_BUILD_FORMAT,
    NATIVE_ENGINE_PACKAGE_FORMAT,
    NATIVE_RUNTIME_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
)
from ..recovered_executable_data import load_recovered_executable_data_contract
from ..roundtrip_fuzz.image_contract import load_stage_a_load_image_contract
from ..util import sha256_file
from . import native_build
from .authority import CandidateAuthorityV3Receipt
from .build_model import (
    INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME,
    INTERPRETER_NATIVE_BUNDLE_INDEX_FORMAT,
    INTERPRETER_NATIVE_OBJECT_FORMAT,
    INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT,
    INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT,
    StageBInterpreterNativeBuildError,
    _Artifact,
    _C_IDENTIFIER,
    _ENGINE_LAYOUT_FILENAME,
    _ENGINE_MANIFEST_FILENAME,
    _GENERATED_ANCHOR_FILENAME,
    _INTERPRETER_MANIFEST_FILENAME,
    _PAYLOAD_FILENAME,
    _PAYLOAD_MAP_FILENAME,
    _RELOCATION_INVENTORY_FILENAME,
)
from .build_objects import (
    _compiler_runtime,
    _generate_anchor_manifest,
    _load_native_object_graph,
    _load_precompiled_native_objects,
    _output_binding,
)
from .build_sources import (
    _bound_bundle_artifact,
    _canonical_compile_flags,
    _compile_flags,
    _compile_units,
    _load_native_source_bundle,
    _native_compiler_binding,
    _native_object_graph_row,
    _native_row_artifacts,
    _native_source_dependency_closure,
    _uses_diagnostic_macro,
    _write_native_source_bundle,
)
from .build_validation import (
    _candidate_authority_manifest_binding,
    _candidate_manifest_pe_sha256,
    _load_package,
    _load_region_override_package,
    _validate_candidate_authority_package_bindings,
    _validate_candidate_authority_v3,
    _validate_candidate_mode_package_bindings,
    _validate_package_closure,
    _validate_region_override_closure,
)
from .build_values import (
    _align_up,
    _file,
    _read_json_object,
    _revalidate_package,
    _u32,
)
from .modes import (
    STATIC_CLOSED_CANDIDATE_MODE,
    STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
    require_candidate_mode,
)
from .pe import (
    CANDIDATE_FILENAME,
    COMPOSITION_MANIFEST_FILENAME,
    ExecutableAnchorManifest,
    compose_stage_b_pe,
)
from .runtime import NATIVE_RUNTIME_MANIFEST_FILENAME


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
    bundles = []
    for row in rows:
        artifacts = (
            (relocation_artifact,)
            if row["id"]
            == relocation_artifact.owner + "-" + relocation_artifact.role
            else _native_row_artifacts(row=row, packages=packages)
        )
        bundles.append(
            _write_native_source_bundle(
                output=output,
                row=row,
                artifacts=artifacts,
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
        "bundles": bundles,
        "counts": {"compile_units": len(rows)},
    }
    payload = {**core, "graph_sha256": native_build._canonical_sha256(core)}
    native_build._write_json(output / "native-object-graph.json", payload)
    bundle_index_core = {
        "format": INTERPRETER_NATIVE_BUNDLE_INDEX_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "bundles": bundles,
        "counts": {"compile_units": len(bundles)},
    }
    native_build._write_json(
        output / "native-object-bundles.json",
        {
            **bundle_index_core,
            "index_sha256": native_build._canonical_sha256(bundle_index_core),
        },
    )
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


def compile_stage_b_interpreter_native_source_bundle(
    *,
    source_bundle: Path | str,
    compiler: Path | str,
    out_dir: Path | str,
) -> dict[str, Any]:
    """Compile one normalized source bundle without depending on its parent graph."""

    bundle_root, payload = _load_native_source_bundle(source_bundle)
    source = _bound_bundle_artifact(
        bundle_root, payload["source"], "native source bundle source"
    )
    for index, dependency in enumerate(payload["dependencies"]):
        _bound_bundle_artifact(
            bundle_root,
            dependency,
            f"native source bundle dependency {index}",
        )
    compiler_value = str(compiler)
    compiler_path = _file(
        shutil.which(compiler_value) or compiler_value,
        "native object compiler",
    )
    compiler_binding = _native_compiler_binding(compiler_path)
    if {
        key: value for key, value in compiler_binding.items() if key != "path"
    } != payload["compiler"]:
        raise StageBInterpreterNativeBuildError(
            "native source bundle compiler binding is stale"
        )
    roots = [
        bundle_root / "roots" / mapping["owner"]
        for mapping in payload["root_mappings"]
    ]
    diagnostic_active = bool(payload["diagnostic_active"])
    arguments = [
        "-x",
        payload["language"],
        "-c",
        str(source),
        *sum((["-I", str(root)] for root in roots), []),
        *_compile_flags(
            payload["source"]["sha256"],
            roots,
            diagnostic_failure_trap=diagnostic_active,
        ),
    ]
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    object_path = output / "object.o"
    try:
        native_build._run(
            [str(compiler_path), *arguments, "-o", str(object_path)],
            phase=f"compile cached source bundle {payload['unit_id']}",
            env=native_build._deterministic_environment(),
            cwd=bundle_root,
        )
    except native_build.StageBNativeBuildError as exc:
        raise StageBInterpreterNativeBuildError(str(exc)) from exc
    if not object_path.is_file():
        raise StageBInterpreterNativeBuildError(
            "compiler omitted bundled native object"
        )
    core = {
        "format": INTERPRETER_NATIVE_OBJECT_FORMAT,
        "status": "compiled",
        "executes_original_binary": False,
        "unit_id": payload["unit_id"],
        "compile_key_sha256": payload["compile_key_sha256"],
        "source_bundle_sha256": payload["bundle_sha256"],
        "object": {
            "path": object_path.name,
            "sha256": sha256_file(object_path),
            "size": object_path.stat().st_size,
        },
    }
    result = {
        **core,
        "object_receipt_sha256": native_build._canonical_sha256(core),
    }
    native_build._write_json(output / "native-object.json", result)
    return result


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
    candidate_authority: Path | str | None,
    final_authority: Path | str | None,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    fallback_coverage_receipt: Path | str | None,
    component_runtime_package: Path | str | None,
    region_override_package: Path | str | None = None,
    load_image_contract: Path | str,
    recovered_executable_data: Path | str | None = None,
    out_dir: Path | str,
    anchor_manifest: Path | str | None = None,
    compiler: Path | str = "i686-w64-mingw32-gcc",
    entry_symbol: str = "stage_b_payload_entry",
    payload_rva: int | None = None,
    diagnostic_failure_trap: bool = False,
    candidate_mode: str = STATIC_CLOSED_CANDIDATE_MODE,
    precompiled_objects: Path | str | None = None,
) -> dict[str, Any]:
    """Compile and compose one explicitly classified interpreter candidate."""

    if not isinstance(diagnostic_failure_trap, bool):
        raise StageBInterpreterNativeBuildError(
            "diagnostic_failure_trap must be a boolean"
        )
    try:
        candidate_mode = require_candidate_mode(candidate_mode)
    except ValueError as exc:
        raise StageBInterpreterNativeBuildError(str(exc)) from exc
    if (
        candidate_mode == STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE
        and not diagnostic_failure_trap
    ):
        raise StageBInterpreterNativeBuildError(
            "structural-diagnostic candidates require the failure trap"
        )
    if _C_IDENTIFIER.fullmatch(entry_symbol) is None:
        raise StageBInterpreterNativeBuildError(
            "payload entry symbol is not a C identifier"
        )

    receipt: CandidateAuthorityV3Receipt | None = None
    if candidate_mode == STATIC_CLOSED_CANDIDATE_MODE:
        if any(value is None for value in (
            candidate_authority,
            final_authority,
            fallback_coverage_receipt,
            component_runtime_package,
        )):
            raise StageBInterpreterNativeBuildError(
                "static-closed candidates require complete v3 authority inputs"
            )
        receipt = _validate_candidate_authority_v3(
            receipt=candidate_authority,
            final_authority=final_authority,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
            fallback_coverage_receipt=fallback_coverage_receipt,
            component_runtime_package=component_runtime_package,
        )
    elif any(value is not None for value in (
        candidate_authority,
        final_authority,
        fallback_coverage_receipt,
        component_runtime_package,
    )):
        raise StageBInterpreterNativeBuildError(
            "structural-diagnostic candidates must not consume acceptance authority"
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
    if candidate_mode == STATIC_CLOSED_CANDIDATE_MODE:
        assert receipt is not None
        _validate_candidate_authority_package_bindings(receipt, interpreter, engine)
    structural_binding = _validate_candidate_mode_package_bindings(
        candidate_mode=candidate_mode,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        interpreter=interpreter,
        engine=engine,
        runtime=runtime,
        runtime_plan=runtime_plan,
    )
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
    if contract.identity.pe_sha256 != _candidate_manifest_pe_sha256(
        machine_ir_manifest
    ):
        raise StageBInterpreterNativeBuildError(
            "load-image contract binds a different PE than the v2 "
            "candidate-authority receipt"
        )
    executable_data_path: Path | None = None
    executable_data_artifact_sha256: str | None = None
    executable_data = None
    if recovered_executable_data is not None:
        executable_data_path = _file(
            recovered_executable_data, "recovered executable-data contract"
        )
        executable_data_artifact_sha256 = sha256_file(executable_data_path)
        executable_data = load_recovered_executable_data_contract(
            executable_data_path
        )
        interpreter_machine_ir = interpreter.payload.get("machine_ir")
        engine_machine_ir = engine.payload.get("machine_ir")
        if (
            not isinstance(interpreter_machine_ir, Mapping)
            or not isinstance(engine_machine_ir, Mapping)
            or interpreter_machine_ir.get("sha256")
            != executable_data.machine_ir_sha256
            or engine_machine_ir.get("sha256")
            != executable_data.machine_ir_sha256
        ):
            raise StageBInterpreterNativeBuildError(
                "recovered executable-data contract binds a different machine IR"
            )
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
    if (
        executable_data_path is not None
        and sha256_file(executable_data_path) != executable_data_artifact_sha256
    ):
        raise StageBInterpreterNativeBuildError(
            "recovered executable-data contract changed during compilation"
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
    if candidate_mode == STATIC_CLOSED_CANDIDATE_MODE:
        assert receipt is not None
        assert candidate_authority is not None
        assert final_authority is not None
        assert fallback_coverage_receipt is not None
        assert component_runtime_package is not None
        repeated_receipt = _validate_candidate_authority_v3(
            receipt=candidate_authority,
            final_authority=final_authority,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
            fallback_coverage_receipt=fallback_coverage_receipt,
            component_runtime_package=component_runtime_package,
        )
        if repeated_receipt != receipt:
            raise StageBInterpreterNativeBuildError(
                "v3 candidate-authority inputs changed during compilation"
            )
    repeated_structural_binding = _validate_candidate_mode_package_bindings(
        candidate_mode=candidate_mode,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        interpreter=interpreter,
        engine=engine,
        runtime=runtime,
        runtime_plan=runtime_plan,
    )
    if repeated_structural_binding != structural_binding:
        raise StageBInterpreterNativeBuildError(
            "candidate execution-scope inputs changed during compilation"
        )
    composition = compose_stage_b_pe(
        load_image_contract=contract_path,
        payload_pe=payload_path,
        anchor_manifest=anchor_path,
        payload_relocation_inventory=relocations,
        recovered_executable_data=executable_data_path,
        out_dir=output,
    )
    composition_path = output / COMPOSITION_MANIFEST_FILENAME
    candidate_path = output / CANDIDATE_FILENAME

    core: dict[str, Any] = {
        "format": INTERPRETER_NATIVE_BUILD_FORMAT,
        "status": "candidate-generated",
        "acceptance_authority": "none",
        "assurance": (
            "non-authorizing fail-closed diagnostic candidate"
            if candidate_mode == STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE
            else "candidate static and behavioral validation required"
        ),
        "inputs": {
            "candidate_authority": (
                None
                if receipt is None
                else _candidate_authority_manifest_binding(
                    candidate_authority, receipt
                )
            ),
            "execution_scope": structural_binding,
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
            "recovered_executable_data": (
                None
                if executable_data is None
                else {
                    "artifact_sha256": executable_data_artifact_sha256,
                    "contract_sha256": executable_data.to_payload()["hashes"][
                        "contract_sha256"
                    ],
                    "machine_ir_sha256": executable_data.machine_ir_sha256,
                    "ranges": len(executable_data.ranges),
                    "bytes": sum(item.size for item in executable_data.ranges),
                }
            ),
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
            "candidate_class": (
                "structural-diagnostic"
                if candidate_mode == STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE
                else "diagnostic-static-closed"
                if diagnostic_failure_trap
                else "release-static-closed"
            ),
            "allow_deferred_potential_transfers": (
                structural_binding["deferred_transfers"] > 0
            ),
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
