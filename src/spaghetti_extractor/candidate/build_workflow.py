"""Top-level orchestration for deterministic interpreter-native builds."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.formats import (
    INTERPRETER_NATIVE_BUILD_FORMAT,
    NATIVE_ENGINE_PACKAGE_FORMAT,
    NATIVE_RUNTIME_PACKAGE_FORMAT,
    SPX_INTERPRETER_PACKAGE_FORMAT,
)
from ..pe32.recovered_executable_data import load_recovered_executable_data_contract
from ..roundtrip_fuzz.image_io import (
    load_spx_load_image_contract,
)
from ..util import sha256_file
from . import native_build
from .authority import CandidateAuthorityV3Receipt
from .build_model import (
    INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME,
    INTERPRETER_NATIVE_BUNDLE_INDEX_FORMAT,
    INTERPRETER_NATIVE_OBJECT_FORMAT,
    INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT,
    INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT,
    CandidateNativeBuildError,
    _Artifact,
    _C_IDENTIFIER,
    _ENGINE_LAYOUT_FILENAME,
    _ENGINE_MANIFEST_FILENAME,
    _INTERPRETER_MANIFEST_FILENAME,
    _PAYLOAD_FILENAME,
    _PAYLOAD_MAP_FILENAME,
    _RELOCATION_INVENTORY_FILENAME,
)
from .build_objects import (
    _compiler_runtime,
    _load_native_object_graph,
    _load_precompiled_native_objects,
    _output_binding,
    _payload_symbol_rvas,
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
    _write_native_source_bundle,
)
from .build_validation import (
    _candidate_authority_manifest_binding,
    _candidate_manifest_pe_sha256,
    _load_package,
    _load_region_override_package,
    _validate_candidate_authority_package_bindings,
    _validate_candidate_authority_v3,
    _validate_structural_execution_v1,
    _validate_structural_candidate_package_bindings,
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
from .pe import (
    COMPOSITION_MANIFEST_FILENAME,
    compose_spx_pe,
)
from .runtime import NATIVE_RUNTIME_MANIFEST_FILENAME


def prepare_spx_interpreter_native_object_graph(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    native_runtime_package: Path | str,
    out_dir: Path | str,
    region_override_package: Path | str | None = None,
    compiler: Path | str = "i686-w64-mingw32-gcc",
    entry_symbol: str,
) -> dict[str, Any]:
    """Emit a deterministic per-source compile graph for Nix CA derivations."""

    if _C_IDENTIFIER.fullmatch(entry_symbol) is None:
        raise CandidateNativeBuildError(
            "payload entry symbol is not a C identifier"
        )
    interpreter = _load_package(
        interpreter_package,
        filename=_INTERPRETER_MANIFEST_FILENAME,
        owner="interpreter",
        expected_format=SPX_INTERPRETER_PACKAGE_FORMAT,
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


def compile_spx_interpreter_native_object(
    *, graph: Path | str, unit_id: str, out_dir: Path | str
) -> dict[str, Any]:
    """Compile exactly one graph unit and bind the object to its checked row."""

    graph_path, graph_payload = _load_native_object_graph(graph)
    matches = [row for row in graph_payload["units"] if row.get("id") == unit_id]
    if len(matches) != 1:
        raise CandidateNativeBuildError(
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
        raise CandidateNativeBuildError("native object source binding is stale")
    compiler = _file(row["compiler"]["path"], "native object compiler")
    if _native_compiler_binding(compiler) != row["compiler"]:
        raise CandidateNativeBuildError("native object compiler binding is stale")
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
    except native_build.CandidateNativeBuildError as exc:
        raise CandidateNativeBuildError(str(exc)) from exc
    if not object_path.is_file():
        raise CandidateNativeBuildError("compiler omitted cached native object")
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


def compile_spx_interpreter_native_source_bundle(
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
        raise CandidateNativeBuildError(
            "native source bundle compiler binding is stale"
        )
    roots = [
        bundle_root / "roots" / mapping["owner"]
        for mapping in payload["root_mappings"]
    ]
    arguments = [
        "-x",
        payload["language"],
        "-c",
        str(source),
        *sum((["-I", str(root)] for root in roots), []),
        *_compile_flags(payload["source"]["sha256"], roots),
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
    except native_build.CandidateNativeBuildError as exc:
        raise CandidateNativeBuildError(str(exc)) from exc
    if not object_path.is_file():
        raise CandidateNativeBuildError(
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


def assemble_spx_interpreter_native_objects(
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
            raise CandidateNativeBuildError("native object receipt self-hash is stale")
        unit_id = str(receipt.get("unit_id"))
        if unit_id in receipts:
            raise CandidateNativeBuildError("duplicate native object receipt")
        if receipt.get("format") != INTERPRETER_NATIVE_OBJECT_FORMAT:
            raise CandidateNativeBuildError("unsupported native object receipt format")
        receipts[unit_id] = (receipt_path.parent, receipt)
    expected_ids = [str(row["id"]) for row in graph_payload["units"]]
    if set(receipts) != set(expected_ids):
        raise CandidateNativeBuildError(
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
            raise CandidateNativeBuildError("native object compile-key binding is stale")
        source = root / str(receipt["object"]["path"])
        if not source.is_file() or sha256_file(source) != receipt["object"]["sha256"]:
            raise CandidateNativeBuildError("native object artifact binding is stale")
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
        "units": graph_payload["units"],
        "objects": rows,
        "counts": {"objects": len(rows)},
    }
    payload = {**core, "package_sha256": native_build._canonical_sha256(core)}
    native_build._write_json(output / "native-object-package.json", payload)
    return payload


def build_spx_interpreter_native_candidate(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    native_runtime_package: Path | str,
    candidate_authority: Path | str | None,
    final_authority: Path | str | None,
    structural_execution_receipt: Path | str | None = None,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    fallback_coverage_receipt: Path | str | None,
    component_runtime_package: Path | str | None,
    region_override_package: Path | str | None = None,
    load_image_contract: Path | str,
    recovered_executable_data: Path | str | None = None,
    out_dir: Path | str,
    native_ingress_plan: Path | str,
    candidate_filename: str,
    compiler: Path | str = "i686-w64-mingw32-gcc",
    payload_rva: int | None = None,
    precompiled_objects: Path | str | None = None,
) -> dict[str, Any]:
    """Compile and compose one explicitly classified interpreter candidate."""

    ingress_path = _file(native_ingress_plan, "native ingress plan")
    ingress_artifact_sha256 = sha256_file(ingress_path)
    ingress = _read_json_object(ingress_path, "native ingress plan")
    module_entries = [
        row for row in ingress.get("ingresses", [])
        if isinstance(row, Mapping)
        and row.get("role") in {"process_entry", "dll_entry"}
    ]
    if ingress.get("status") != "complete" or len(module_entries) != 1:
        raise CandidateNativeBuildError(
            "native build requires one complete module-entry ingress"
        )
    entry_symbol = module_entries[0].get("bridge_symbol")
    if not isinstance(entry_symbol, str) or _C_IDENTIFIER.fullmatch(entry_symbol) is None:
        raise CandidateNativeBuildError(
            "native ingress module-entry symbol is not a C identifier"
        )
    if (
        not isinstance(candidate_filename, str)
        or not candidate_filename
        or Path(candidate_filename).name != candidate_filename
    ):
        raise CandidateNativeBuildError("candidate filename must be a loader basename")

    if component_runtime_package is None:
        raise CandidateNativeBuildError(
            "structural candidates require component-runtime inputs"
        )
    structural_policy_binding: dict[str, Any] | None = None
    receipt: CandidateAuthorityV3Receipt | None = None
    if structural_execution_receipt is not None:
        structural_policy_binding = _validate_structural_execution_v1(
            receipt=structural_execution_receipt,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
        )
    elif candidate_authority is not None and final_authority is not None:
        if fallback_coverage_receipt is None:
            raise CandidateNativeBuildError(
                "legacy candidate authority requires fallback-coverage evidence"
            )
        receipt = _validate_candidate_authority_v3(
            receipt=candidate_authority,
            final_authority=final_authority,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
            fallback_coverage_receipt=fallback_coverage_receipt,
            component_runtime_package=component_runtime_package,
        )
    else:
        raise CandidateNativeBuildError(
            "candidate construction requires structural-executable-v1"
        )

    interpreter = _load_package(
        interpreter_package,
        filename=_INTERPRETER_MANIFEST_FILENAME,
        owner="interpreter",
        expected_format=SPX_INTERPRETER_PACKAGE_FORMAT,
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
    if receipt is not None:
        _validate_candidate_authority_package_bindings(receipt, interpreter, engine)
    structural_binding = _validate_structural_candidate_package_bindings(
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
    contract = load_spx_load_image_contract(contract_path)
    native_build._require_pe32_contract(contract)
    if contract.identity.pe_sha256 != _candidate_manifest_pe_sha256(
        machine_ir_manifest
    ):
        raise CandidateNativeBuildError(
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
            raise CandidateNativeBuildError(
                "recovered executable-data contract binds a different machine IR"
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
        raise CandidateNativeBuildError(
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
            except native_build.CandidateNativeBuildError as exc:
                raise CandidateNativeBuildError(str(exc)) from exc
            if not object_path.is_file():
                raise CandidateNativeBuildError(
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
    except native_build.CandidateNativeBuildError as exc:
        raise CandidateNativeBuildError(str(exc)) from exc
    if not raw_payload.is_file() or not linker_map.is_file():
        raise CandidateNativeBuildError(
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
            raise CandidateNativeBuildError(
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
        linked_symbols = _payload_symbol_rvas(
            linker_map, image_base=contract.identity.preferred_base
        )
        linked_entry_rva = linked_symbols.get(entry_symbol)
        if linked_entry_rva is None:
            raise CandidateNativeBuildError(
                f"linked payload map omits native ingress {entry_symbol}"
            )
        file_header = native_build._file_header(payload_pe)
        relocations_stripped = bool(
            int(file_header.Characteristics) & native_build._IMAGE_FILE_RELOCS_STRIPPED
        )
        payload_pe.close()
    except CandidateNativeBuildError:
        raise
    except Exception as exc:
        raise CandidateNativeBuildError(str(exc)) from exc

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
        raise CandidateNativeBuildError(
            "load-image contract changed during compilation"
        )
    if (
        executable_data_path is not None
        and sha256_file(executable_data_path) != executable_data_artifact_sha256
    ):
        raise CandidateNativeBuildError(
            "recovered executable-data contract changed during compilation"
        )
    if sha256_file(ingress_path) != ingress_artifact_sha256:
        raise CandidateNativeBuildError("native ingress plan changed during compilation")
    if sha256_file(compiler_runtime) != compiler_runtime_sha256:
        raise CandidateNativeBuildError(
            "compiler runtime changed during compilation"
        )
    assert component_runtime_package is not None
    if structural_execution_receipt is not None:
        repeated_policy = _validate_structural_execution_v1(
            receipt=structural_execution_receipt,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
        )
        if repeated_policy != structural_policy_binding:
            raise CandidateNativeBuildError(
                "structural-executable inputs changed during compilation"
            )
    else:
        assert candidate_authority is not None
        assert final_authority is not None
        assert fallback_coverage_receipt is not None
        assert receipt is not None
        repeated_receipt = _validate_candidate_authority_v3(
            receipt=candidate_authority,
            final_authority=final_authority,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
            fallback_coverage_receipt=fallback_coverage_receipt,
            component_runtime_package=component_runtime_package,
        )
        if repeated_receipt != receipt:
            raise CandidateNativeBuildError(
                "v3 candidate-authority inputs changed during compilation"
            )
    repeated_structural_binding = _validate_structural_candidate_package_bindings(
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        interpreter=interpreter,
        engine=engine,
        runtime=runtime,
        runtime_plan=runtime_plan,
    )
    if repeated_structural_binding != structural_binding:
        raise CandidateNativeBuildError(
            "candidate execution-scope inputs changed during compilation"
        )
    composition = compose_spx_pe(
        load_image_contract=contract_path,
        payload_pe=payload_path,
        entry_rva=linked_entry_rva,
        payload_relocation_inventory=relocations,
        recovered_executable_data=executable_data_path,
        out_dir=output,
        candidate_filename=candidate_filename,
    )
    composition_path = output / COMPOSITION_MANIFEST_FILENAME
    candidate_path = output / candidate_filename

    core: dict[str, Any] = {
        "format": INTERPRETER_NATIVE_BUILD_FORMAT,
        "status": "candidate-generated",
        "acceptance_authority": "none",
        "assurance": "candidate static and behavioral validation required",
        "inputs": {
            "candidate_authority": (
                None
                if candidate_authority is None or receipt is None
                else _candidate_authority_manifest_binding(candidate_authority, receipt)
            ),
            "structural_executable": structural_policy_binding,
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
            "native_ingress_plan": {
                "artifact_sha256": ingress_artifact_sha256,
                "plan_sha256": ingress.get("plan_sha256"),
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
                "structural-executable-hybrid"
                if structural_policy_binding is not None
                else "release-static-closed"
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
