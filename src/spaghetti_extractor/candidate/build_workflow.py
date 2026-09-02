"""Compile selected semantic providers into one native-realization payload."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..pe32.recovered_executable_data import load_recovered_executable_data_contract
from ..roundtrip_fuzz.image_io import (
    load_spx_load_image_contract,
)
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.qualification_v2 import SemanticProviderQualificationV2
from ..semantic_providers.selection_v2 import ImplementationSelectionV2
from ..util import sha256_file
from . import native_build
from .formats import NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT
from .build_model import (
    CandidateNativeBuildError,
    _C_IDENTIFIER,
    _RUNTIME_STATE_LAYOUT_FILENAME,
    _PAYLOAD_FILENAME,
    _PAYLOAD_MAP_FILENAME,
    _RELOCATION_INVENTORY_FILENAME,
)
from .build_objects import (
    _compiler_runtime,
    _output_binding,
    _payload_symbol_rvas,
)
from .build_validation import (
    _validate_linked_semantic_execution,
)
from .build_values import (
    _align_up,
    _file,
    _read_json_object,
    _u32,
)


def _selected_provider_object_sources(
    *, implementation_selection: Path | str,
    provider_qualifications: Sequence[Path | str],
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Resolve selected provider objects to their exact compiled sources."""

    selection_payload = _read_json_object(
        Path(implementation_selection), "implementation selection"
    )
    selection = ImplementationSelectionV2.parse(selection_payload)
    records = []
    for raw_path in provider_qualifications:
        path = Path(raw_path)
        qualification_payload = _read_json_object(
            path, "selected provider qualification"
        )
        qualification = SemanticProviderQualificationV2.parse(
            qualification_payload
        )
        records.append((path, qualification))
    qualifications = {item.provider_id: (path, item) for path, item in records}
    if len(qualifications) != len(records):
        raise CandidateNativeBuildError(
            "selected provider qualification identities overlap"
        )
    expected: dict[str, dict[str, Any]] = {}
    materialization_indexes: dict[str, dict[str, dict[str, Mapping[str, Any]]]] = {}
    for _path, qualification in records:
        materialization_indexes[qualification.provider_id] = {
            "definition": {
                str(row["definition_id"]): row
                for row in qualification.payload["definition_materializations"]
            },
            "obligation": {
                str(row["obligation_id"]): row
                for row in qualification.payload["obligation_implementations"]
            },
        }
    selected_rows: list[tuple[str, Mapping[str, Any]]] = []
    selected_rows.extend(
        ("definition", row)
        for row in selection.payload["definition_selections"]
    )
    selected_rows.extend(
        ("obligation", row)
        for row in selection.payload["obligation_selections"]
    )
    for subject_kind, choice in selected_rows:
        provider_id = str(choice["provider_id"])
        pair = qualifications.get(provider_id)
        if pair is None:
            raise CandidateNativeBuildError(
                f"selected provider qualification is missing: {provider_id}"
            )
        _, qualification = pair
        if (
            qualification.provider_kind != choice["provider_kind"]
            or qualification.identity != choice["qualification_sha256"]
        ):
            raise CandidateNativeBuildError(
                f"selected provider qualification is stale: {provider_id}"
            )
        if subject_kind == "definition":
            subject_id = str(choice["definition_id"])
            materialization = materialization_indexes[provider_id][
                "definition"
            ].get(subject_id)
        elif subject_kind == "obligation":
            subject_id = str(choice["obligation_id"])
            materialization = materialization_indexes[provider_id][
                "obligation"
            ].get(subject_id)
            if (
                materialization is not None
                and materialization["receipt_sha256"]
                != choice["receipt_sha256"]
            ):
                materialization = None
        if (
            materialization is None
            or materialization["native_symbol"] != choice["native_symbol"]
        ):
            raise CandidateNativeBuildError(
                f"selected provider {subject_kind} is absent or stale: "
                f"{subject_id}"
            )
        for digest in materialization["object_sha256s"]:
            row = expected.setdefault(digest, {
                "provider_ids": set(), "symbol_ids": set(),
                "definition_ids": set(), "obligation_ids": set(),
                "qualification_sha256s": set(), "provider_kinds": set(),
            })
            row["provider_ids"].add(provider_id)
            row[f"{subject_kind}_ids"].add(subject_id)
            row["qualification_sha256s"].add(qualification.identity)
            row["provider_kinds"].add(choice["provider_kind"])

    by_source: dict[str, dict[str, Any]] = {}
    scanned_roots: set[Path] = set()
    found_objects: set[str] = set()
    for qualification_path, _ in records:
        root = qualification_path.parent
        if root in scanned_roots:
            continue
        scanned_roots.add(root)
        for manifest_name in (
            "compile-receipt.json", "provider-object-manifest.json",
            "object-manifest.json", "native-realization-object-manifest.json",
        ):
            manifest_path = root / manifest_name
            if not manifest_path.is_file():
                continue
            manifest = _read_json_object(
                manifest_path, "selected provider object manifest"
            )
            rows = manifest.get("objects")
            if not isinstance(rows, list):
                raise CandidateNativeBuildError(
                    "selected provider object manifest has no object inventory"
                )
            for raw in rows:
                if not isinstance(raw, Mapping):
                    raise CandidateNativeBuildError(
                        "selected provider object manifest row is malformed"
                    )
                digest = raw.get("object_sha256", raw.get("sha256"))
                source_sha256 = raw.get("source_sha256")
                relative = raw.get("object", raw.get("path"))
                if digest not in expected:
                    continue
                if (
                    not isinstance(source_sha256, str)
                    or not isinstance(relative, str)
                ):
                    raise CandidateNativeBuildError(
                        "selected provider object lacks source provenance"
                    )
                object_path = root / relative
                if (
                    not object_path.is_file()
                    or sha256_file(object_path) != digest
                ):
                    raise CandidateNativeBuildError(
                        "selected provider object binding is stale"
                    )
                found_objects.add(digest)
                binding = {
                    "object_sha256": digest,
                    "object_path": object_path,
                    "source": raw.get("source"),
                    "source_owner": raw.get("source_owner"),
                    "source_role": raw.get("source_role"),
                    "language": raw.get("language"),
                    "flags": raw.get("flags", raw.get("compile_flags", [])),
                    "provider_ids": sorted(expected[digest]["provider_ids"]),
                    "symbol_ids": sorted(expected[digest]["symbol_ids"]),
                    "definition_ids": sorted(
                        expected[digest]["definition_ids"]
                    ),
                    "obligation_ids": sorted(
                        expected[digest]["obligation_ids"]
                    ),
                    "qualification_sha256s": sorted(
                        expected[digest]["qualification_sha256s"]
                    ),
                    "provider_kinds": sorted(
                        expected[digest]["provider_kinds"]
                    ),
                }
                previous = by_source.setdefault(source_sha256, binding)
                if previous["object_sha256"] != digest:
                    raise CandidateNativeBuildError(
                        "one selected provider source maps to unequal objects"
                    )
    missing = sorted(set(expected) - found_objects)
    if missing:
        raise CandidateNativeBuildError(
            "selected provider objects are not materialized: "
            + ", ".join(missing)
        )
    return by_source, set(expected)


def _stage_provider_objects(
    *,
    selected_objects_by_source: Mapping[str, Mapping[str, Any]],
    expected_selected_object_hashes: set[str],
    realization_objects_by_source: Mapping[str, Mapping[str, Any]],
    expected_realization_object_hashes: set[str],
    objects: Path,
    output: Path,
) -> tuple[list[Path], list[dict[str, Any]]]:
    """Stage the exact selected and intrinsic provider object union."""

    by_digest: dict[str, dict[str, Any]] = {}

    def add(
        source_sha256: str, binding: Mapping[str, Any], *, selected: bool,
    ) -> None:
        digest = binding.get("object_sha256")
        object_path = binding.get("object_path")
        if (
            not isinstance(digest, str)
            or not isinstance(object_path, Path)
            or not object_path.is_file()
            or sha256_file(object_path) != digest
        ):
            raise CandidateNativeBuildError(
                "provider object binding is absent or stale"
            )
        row = by_digest.setdefault(digest, {
            "bindings": [], "selected": False, "realization": False,
        })
        row["bindings"].append((source_sha256, dict(binding)))
        row["selected"] = bool(row["selected"] or selected)
        row["realization"] = bool(row["realization"] or not selected)

    for source_sha256, binding in realization_objects_by_source.items():
        add(source_sha256, binding, selected=False)
    for source_sha256, binding in selected_objects_by_source.items():
        add(source_sha256, binding, selected=True)

    selected_hashes = {
        digest for digest, row in by_digest.items() if row["selected"]
    }
    realization_hashes = {
        digest for digest, row in by_digest.items() if row["realization"]
    }
    if selected_hashes != expected_selected_object_hashes:
        raise CandidateNativeBuildError(
            "native link provider object inventory is incomplete"
        )
    if realization_hashes != expected_realization_object_hashes:
        raise CandidateNativeBuildError(
            "native link realization object inventory is incomplete"
        )

    def metadata(digest: str, row: Mapping[str, Any]) -> dict[str, Any]:
        bindings = row["bindings"]
        preferred = next(
            (binding for _source, binding in bindings
             if binding.get("source_owner") is not None),
            bindings[0][1],
        )
        provider_kinds = sorted({
            str(kind)
            for _source, binding in bindings
            for kind in binding.get("provider_kinds", ())
        })
        owner = preferred.get("source_owner")
        if not isinstance(owner, str) or not owner:
            owner = (
                "component"
                if provider_kinds == ["qualified_portable_c"]
                else "behavioral_c"
            )
        source = preferred.get("source")
        if not isinstance(source, str) or not source:
            source = f"provider-object/{digest}.o"
        role = preferred.get("source_role")
        if not isinstance(role, str) or not role:
            role = (
                "selected_portable_provider_object"
                if owner in {"component", "portable_c"}
                else f"behavioral_function:{Path(source).stem}"
            )
        language = preferred.get("language")
        if not isinstance(language, str) or not language:
            language = (
                "assembler-with-cpp"
                if Path(source).suffix.lower() == ".s"
                else "c"
            )
        flags = preferred.get("flags", [])
        if not isinstance(flags, list) or any(
            not isinstance(flag, str) for flag in flags
        ):
            raise CandidateNativeBuildError(
                "provider object compile flags are malformed"
            )
        object_paths = {
            Path(str(binding["object_path"])) for _source, binding in bindings
        }
        if len({sha256_file(path) for path in object_paths}) != 1:
            raise CandidateNativeBuildError(
                "one provider object resolves to unequal package bytes"
            )
        source_hashes = sorted({
            source_sha256 for source_sha256, _binding in bindings
        })
        return {
            "source": source,
            "owner": owner,
            "role": role,
            "language": language,
            "flags": flags,
            "object_path": sorted(object_paths, key=str)[0],
            "source_sha256": (
                source_hashes[0]
                if len(source_hashes) == 1
                else canonical_sha256_v3(source_hashes)
            ),
            "provider_ids": sorted({
                str(value) for _source, binding in bindings
                for value in binding.get("provider_ids", ())
            }),
            "symbol_ids": sorted({
                str(value) for _source, binding in bindings
                for value in binding.get("symbol_ids", ())
            }),
            "definition_ids": sorted({
                str(value) for _source, binding in bindings
                for value in binding.get("definition_ids", ())
            }),
            "obligation_ids": sorted({
                str(value) for _source, binding in bindings
                for value in binding.get("obligation_ids", ())
            }),
            "qualification_sha256s": sorted({
                str(value) for _source, binding in bindings
                for value in binding.get("qualification_sha256s", ())
            }),
        }

    prepared = [
        (digest, row, metadata(digest, row))
        for digest, row in by_digest.items()
    ]
    owner_order = {"behavioral_c": 0, "shared_module_runtime": 1}
    prepared.sort(key=lambda item: (
        item[2]["owner"] in {"component", "portable_c"},
        0 if item[2]["language"] == "assembler-with-cpp" else 1,
        owner_order.get(item[2]["owner"], 2),
        item[2]["source"],
        item[0],
    ))

    staged_paths: list[Path] = []
    staged_rows: list[dict[str, Any]] = []
    for index, (digest, row, prepared_row) in enumerate(prepared):
        destination = objects / f"{index:03d}-provider.o"
        shutil.copyfile(prepared_row["object_path"], destination)
        if sha256_file(destination) != digest:
            raise CandidateNativeBuildError(
                "provider object changed while staging"
            )
        staged_paths.append(destination)
        object_row: dict[str, Any] = {
            "source": {
                "owner": prepared_row["owner"],
                "role": prepared_row["role"],
                "path": prepared_row["source"],
                "sha256": prepared_row["source_sha256"],
            },
            "language": prepared_row["language"],
            "object": destination.relative_to(output).as_posix(),
            "object_sha256": digest,
            "flags": prepared_row["flags"],
            "cache": (
                "selected_provider_object_package"
                if row["selected"]
                else "native_realization_object_package"
            ),
        }
        if row["selected"]:
            selected_provider = {
                "provider_ids": prepared_row["provider_ids"],
                "symbol_ids": prepared_row["symbol_ids"],
                "qualification_sha256s": prepared_row[
                    "qualification_sha256s"
                ],
            }
            if prepared_row["definition_ids"]:
                selected_provider["definition_ids"] = prepared_row[
                    "definition_ids"
                ]
            if prepared_row["obligation_ids"]:
                selected_provider["obligation_ids"] = prepared_row[
                    "obligation_ids"
                ]
            object_row["selected_provider"] = selected_provider
        staged_rows.append(object_row)
    return staged_paths, staged_rows


def _native_realization_object_sources(
    manifest_path: Path | str,
) -> tuple[dict[str, dict[str, Any]], set[str], str]:
    """Load exact precompiled realization infrastructure by source hash."""

    path = Path(manifest_path)
    manifest = _read_json_object(path, "native realization object manifest")
    observed_identity = manifest.get("receipt_sha256")
    core = {
        key: value for key, value in manifest.items()
        if key != "receipt_sha256"
    }
    if (
        not isinstance(observed_identity, str)
        or observed_identity != canonical_sha256_v3(core)
    ):
        raise CandidateNativeBuildError(
            "native realization object manifest is stale"
        )
    rows = manifest.get("objects")
    if not isinstance(rows, list) or not rows:
        raise CandidateNativeBuildError(
            "native realization object manifest has no object inventory"
        )
    root = path.parent
    by_source: dict[str, dict[str, Any]] = {}
    object_hashes: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise CandidateNativeBuildError(
                "native realization object manifest row is malformed"
            )
        source_sha256 = raw.get("source_sha256")
        object_sha256 = raw.get("object_sha256")
        relative = raw.get("path")
        if not all(
            isinstance(value, str) and value
            for value in (source_sha256, object_sha256, relative)
        ):
            raise CandidateNativeBuildError(
                "native realization object binding is incomplete"
            )
        object_path = root / str(relative)
        if (
            not object_path.is_file()
            or sha256_file(object_path) != object_sha256
        ):
            raise CandidateNativeBuildError(
                "native realization object binding is stale"
            )
        binding = {
            "object_sha256": object_sha256,
            "object_path": object_path,
            "source": raw.get("source"),
            "source_owner": raw.get("source_owner"),
            "source_role": raw.get("source_role"),
            "language": raw.get("language"),
            "flags": raw.get("compile_flags", []),
        }
        previous = by_source.setdefault(str(source_sha256), binding)
        if previous["object_sha256"] != object_sha256:
            raise CandidateNativeBuildError(
                "one realization source maps to unequal objects"
            )
        if object_sha256 in object_hashes:
            raise CandidateNativeBuildError(
                "native realization object inventory is ambiguous"
            )
        object_hashes.add(str(object_sha256))
    return by_source, object_hashes, observed_identity


def build_native_realization_payload(
    *,
    transfer_plan: Path | str,
    load_image_contract: Path | str,
    recovered_executable_data: Path | str | None = None,
    out_dir: Path | str,
    native_ingress_plan: Path | str,
    candidate_filename: str,
    compiler: Path | str = "i686-w64-mingw32-gcc",
    payload_rva: int | None = None,
    implementation_selection: Path | str,
    provider_qualifications: Sequence[Path | str],
    native_realization_object_manifest: Path | str,
    linked_semantic_module: Path | str,
) -> dict[str, Any]:
    """Compile one selected linked semantic module into a PE32 payload."""

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

    structural_policy_binding = _validate_linked_semantic_execution(
        linked_semantic_module=linked_semantic_module,
        implementation_selection=implementation_selection,
        transfer_plan=transfer_plan,
    )
    linked = LinkedSemanticModuleV2.load(
        Path(linked_semantic_module), require_complete=True
    )
    if linked.semantic_object is None:
        raise CandidateNativeBuildError(
            "native realization requires a packaged semantic module V2"
        )
    resolved_external_environment = (
        linked.semantic_object.resolved_external_environment_path
    )
    machine_object_authority = (
        linked.semantic_object.machine_object_authority_path
    )

    contract_path = _file(load_image_contract, "load-image contract")
    contract_artifact_sha256 = sha256_file(contract_path)
    contract = load_spx_load_image_contract(contract_path)
    native_build._require_pe32_contract(contract)
    if (
        contract.identity.pe_sha256
        != structural_policy_binding["bindings"].get("pe_sha256")
    ):
        raise CandidateNativeBuildError(
            "load-image contract binds a different PE than the canonical "
            "transfer universe"
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
        if (
            structural_policy_binding["bindings"].get("machine_ir_sha256")
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

    (
        selected_objects_by_source,
        expected_selected_object_hashes,
    ) = _selected_provider_object_sources(
        implementation_selection=implementation_selection,
        provider_qualifications=provider_qualifications,
    )
    (
        realization_objects_by_source,
        expected_realization_object_hashes,
        realization_object_receipt_sha256,
    ) = _native_realization_object_sources(native_realization_object_manifest)
    object_paths, object_rows = _stage_provider_objects(
        selected_objects_by_source=selected_objects_by_source,
        expected_selected_object_hashes=expected_selected_object_hashes,
        realization_objects_by_source=realization_objects_by_source,
        expected_realization_object_hashes=expected_realization_object_hashes,
        objects=objects,
        output=output,
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
            phase="link freestanding behavioral payload",
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
        layout_payload, layout, layout_location = native_build._extract_runtime_state_layout(
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

    layout_path = output / _RUNTIME_STATE_LAYOUT_FILENAME
    layout_path.write_bytes(layout_payload)
    relocation_path = output / _RELOCATION_INVENTORY_FILENAME
    native_build._write_json(relocation_path, relocations.to_payload())
    raw_payload.unlink(missing_ok=True)

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
    repeated_policy = _validate_linked_semantic_execution(
        linked_semantic_module=linked_semantic_module,
        implementation_selection=implementation_selection,
        transfer_plan=transfer_plan,
    )
    if repeated_policy != structural_policy_binding:
        raise CandidateNativeBuildError(
            "structural-executable inputs changed during compilation"
        )
    core: dict[str, Any] = {
        "format": NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT,
        "status": "linked",
        "acceptance_authority": "none",
        "assurance": "composition and independent candidate observation required",
        "inputs": {
            "structural_executable": structural_policy_binding,
            "linked_semantic_module": {
                "artifact_sha256": sha256_file(Path(linked_semantic_module)),
                "receipt_sha256": linked.identity,
                "resolved_external_environment_sha256": sha256_file(
                    resolved_external_environment
                ),
                "machine_object_authority_sha256": sha256_file(
                    machine_object_authority
                ),
            },
            "selected_provider_objects": {
                "objects": len(expected_selected_object_hashes),
                "qualification_artifact_sha256s": sorted(
                    {
                        qualification_sha256
                        for row in object_rows
                        for qualification_sha256 in row.get(
                            "selected_provider", {}
                        ).get("qualification_sha256s", [])
                    }
                ),
            },
            "native_realization_objects": {
                "artifact_sha256": sha256_file(
                    Path(native_realization_object_manifest)
                ),
                "receipt_sha256": realization_object_receipt_sha256,
                "objects": len(expected_realization_object_hashes),
            },
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
            "candidate_class": "semantic-module-native-realization-payload",
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
            "object_compilation": "content-addressed-selected-provider-objects",
        },
        "objects": object_rows,
        "commands": {
            "compile_flags_policy": "deterministic-freestanding-proof-o0-v1",
            "link_flags": link_flags,
        },
        "outputs": {
            "payload": _output_binding(payload_path, output),
            "linker_map": _output_binding(linker_map, output),
            "runtime_state_layout": {
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
        output / "native-realization-build-manifest.json", manifest
    )
    return manifest
