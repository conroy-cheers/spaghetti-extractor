"""Compile selected semantic providers into one native-realization payload."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.machine_overlay_v5 import render_component_dispatch_registry_v1
from ..components.bisimulation import ComponentBisimulationError
from ..components.contextual_bisimulation import validate_contextual_refinement_v2
from ..components.bisimulation_allocation_dependencies import allocation_dependencies
from ..native_realization.allocation_link import check_allocation_manifest_binding, check_portable_allocation_contexts
from ..native_realization.formats import (
    PORTABLE_DISPATCH_LINK_RECEIPT_V1_FORMAT,
)
from ..native_realization.context_link import (
    ExactContextLinkError, selected_context, bind_context_objects, finish_context,
)
from ..pe32.recovered_executable_data import load_recovered_executable_data_contract
from ..roundtrip_fuzz.image_io import (
    load_spx_load_image_contract,
)
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.qualification_v2 import SemanticProviderQualificationV2
from ..semantic_providers.selection_v2 import ImplementationSelectionV2
from ..semantic_providers.exact_context import exact_context_blockers, validate_proof_exact_context
from ..semantic_providers.slices_v2 import SemanticSliceV2Error
from ..transfer.plan import load_executable_transfer_plan
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
) -> tuple[
    dict[str, dict[str, Any]],
    set[str],
    list[dict[str, Any]],
]:
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
    context_blockers = exact_context_blockers(
        qualifications=[item for _path, item in records],
        definition_selections=selection.payload["definition_selections"],
        obligation_selections=selection.payload["obligation_selections"],
    )
    if context_blockers:
        raise CandidateNativeBuildError(
            f"selected provider exact context is unsatisfied: {context_blockers}"
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
    portable_dispatch_inputs = _portable_dispatch_inputs(
        selection=selection,
        qualification_records=records,
    )
    return by_source, set(expected), portable_dispatch_inputs


def _portable_dispatch_inputs(
    *,
    selection: ImplementationSelectionV2,
    qualification_records: Sequence[
        tuple[Path, SemanticProviderQualificationV2]
    ],
) -> list[dict[str, Any]]:
    """Recover proof-bound overlay rows for the selected portable domain."""

    def dependency_digest(
        qualification: SemanticProviderQualificationV2,
        prefix: str,
        context: str,
    ) -> str:
        values = [
            str(value).removeprefix(prefix)
            for value in qualification.payload["dependencies"]
            if str(value).startswith(prefix)
        ]
        if (
            len(values) != 1
            or len(values[0]) != 64
            or any(character not in "0123456789abcdef" for character in values[0])
        ):
            raise CandidateNativeBuildError(
                f"portable provider omits its unique {context} identity"
            )
        return values[0]

    selected = [
        dict(row)
        for row in selection.payload["definition_selections"]
        if row["provider_kind"] == "qualified_portable_c"
    ]
    if not selected:
        return []
    by_provider = {
        qualification.provider_id: (path, qualification)
        for path, qualification in qualification_records
    }
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in selected:
        grouped.setdefault(str(row["provider_id"]), []).append(row)

    result: list[dict[str, Any]] = []
    covered_definitions: set[str] = set()
    for provider_id, choices in sorted(grouped.items()):
        pair = by_provider.get(provider_id)
        if pair is None:
            raise CandidateNativeBuildError(
                f"portable dispatch provider is absent: {provider_id}"
            )
        qualification_path, qualification = pair
        if qualification.payload["status"] != "complete":
            raise CandidateNativeBuildError(
                f"portable dispatch provider is incomplete: {provider_id}"
            )
        proof_sha256 = dependency_digest(
            qualification,
            "contextual-refinement:",
            "contextual proof",
        )
        plan_sha256 = dependency_digest(
            qualification,
            "component-proof-plan:",
            "component proof plan",
        )
        exact_slice_sha256 = dependency_digest(
            qualification,
            "component-exact-c-slice:",
            "component exact-C slice",
        )
        root = qualification_path.parent
        manifest_path = root / "provider-object-manifest.json"
        manifest = _read_json_object(
            manifest_path, "portable provider object manifest"
        )
        manifest_core = {
            key: value for key, value in manifest.items()
            if key != "receipt_sha256"
        }
        if (
            manifest.get("receipt_sha256")
            != canonical_sha256_v3(manifest_core)
            or manifest.get("contextual_refinement_sha256") != proof_sha256
            or manifest.get("proof_plan_sha256") != plan_sha256
            or manifest.get("exact_c_slice_sha256") != exact_slice_sha256
            or manifest.get("semantic_slice_sha256")
            != qualification.semantic_slice.identity
            or not isinstance(manifest.get("implementation_sha256"), str)
            or len(manifest["implementation_sha256"]) != 64
        ):
            raise CandidateNativeBuildError(
                "portable provider dispatch manifest is stale"
            )
        proof_path = root / "contextual-refinement-result.json"
        proof_wrapper = _read_json_object(
            proof_path, "portable contextual refinement"
        )
        proof = proof_wrapper.get("proof")
        if not isinstance(proof, Mapping):
            raise CandidateNativeBuildError(
                "portable contextual refinement omits its proof"
            )
        proof_core = {
            key: value for key, value in proof.items()
            if key != "receipt_sha256"
        }
        proof_policy = proof.get("policy")
        proof_bindings = proof.get("bindings")
        proof_models = proof.get("models")
        proof_plan = _read_json_object(
            root / "component-proof-plan-v1.json",
            "portable component proof plan",
        )
        exact_slice = _read_json_object(
            root / "exact-c" / "component-exact-c-slice-v1.json",
            "portable component exact-C slice",
        )
        try:
            validate_proof_exact_context(proof_plan=proof_plan, qualification=qualification)
            exact_context = selected_context(
                qualification=qualification, selection=selection,
                qualifications=[item for _path, item in qualification_records],
            )
            validate_contextual_refinement_v2(
                proof,
                proof_plan=proof_plan,
                exact_c_slice=exact_slice,
                implementation_sha256=str(manifest["implementation_sha256"]),
            )
        except (ComponentBisimulationError, SemanticSliceV2Error, ExactContextLinkError) as exc:
            raise CandidateNativeBuildError(
                f"portable contextual refinement is invalid: {exc}"
            ) from exc
        if (
            proof_wrapper.get("status") != "satisfied"
            or proof_wrapper.get("receipt_sha256") != proof_sha256
            or proof.get("status") != "satisfied"
            or (proof.get("activation_authorized") is not True and exact_context is None)
            or proof.get("receipt_sha256") != canonical_sha256_v3(proof_core)
            or not isinstance(proof_policy, Mapping)
            or not isinstance(proof_bindings, Mapping)
            or not isinstance(proof_models, Mapping)
            or proof_bindings.get("proof_plan_sha256") != plan_sha256
            or proof_bindings.get("exact_c_slice_sha256")
            != exact_slice_sha256
            or proof_bindings.get("implementation_sha256")
            != manifest.get("implementation_sha256")
            or manifest.get("machine_overlay_source_sha256")
            != proof_models.get("machine_overlay_sha256")
            or proof_policy.get("proof_form")
            != "strong_cutpoint_bisimulation"
            or proof_policy.get("compiler_trusted") is not True
            or proof_policy.get("private_stack_disjoint_checked_image") is not True
            or proof_policy.get("path_enumeration_authorizes") is not False
            or proof_policy.get("partial_authority") is not False
        ):
            raise CandidateNativeBuildError(
                "portable contextual refinement is not strong authority"
            )
        if proof_models.get('reference_allocation_requirements'):
            check_allocation_manifest_binding(qualification=qualification, manifest=manifest,
                manifest_sha256=sha256_file(manifest_path))
        overlays = manifest.get("machine_overlays")
        manifest_objects = manifest.get("objects")
        if not isinstance(overlays, list) or any(
            not isinstance(row, Mapping) for row in overlays
        ) or not isinstance(manifest_objects, list) or any(
            not isinstance(row, Mapping) for row in manifest_objects
        ):
            raise CandidateNativeBuildError(
                "portable provider omits its machine-overlay/object inventory"
            )
        provider_object_sha256s = sorted(
            str(row.get("object_sha256", "")) for row in manifest_objects
        )
        if any(len(value) != 64 for value in provider_object_sha256s):
            raise CandidateNativeBuildError(
                "portable provider object inventory is malformed"
            )
        proved_overlay_object_sha256 = manifest.get(
            "machine_overlay_object_sha256"
        )
        proved_overlay_objects = [
            row
            for row in manifest_objects
            if row.get("object_sha256") == proved_overlay_object_sha256
            and row.get("source_sha256")
            == manifest.get("machine_overlay_source_sha256")
        ]
        if len(proved_overlay_objects) != 1:
            raise CandidateNativeBuildError(
                "portable provider has no unique proof-bound overlay object"
            )
        for choice in choices:
            symbol_id = str(choice["symbol_id"])
            prefix = "original:function:"
            if not symbol_id.startswith(prefix):
                raise CandidateNativeBuildError(
                    "portable dispatch selected a non-transfer definition"
                )
            unit_id = symbol_id[len(prefix) :]
            matches = [
                dict(overlay)
                for overlay in overlays
                if unit_id in overlay.get("owned_unit_ids", [])
                and overlay.get("symbol") == choice["native_symbol"]
            ]
            if len(matches) != 1:
                raise CandidateNativeBuildError(
                    "portable definition lacks one proof-bound overlay"
                )
            covered_definitions.add(str(choice["definition_id"]))
            key = (
                provider_id,
                str(matches[0].get("component_id", "")),
                str(matches[0].get("operation_id", "")),
            )
            existing = next(
                (item for item in result if tuple(item["key"]) == key),
                None,
            )
            if existing is not None:
                existing["selected_unit_ids"].append(unit_id)
                existing["selected_definition_ids"].append(
                    str(choice["definition_id"])
                )
                continue
            result.append(
                {
                    "key": list(key),
                    "provider_id": provider_id,
                    "qualification_sha256": qualification.identity,
                    "contextual_refinement_sha256": proof_sha256,
                    "contextual_proof_sha256": str(proof["receipt_sha256"]),
                    "provider_object_manifest_sha256": sha256_file(
                        manifest_path
                    ),
                    "selected_unit_ids": [unit_id],
                    "selected_definition_ids": [str(choice["definition_id"])],
                    "provider_object_sha256s": provider_object_sha256s,
                    "proved_overlay_object_sha256": proved_overlay_object_sha256,
                    "overlay": matches[0],
                    "allocation_context": allocation_dependencies(proof_models, matches[0]),
                    **({"exact_context": exact_context} if exact_context is not None else {}),
                }
            )
    if covered_definitions != {
        str(row["definition_id"]) for row in selected
    }:
        raise CandidateNativeBuildError(
            "portable dispatch proof coverage is incomplete"
        )
    for row in result:
        row["selected_unit_ids"] = sorted(set(row["selected_unit_ids"]))
        row["selected_definition_ids"] = sorted(
            set(row["selected_definition_ids"])
        )
    return sorted(result, key=lambda row: tuple(row["key"]))


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


_PORTABLE_REGISTRY_SYMBOLS = (
    "spx_region_override_count",
    "spx_region_override_lookup",
    "spx_region_overrides",
)


def _object_global_symbol_bindings(
    *, nm: Path, object_path: Path, environment: Mapping[str, str],
) -> dict[str, str]:
    try:
        output = subprocess.run(
            [
                str(nm), "-g", "--defined-only", "--format=posix",
                str(object_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=dict(environment),
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise CandidateNativeBuildError(
            f"cannot inspect linked object {object_path.name}: {exc}"
        ) from exc
    result: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        symbol = fields[0].removeprefix("_")
        kind = fields[1]
        binding = "weak" if kind in {"W", "V", "w", "v"} else "strong"
        previous = result.setdefault(symbol, binding)
        if previous != binding:
            raise CandidateNativeBuildError(
                f"object symbol {symbol!r} has ambiguous linkage"
            )
    return result


def _prepare_portable_dispatch_registry(
    *,
    portable_inputs: Sequence[Mapping[str, Any]],
    transfer_plan: Path | str,
    provider_qualifications: Sequence[Path | str],
    compiler: Path,
    nm: Path,
    object_paths: list[Path],
    object_rows: list[dict[str, Any]],
    objects: Path,
    output: Path,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    """Compile the sole strong module registry and bind every entry object."""

    if len(object_paths) != len(object_rows):
        raise CandidateNativeBuildError(
            "linked object paths and receipts are not aligned"
        )
    if not portable_inputs:
        return {"entries": [], "registry": None}
    symbol_owners: dict[str, list[tuple[str, Path, Mapping[str, Any]]]] = {}
    for path, row in zip(object_paths, object_rows, strict=True):
        for symbol, binding in _object_global_symbol_bindings(
            nm=nm, object_path=path, environment=environment
        ).items():
            symbol_owners.setdefault(symbol, []).append((binding, path, row))

    _payload, transfers = load_executable_transfer_plan(
        Path(transfer_plan), require_complete=True
    )
    rva_by_unit = {item.identity: item.rva_start for item in transfers}
    selected_unit_ids = {
        str(unit_id)
        for item in portable_inputs
        for unit_id in item["selected_unit_ids"]
    }
    portable_unit_rvas: dict[str, int] = {}
    for unit_id in sorted(selected_unit_ids):
        rva = rva_by_unit.get(unit_id)
        if rva is None:
            raise CandidateNativeBuildError(
                f"portable dispatch unit is absent from transfer plan: {unit_id}"
            )
        portable_unit_rvas[unit_id] = rva

    entry_receipts: list[dict[str, Any]] = []
    for item in portable_inputs:
        context = None
        if "exact_context" in item:
            try:
                context = bind_context_objects(item["exact_context"], object_rows=object_rows, symbol_owners=symbol_owners)
            except ExactContextLinkError as exc:
                raise CandidateNativeBuildError(str(exc)) from exc
        overlay = dict(item["overlay"])
        native_symbol = str(overlay.get("symbol", ""))
        owners = symbol_owners.get(native_symbol, [])
        if len(owners) != 1 or owners[0][0] != "strong":
            raise CandidateNativeBuildError(
                "portable overlay symbol is missing, weak, or duplicated: "
                + native_symbol
            )
        _binding, _path, object_row = owners[0]
        selected_provider = object_row.get("selected_provider")
        provider_ids = (
            selected_provider.get("provider_ids")
            if isinstance(selected_provider, Mapping)
            else None
        )
        qualification_sha256s = (
            selected_provider.get("qualification_sha256s")
            if isinstance(selected_provider, Mapping)
            else None
        )
        definition_ids = (
            selected_provider.get("definition_ids")
            if isinstance(selected_provider, Mapping)
            else None
        )
        if (
            object_row.get("object_sha256")
            != item["proved_overlay_object_sha256"]
            or not isinstance(selected_provider, Mapping)
            or not isinstance(provider_ids, list)
            or not isinstance(qualification_sha256s, list)
            or not isinstance(definition_ids, list)
            or str(item["provider_id"]) not in provider_ids
            or str(item["qualification_sha256"]) not in qualification_sha256s
            or not set(item["selected_definition_ids"]).issubset(
                set(definition_ids or [])
            )
        ):
            raise CandidateNativeBuildError(
                "portable overlay symbol owner is not proof-bound to its provider"
            )
        source = object_row.get("source")
        if not isinstance(source, Mapping):
            raise CandidateNativeBuildError(
                "portable overlay object omits source provenance"
            )
        entry_receipts.append(
            {
                "component_id": str(overlay["component_id"]),
                "operation_id": str(overlay["operation_id"]),
                "entry_unit_id": str(overlay["entry_unit_id"]),
                "owned_unit_ids": list(overlay["owned_unit_ids"]),
                "entry_rva": int(overlay["entry_rva"]),
                "native_symbol": native_symbol,
                "provider_id": str(item["provider_id"]),
                "qualification_sha256": str(item["qualification_sha256"]),
                "contextual_refinement_sha256": str(
                    item["contextual_refinement_sha256"]
                ),
                "contextual_proof_sha256": str(
                    item["contextual_proof_sha256"]
                ),
                "provider_object_manifest_sha256": str(
                    item["provider_object_manifest_sha256"]
                ),
                "implementation_source_sha256": str(source["sha256"]),
                "implementation_object_sha256": str(
                    object_row["object_sha256"]
                ),
                **({"exact_context": context} if context is not None else {}),
            }
        )

    registry: dict[str, Any] | None = None
    if portable_inputs:
        registry_source = render_component_dispatch_registry_v1(
            entries=[dict(item["overlay"]) for item in portable_inputs],
            portable_unit_rvas=portable_unit_rvas,
        )
        source_path = output / "portable-dispatch-registry.c"
        source_path.write_text(registry_source, encoding="ascii")
        source_sha256 = sha256_file(source_path)
        object_path = objects / f"{len(object_paths):03d}-portable-dispatch-registry.o"
        qualification_roots = {
            Path(path).parent for path in provider_qualifications
        }
        include_roots = sorted(
            {
                root / "exact-c"
                for root in qualification_roots
                if (root / "exact-c" / "state-machine-runtime.h").is_file()
            },
            key=str,
        )
        header_hashes = {
            sha256_file(root / "state-machine-runtime.h")
            for root in include_roots
        }
        if len(header_hashes) != 1:
            raise CandidateNativeBuildError(
                "portable dispatch registry lacks one state-machine ABI"
            )
        flags = native_build._common_compile_flags(source_sha256)
        native_build._run(
            [
                str(compiler), "-x", "c", "-c", str(source_path),
                "-o", str(object_path),
                *(
                    argument
                    for root in include_roots
                    for argument in ("-I", str(root))
                ),
                *flags,
            ],
            phase="compile strong portable dispatch registry",
            env=dict(environment),
        )
        bindings = _object_global_symbol_bindings(
            nm=nm, object_path=object_path, environment=environment
        )
        if any(
            bindings.get(symbol) != "strong"
            or symbol in symbol_owners
            for symbol in _PORTABLE_REGISTRY_SYMBOLS
        ):
            raise CandidateNativeBuildError(
                "portable dispatch registry symbols are missing, weak, or duplicated"
            )
        object_sha256 = sha256_file(object_path)
        object_paths.append(object_path)
        object_rows.append(
            {
                "source": {
                    "owner": "generated",
                    "role": "portable_dispatch_registry",
                    "path": source_path.name,
                    "sha256": source_sha256,
                },
                "language": "c",
                "object": object_path.relative_to(output).as_posix(),
                "object_sha256": object_sha256,
                "flags": flags,
                "cache": "generated_from_exact_portable_selection",
            }
        )
        registry = {
            "source_sha256": source_sha256,
            "object_sha256": object_sha256,
            "symbols": list(_PORTABLE_REGISTRY_SYMBOLS),
        }
    return {
        "entries": sorted(entry_receipts, key=lambda row: row["entry_rva"]),
        "registry": registry,
    }


def _finish_portable_dispatch_link_receipt(
    *,
    pending: Mapping[str, Any],
    implementation_selection: Path | str,
    linked_symbols: Mapping[str, int],
    payload: Path,
    linker_map: Path,
    output: Path,
) -> tuple[dict[str, Any], Path]:
    selection = ImplementationSelectionV2.load(Path(implementation_selection))
    entries: list[dict[str, Any]] = []
    for raw in pending["entries"]:
        row = dict(raw)
        if "exact_context" in row:
            try:
                row["exact_context"] = finish_context(row["exact_context"], linked_symbols=linked_symbols, selection_sha256=selection.identity)
            except ExactContextLinkError as exc:
                raise CandidateNativeBuildError(str(exc)) from exc
        native_symbol = str(row["native_symbol"])
        linked_rva = linked_symbols.get(native_symbol)
        if linked_rva is None:
            raise CandidateNativeBuildError(
                f"portable overlay symbol is absent from linker map: {native_symbol}"
            )
        entries.append({**row, "linked_rva": linked_rva})
    registry = pending.get("registry")
    linked_registry: dict[str, Any] | None = None
    if registry is not None:
        symbol_rvas = {
            symbol: linked_symbols.get(symbol)
            for symbol in registry["symbols"]
        }
        if any(value is None for value in symbol_rvas.values()):
            raise CandidateNativeBuildError(
                "portable dispatch registry is absent from linker map"
            )
        linked_registry = {
            "source_sha256": registry["source_sha256"],
            "object_sha256": registry["object_sha256"],
            "symbol_rvas": symbol_rvas,
        }
    core = {
        "format": PORTABLE_DISPATCH_LINK_RECEIPT_V1_FORMAT,
        "status": "complete",
        "activation_authorized": True,
        "bindings": {
            "implementation_selection_sha256": selection.identity,
            "payload_sha256": sha256_file(payload),
            "linker_map_sha256": sha256_file(linker_map),
        },
        "registry": linked_registry,
        "entries": entries,
        "policy": {
            "strong_module_registry_required_when_portable": True,
            "one_strong_implementation_symbol_per_entry": True,
            "exact_selected_object_membership_required": True,
            "contextual_bisimulation_authority_required": True,
            "weak_or_duplicate_fallback_forbidden": True,
            "source_only_authority": False,
        },
        "blockers": [],
    }
    receipt = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    path = output / "portable-dispatch-link-receipt.json"
    native_build._write_json(path, receipt)
    return receipt, path


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
        portable_dispatch_inputs,
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
    allocation_correspondence = check_portable_allocation_contexts(
        portable_inputs=portable_dispatch_inputs, object_manifest_path=native_realization_object_manifest,
        selection=ImplementationSelectionV2.load(Path(implementation_selection)),
        qualifications=[SemanticProviderQualificationV2.parse(_read_json_object(Path(path), 'allocation selected qualification'))
                        for path in provider_qualifications])
    if allocation_correspondence is not None:
        native_build._write_json(output / 'portable-allocation-correspondence.json', allocation_correspondence)
    portable_dispatch_pending = _prepare_portable_dispatch_registry(
        portable_inputs=portable_dispatch_inputs,
        transfer_plan=transfer_plan,
        provider_qualifications=provider_qualifications,
        compiler=toolchain.compiler,
        nm=toolchain.nm,
        object_paths=object_paths,
        object_rows=object_rows,
        objects=objects,
        output=output,
        environment=environment,
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
    portable_dispatch_receipt, portable_dispatch_receipt_path = (
        _finish_portable_dispatch_link_receipt(
            pending=portable_dispatch_pending,
            implementation_selection=implementation_selection,
            linked_symbols=linked_symbols,
            payload=payload_path,
            linker_map=linker_map,
            output=output,
        )
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
            "portable_dispatch_authority": (
                "strong-linked-registry-and-symbol-receipt-v1"
            ),
        },
        "objects": object_rows,
        "portable_dispatch_link_receipt": portable_dispatch_receipt,
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
            "portable_dispatch_link_receipt": _output_binding(
                portable_dispatch_receipt_path, output
            ),
            **({'portable_allocation_correspondence': _output_binding(
                output / 'portable-allocation-correspondence.json', output)} if allocation_correspondence is not None else {}),
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
