"""Link, compose, decode, and receipt linked-semantic-module-v2.

This reuses the single native payload linker and PE32 composer.  V2 differs at
their input seam only: generated, portable, and qualified-runtime objects all
come from the explicit total provider selection, including every residual
obligation implementation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..candidate.build import build_native_realization_payload
from ..candidate.module_composer import compose_pe32_native_module
from ..candidate.project import write_pe32_module_interface
from ..roundtrip_fuzz.image_io import write_spx_load_image_contract
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.qualification_v2 import SemanticProviderQualificationV2
from ..semantic_providers.selection_v2 import ImplementationSelectionV2
from ..util import sha256_file
from .build import (
    NativeRealizationBuildError,
    _bridges,
    _checked_native_symbol,
    _json_object,
    _linked_payload_facts,
    _loader_surface,
    _pinned_layout_blockers,
    _pinned_layout_requirements,
    _resolved_environment_identity,
)
from .receipt_v2 import NativeRealizationV2, write_native_realization_v2


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _native_objects_v2(
    build_manifest: Mapping[str, Any],
) -> list[dict[str, Any]]:
    roles = {
        "behavioral_c": "generated_behavioral_c",
        "component": "portable_c",
        "portable_c": "portable_c",
        "generated": "loader_support",
    }
    role_priority = {
        "loader_support": 0,
        "generated_behavioral_c": 1,
        "portable_c": 2,
        "runtime": 3,
        "ingress": 4,
    }
    raw_objects = build_manifest.get("objects")
    if not isinstance(raw_objects, list):
        raise NativeRealizationBuildError(
            "V2 native build manifest omits its exact object inventory"
        )
    by_hash: dict[str, dict[str, Any]] = {}
    for raw in raw_objects:
        if not isinstance(raw, Mapping):
            raise NativeRealizationBuildError(
                "V2 native build object row is malformed"
            )
        digest = raw.get("object_sha256")
        source = raw.get("source")
        selected = raw.get("selected_provider", {})
        if (
            not isinstance(digest, str)
            or not isinstance(source, Mapping)
            or not isinstance(selected, Mapping)
        ):
            raise NativeRealizationBuildError(
                "V2 native build object lacks source or selection identity"
            )
        owner = source.get("owner")
        source_role = source.get("role")
        if not isinstance(owner, str) or not isinstance(source_role, str):
            raise NativeRealizationBuildError(
                "V2 native build object source ownership is malformed"
            )
        role = roles.get(owner, "runtime")
        if owner == "shared_module_runtime" and any(
            marker in source_role for marker in ("ingress", "bridge", "seh")
        ):
            role = "ingress"
        row = {
            "object_sha256": digest,
            "role": role,
            "provider_ids": sorted(set(selected.get("provider_ids", []))),
            "definition_ids": sorted(set(selected.get("definition_ids", []))),
            "obligation_ids": sorted(set(selected.get("obligation_ids", []))),
            "section_ids": [],
        }
        existing = by_hash.get(digest)
        if existing is None:
            by_hash[digest] = row
            continue
        for field in (
            "provider_ids", "definition_ids", "obligation_ids", "section_ids",
        ):
            existing[field] = sorted(set(existing[field]) | set(row[field]))
        if role_priority[role] > role_priority[str(existing["role"])]:
            existing["role"] = role
    return [by_hash[digest] for digest in sorted(by_hash)]


def _original_imports(
    original_interface: Mapping[str, Any],
) -> dict[tuple[str, str], list[Mapping[str, Any]]]:
    imports = original_interface.get("imports")
    if not isinstance(imports, list):
        raise NativeRealizationBuildError("original interface imports are malformed")
    result: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for raw in imports:
        if not isinstance(raw, Mapping):
            raise NativeRealizationBuildError("original import row is malformed")
        symbol = raw.get("symbol")
        identity = (
            str(raw.get("dll", "")).lower(),
            str(symbol) if symbol is not None else f"ordinal:{raw.get('ordinal')}",
        )
        result.setdefault(identity, []).append(raw)
    return result


def _realized_definitions_v2(
    *, linked: LinkedSemanticModuleV2,
    selection: ImplementationSelectionV2,
    original_interface: Mapping[str, Any],
    native_symbols: Mapping[str, Mapping[str, Any]],
    linked_sections: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if linked.semantic_object is None:
        raise NativeRealizationBuildError(
            "V2 definition realization requires the packaged semantic object"
        )
    semantic_symbols = {
        str(row["symbol_id"]): row
        for row in linked.semantic_object.payload["symbols"]
    }
    definitions = {
        str(row["definition_id"]): row for row in linked.payload["definitions"]
    }
    imports = _original_imports(original_interface)
    blockers: list[dict[str, Any]] = []
    realized: list[dict[str, Any]] = []
    for choice in selection.payload["definition_selections"]:
        definition_id = str(choice["definition_id"])
        definition = definitions[definition_id]
        symbol_id = str(choice["symbol_id"])
        semantic = semantic_symbols[symbol_id]
        implementation_rva: int | None = None
        if choice["provider_kind"] == "external_environment":
            declaration = semantic.get("declaration")
            if not isinstance(declaration, Mapping):
                raise NativeRealizationBuildError(
                    "external definition lacks its semantic declaration"
                )
            dll = declaration.get("dll")
            symbol = declaration.get("symbol")
            ordinal = declaration.get("ordinal")
            has_symbol = isinstance(symbol, str) and bool(symbol)
            has_ordinal = (
                isinstance(ordinal, int)
                and not isinstance(ordinal, bool)
                and ordinal >= 0
            )
            if (
                not isinstance(dll, str) or not dll
                or has_symbol == has_ordinal
            ):
                raise NativeRealizationBuildError(
                    "external definition has a malformed import identity"
                )
            identity = (
                dll.lower(),
                symbol if has_symbol else f"ordinal:{ordinal}",
            )
            matches = imports.get(identity, [])
            declaration_role = declaration.get("declaration_role")
            if len(matches) == 1:
                address = {
                    "kind": "loader_import", "iat_rva": int(matches[0]["iat_rva"]),
                }
            elif (
                not matches
                and declaration_role == "loader_service"
            ):
                loader_service_sha256 = declaration.get(
                    "loader_service_contract_sha256"
                )
                if (
                    not isinstance(loader_service_sha256, str)
                    or _SHA256.fullmatch(loader_service_sha256) is None
                ):
                    raise NativeRealizationBuildError(
                        "loader-resolved export lacks its exact service contract"
                    )
                address = {
                    "kind": "loader_resolved_export",
                    "dll": dll.lower(),
                    "symbol": symbol if has_symbol else None,
                    "ordinal": ordinal if has_ordinal else None,
                    "loader_service_contract_sha256": loader_service_sha256,
                }
            else:
                blockers.append({
                    "code": "external_import_address_unresolved",
                    "definition_id": definition_id,
                })
                address = {"kind": "loader_import", "iat_rva": 0}
        else:
            native = _checked_native_symbol(
                native_symbols, linked_sections, str(choice["native_symbol"]),
                executable=True,
            )
            if native is None:
                blockers.append({
                    "code": "native_definition_symbol_unresolved",
                    "definition_id": definition_id,
                    "native_symbol": choice["native_symbol"],
                })
            else:
                implementation_rva = int(native["rva"])
            if definition["definition_kind"] in {"image_object", "object_anchor"}:
                address = {
                    "kind": "object_anchor", "object_id": symbol_id, "offset": 0,
                }
            else:
                address = {
                    "kind": "linked_rva", "rva": implementation_rva or 0,
                }
        realized.append({
            **choice,
            "address": address,
            "implementation_rva": implementation_rva,
            "bridge_class_id": None,
        })
    return sorted(realized, key=lambda row: row["definition_id"]), blockers


def _realized_obligations_v2(
    *, selection: ImplementationSelectionV2,
    native_symbols: Mapping[str, Mapping[str, Any]],
    linked_sections: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    realized: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for choice in selection.payload["obligation_selections"]:
        native = _checked_native_symbol(
            native_symbols, linked_sections, str(choice["native_symbol"]),
            executable=True,
        )
        if native is None:
            blockers.append({
                "code": "native_obligation_symbol_unresolved",
                "obligation_id": choice["obligation_id"],
                "native_symbol": choice["native_symbol"],
            })
            rva = 0
        else:
            rva = int(native["rva"])
        realized.append({**choice, "implementation_rva": rva})
    return sorted(realized, key=lambda row: row["obligation_id"]), blockers


def _runtime_symbols_v2(
    *, ingress: Mapping[str, Any],
    selection: ImplementationSelectionV2,
    native_symbols: Mapping[str, Mapping[str, Any]],
    linked_sections: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    requirements: dict[str, tuple[str, bool | None]] = {}

    def require(symbol: object, role: str, executable: bool | None) -> None:
        if isinstance(symbol, str) and symbol:
            previous = requirements.setdefault(symbol, (role, executable))
            if previous[1] != executable:
                requirements[symbol] = (previous[0], None)

    for row in selection.payload["obligation_selections"]:
        require(row.get("native_symbol"), "residual_obligation", True)
    for row in ingress.get("bridges", []):
        if isinstance(row, Mapping):
            require(row.get("symbol"), "ingress_bridge", True)
    for protocol in ingress.get("seh_protocols", []):
        if not isinstance(protocol, Mapping):
            continue
        require(protocol.get("gateway_handler_symbol"), "seh_gateway", True)
        for portal in protocol.get("portals", []):
            if isinstance(portal, Mapping):
                require(portal.get("candidate_symbol"), "exception_portal", True)
    for row in ingress.get("support_symbols", []):
        if isinstance(row, Mapping):
            require(row.get("symbol"), "loader_support", None)

    realized: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for symbol, (role, executable) in sorted(requirements.items()):
        native = _checked_native_symbol(
            native_symbols, linked_sections, symbol, executable=executable
        )
        if native is None:
            blockers.append({
                "code": "required_runtime_symbol_unresolved",
                "native_symbol": symbol,
                "role": role,
            })
            rva = 0
        else:
            rva = int(native["rva"])
        realized.append({"symbol": symbol, "rva": rva, "role": role})
    return realized, blockers


def write_native_realization_v2_from_linked_payload(
    *, linked_semantic_module: Path, implementation_selection: Path,
    provider_qualifications: Sequence[Path], native_build_manifest: Path,
    linked_skeleton: Path, linked_relocations: Path,
    load_image_contract: Path, native_ingress_plan: Path,
    candidate_filename: str, out: Path,
    _linked: LinkedSemanticModuleV2 | None = None,
) -> NativeRealizationV2:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    linked = _linked or LinkedSemanticModuleV2.load(
        linked_semantic_module, require_complete=True
    )
    if linked.semantic_object is None:
        raise NativeRealizationBuildError(
            "V2 native realization requires the packaged semantic object"
        )
    semantic = linked.semantic_object
    original_module_interface = semantic.module_interface_path
    resolved_external_environment = semantic.resolved_external_environment_path
    object_authority = semantic.machine_object_authority_path
    original_interface = _json_object(
        original_module_interface, "original module interface"
    )
    selection = ImplementationSelectionV2.load(implementation_selection)
    qualifications = [
        SemanticProviderQualificationV2.load(Path(path))
        for path in provider_qualifications
    ]
    runtime_qualifications = [
        item for item in qualifications if item.provider_kind == "qualified_runtime"
    ]
    if len(runtime_qualifications) != 1:
        raise NativeRealizationBuildError(
            "V2 native realization requires one qualified-runtime provider"
        )
    runtime_qualification = runtime_qualifications[0]
    ingress = _json_object(native_ingress_plan, "native ingress plan")
    if ingress.get("status") != "complete":
        raise NativeRealizationBuildError(
            "V2 native realization requires a complete native ingress plan"
        )

    compose_pe32_native_module(
        linked_skeleton=linked_skeleton,
        linked_relocation_inventory=linked_relocations,
        load_image_contract=load_image_contract,
        recovered_executable_data=None,
        original_module_interface=original_module_interface,
        native_ingress_plan=native_ingress_plan,
        native_build_manifest=native_build_manifest,
        resolved_external_environment=resolved_external_environment,
        object_authority=object_authority,
        out=output,
        candidate_filename=candidate_filename,
    )
    candidate_module = output / candidate_filename
    candidate_load_contract = output / "candidate-load-image-contract.json"
    write_spx_load_image_contract(
        original_pe=candidate_module, out=candidate_load_contract
    )
    candidate_interface_root = output / "candidate-interface"
    write_pe32_module_interface(
        image_id=candidate_filename,
        original_pe=candidate_module,
        load_image_contract=candidate_load_contract,
        out=candidate_interface_root,
    )
    candidate_interface = _json_object(
        candidate_interface_root / "module-interface.json",
        "candidate module interface",
    )

    build_manifest, native_symbols, linked_sections = _linked_payload_facts(
        native_build_manifest
    )
    portable_dispatch_link_receipt = build_manifest.get(
        "portable_dispatch_link_receipt"
    )
    if not isinstance(portable_dispatch_link_receipt, Mapping):
        raise NativeRealizationBuildError(
            "V2 native build omits portable dispatch link authority"
        )
    native_objects = _native_objects_v2(build_manifest)
    definitions, definition_blockers = _realized_definitions_v2(
        linked=linked, selection=selection,
        original_interface=original_interface,
        native_symbols=native_symbols, linked_sections=linked_sections,
    )
    obligations, obligation_blockers = _realized_obligations_v2(
        selection=selection, native_symbols=native_symbols,
        linked_sections=linked_sections,
    )
    bridges, bridge_blockers = _bridges(
        ingress, native_symbols, linked_sections
    )
    required_symbols, runtime_symbol_blockers = _runtime_symbols_v2(
        ingress=ingress, selection=selection, native_symbols=native_symbols,
        linked_sections=linked_sections,
    )
    pinned_blockers = _pinned_layout_blockers(
        ingress=ingress, original_interface=original_interface,
        candidate_interface=candidate_interface,
        resolved_environment_sha256=_resolved_environment_identity(
            resolved_external_environment
        ),
    )
    support_import_ids = sorted({
        f"{str(row['dll']).lower()}!"
        + (
            str(row["symbol"])
            if row["symbol"] is not None
            else f"ordinal:{row['ordinal']}"
        )
        for row in ingress["required_support_imports"]
    })
    runtime = {
        "qualification_sha256": runtime_qualification.identity,
        "tls_layout_sha256": canonical_sha256_v3(ingress["tls_layout"]),
        "private_stack_size": ingress["runtime_requirements"][
            "private_stack_bytes"
        ],
        "support_import_ids": support_import_ids,
        "required_symbols": required_symbols,
        "obligation_receipt_sha256s": sorted({
            str(row["receipt_sha256"])
            for row in selection.payload["obligation_selections"]
        }),
    }
    manifest_root = Path(native_build_manifest).parent
    link = {
        "payload_sha256": sha256_file(manifest_root / "payload.exe"),
        "linker_map_sha256": sha256_file(manifest_root / "payload.map"),
        "relocation_inventory_sha256": sha256_file(
            manifest_root / "payload-relocations.json"
        ),
        "section_table_sha256": canonical_sha256_v3(linked_sections),
        "entry_symbols": sorted({
            str(row["symbol"]) for row in ingress["bridges"]
        }),
    }
    candidate = {
        "filename": candidate_filename,
        "sha256": sha256_file(candidate_module),
        "size": candidate_module.stat().st_size,
        "module_interface_sha256": candidate_interface["interface_sha256"],
    }
    pinned_requirements = _pinned_layout_requirements(
        ingress=ingress, candidate_sha256=candidate["sha256"],
        linker_layout_sha256=link["linker_map_sha256"],
    )
    return write_native_realization_v2(
        linked_semantic_module=linked_semantic_module,
        implementation_selection=implementation_selection,
        provider_qualifications=provider_qualifications,
        candidate_module=candidate_module,
        qualified_platform_sha256=linked.payload["bindings"].get(
            "qualified_platform_sha256"
        ),
        original_module_interface_sha256=original_interface["interface_sha256"],
        definitions=definitions, obligations=obligations,
        native_objects=native_objects, bridges=bridges, runtime=runtime,
        link=link,
        portable_dispatch_link_receipt=portable_dispatch_link_receipt,
        loader_surface=_loader_surface(candidate_interface),
        candidate=candidate,
        pinned_code_layout_requirements=pinned_requirements,
        blockers=[
            *definition_blockers, *obligation_blockers, *bridge_blockers,
            *runtime_symbol_blockers, *pinned_blockers,
        ],
        out=output,
    )


def write_native_realization_v2_candidate(
    *, linked_semantic_module: Path, implementation_selection: Path,
    provider_qualifications: Sequence[Path], load_image_contract: Path,
    compiler: Path, nm: Path, candidate_filename: str, out: Path,
    recovered_executable_data: Path | None = None,
) -> NativeRealizationV2:
    """Use selected provider packages as the sole object source and link once."""

    del nm  # The shared linker resolves and validates its own exact nm tool.
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    linked = LinkedSemanticModuleV2.load(
        linked_semantic_module, require_complete=True
    )
    if linked.semantic_object is None:
        raise NativeRealizationBuildError(
            "V2 native realization requires one packaged linked module"
        )
    qualification_paths = tuple(Path(path) for path in provider_qualifications)
    qualifications = [
        (path, SemanticProviderQualificationV2.load(path))
        for path in qualification_paths
    ]
    runtime_packages = [
        path.parent for path, item in qualifications
        if item.provider_kind == "qualified_runtime"
    ]
    if len(runtime_packages) != 1:
        raise NativeRealizationBuildError(
            "V2 native realization requires one qualified-runtime package"
        )
    runtime_root = runtime_packages[0]
    native_ingress_plan = runtime_root / "native-ingress-plan.json"
    runtime_object_manifest = (
        runtime_root / "native-realization-object-manifest.json"
    )
    if not native_ingress_plan.is_file() or not runtime_object_manifest.is_file():
        raise NativeRealizationBuildError(
            "qualified-runtime package omits ingress or exact objects"
        )

    build_native_realization_payload(
        transfer_plan=linked.semantic_object.transfer_plan_path,
        implementation_selection=implementation_selection,
        provider_qualifications=qualification_paths,
        native_realization_object_manifest=runtime_object_manifest,
        linked_semantic_module=linked_semantic_module,
        load_image_contract=load_image_contract,
        recovered_executable_data=recovered_executable_data,
        compiler=compiler, out_dir=output,
        native_ingress_plan=native_ingress_plan,
        candidate_filename=candidate_filename,
    )
    return write_native_realization_v2_from_linked_payload(
        linked_semantic_module=linked_semantic_module,
        implementation_selection=implementation_selection,
        provider_qualifications=qualification_paths,
        native_build_manifest=output / "native-realization-build-manifest.json",
        linked_skeleton=output / "payload.exe",
        linked_relocations=output / "payload-relocations.json",
        load_image_contract=load_image_contract,
        native_ingress_plan=native_ingress_plan,
        candidate_filename=candidate_filename,
        out=output, _linked=linked,
    )


__all__ = [
    "write_native_realization_v2_candidate",
    "write_native_realization_v2_from_linked_payload",
]
