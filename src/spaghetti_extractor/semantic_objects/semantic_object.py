"""Closed codec and faithful migration builder for ``semantic-object-v1``.

The exact package member ``executable-transfer-plan.json`` is the sole
executable body language.  Everything else is a relocatable index over facts
already checked by that plan or by pe32-module-interface-v2.  The first builder
is deliberately a non-authorizing migration shadow: typed link-time facts that
are not yet projected are represented as holes, never guessed.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .object_authority import MachineObjectAuthorityV2
from ..errors import ToolkitInputError
from ..external.resolved import ResolvedExternalEnvironmentV1
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..qualified_platform.selection import (
    select_isa_requirements_from_platform_v1,
)
from ..transfer.plan import parse_executable_transfer_plan
from ..transfer.operations import runtime_provider_requirements_v2
from ..transfer.exception_semantics import (
    CheckedExceptionTransitionV1,
    checked_exception_transition_from_payload_v1,
)
from ..util import json_dumps, sha256_bytes, write_json
from .formats import SEMANTIC_OBJECT_FORMAT
from .exception_projection import (
    load_exception_projection_inputs,
    project_exception_transitions,
)
from .loader_projection import (
    loader_section_storage_symbol_id,
    project_base_relocations,
    project_load_config_declarations,
    project_load_config_relocations,
    project_resource_declarations,
    project_resource_relocations,
    required_loader_section_storage_sections,
)


MAX_SEMANTIC_OBJECT_BYTES = 512 * 1024 * 1024
MAX_SEMANTIC_ROWS = 1_000_000
_FIELDS = {
    "format", "status", "role", "authority", "bindings",
    "members", "symbols", "definitions",
    "relocations", "effect_index", "roots", "platform_selection",
    "evidence", "holes", "counts",
    "semantic_object_sha256",
}


class SemanticObjectError(ToolkitInputError):
    """A semantic object failed closed."""


def _fail(message: str) -> None:
    raise SemanticObjectError(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{context} must be an array")
    if len(value) > MAX_SEMANTIC_ROWS:
        _fail(f"{context} exceeds the semantic-object row bound")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{context} must be nonempty text")
    return value


def _integer(value: object, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{context} must be a nonnegative integer")
    return value


def _sha256(value: object, context: str) -> str:
    text = _text(value, context)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        _fail(f"{context} must be lowercase SHA-256")
    return text


def _canonical_bytes(value: object) -> bytes:
    return (json_dumps(value) + "\n").encode("utf-8")


def _read_canonical_json(path: Path, context: str) -> tuple[dict[str, Any], str]:
    source = Path(path)
    try:
        size = source.stat().st_size
        if size > MAX_SEMANTIC_OBJECT_BYTES:
            _fail(f"{context} exceeds the semantic-object byte bound")
        data = source.read_bytes()
        value = json.loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    payload = dict(_mapping(value, context))
    canonical = _canonical_bytes(payload)
    if data != canonical:
        _fail(f"{context} is not canonical JSON")
    return payload, sha256_bytes(canonical)


def _read_json_payload(path: Path, context: str) -> dict[str, Any]:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_SEMANTIC_OBJECT_BYTES:
            _fail(f"{context} exceeds the semantic-object byte bound")
        value = json.loads(source.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    return dict(_mapping(value, context))


def _function_symbol_id(transfer_id: str) -> str:
    return f"original:function:{transfer_id}"


def _object_symbol_id(origin: str) -> str:
    return f"original:object:{origin}"


def _import_symbol_id(slot_id: str, *, delay: bool = False) -> str:
    namespace = "delay-import" if delay else "import"
    return f"external:{namespace}:{slot_id}"


def _runtime_primitive_symbol_id(provider: str) -> str:
    return f"platform:runtime-primitive:{provider}"


def _semantic_import_identity(call: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "dll": str(call["dll"]),
        "symbol": call["symbol"],
        "ordinal": call["ordinal"],
    }


def _semantic_import_symbol_id(identity: Mapping[str, Any]) -> str:
    return f"external:function-import:{canonical_sha256_v3(identity)[:24]}"


def _environment_contracts(
    environment: ResolvedExternalEnvironmentV1 | None,
) -> dict[str, Mapping[str, Any]]:
    if environment is None:
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    rows = list(environment.payload["machine_import_contracts"])
    for raw_service in environment.payload["loader_service_contracts"]:
        service = _mapping(raw_service, "resolved loader-service contract")
        catalog = service.get("resolution_catalog", [])
        if not isinstance(catalog, list):
            _fail("resolved loader-service resolution catalog is malformed")
        for raw_target in catalog:
            target = _mapping(raw_target, "resolved dynamic-export contract")
            if target.get("dynamic_export_kind") == "code":
                rows.append(target)
    for raw in rows:
        row = _mapping(raw, "resolved machine-import contract")
        identity = _mapping(row.get("identity"), "machine-import identity")
        boundary = row.get("boundary")
        if boundary is None:
            continue
        _mapping(boundary, "resolved machine-import boundary")
        key = canonical_sha256_v3(dict(identity))
        if key in result:
            if result[key] == row:
                continue
            _fail("resolved environment contains a duplicate import identity")
        result[key] = row
    return result


def _environment_loader_services(
    environment: ResolvedExternalEnvironmentV1 | None,
) -> dict[str, Mapping[str, Any]]:
    if environment is None:
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for raw in environment.payload["loader_service_contracts"]:
        row = _mapping(raw, "resolved loader-service contract")
        identity = _mapping(row.get("identity"), "loader-service identity")
        contract = _mapping(
            row.get("contract"), "resolved loader-service profile contract"
        )
        profile_payload = _mapping(
            contract.get("payload"), "resolved loader-service profile payload"
        )
        if not isinstance(profile_payload.get("loader_service"), Mapping):
            continue
        key = canonical_sha256_v3(dict(identity))
        if key in result:
            _fail("resolved environment contains a duplicate loader-service identity")
        result[key] = row
        catalog = row.get("resolution_catalog", [])
        if not isinstance(catalog, list):
            _fail("resolved loader-service resolution catalog is malformed")
        for raw_target in catalog:
            target = _mapping(raw_target, "resolved dynamic-export contract")
            if target.get("dynamic_export_kind") != "code":
                continue
            target_identity = _mapping(
                target.get("identity"), "dynamic-export identity"
            )
            target_key = canonical_sha256_v3(dict(target_identity))
            prior = result.get(target_key)
            if prior is not None and prior != row:
                _fail("dynamic-export identity has ambiguous loader services")
            result[target_key] = row
    return result


def _data_anchor_symbol_id(rva: int) -> str:
    return f"original:data-anchor:rva:{rva:08x}"


def _tls_anchor_symbol_id(role: str, rva: int) -> str:
    return f"original:tls:{role}:{rva:08x}"


def _import_rows(
    interface: Mapping[str, Any],
) -> list[tuple[bool, Mapping[str, Any]]]:
    return [
        (False, _mapping(row, "module import"))
        for row in interface["imports"]
    ] + [
        (True, _mapping(cell, "module delay import"))
        for descriptor in interface["delay_imports"]
        for cell in descriptor["cells"]
    ]


def _section_at(interface: Mapping[str, Any], rva: int) -> Mapping[str, Any] | None:
    for raw in interface["sections"]:
        row = _mapping(raw, "module section")
        start = int(row["rva"])
        if start <= rva < start + int(row["mapped_size"]):
            return row
    return None


def _project_symbols(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
    checked_exceptions: tuple[CheckedExceptionTransitionV1, ...] = (),
    resolved_environment: ResolvedExternalEnvironmentV1 | None = None,
) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
]:
    symbols: list[dict[str, Any]] = []
    definitions: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []
    environment_contracts = _environment_contracts(resolved_environment)
    loader_services = _environment_loader_services(resolved_environment)
    for raw in plan["transfers"]:
        transfer = _mapping(raw, "transfer")
        transfer_id = str(transfer["identity"])
        source = _mapping(transfer["source"], "transfer source")
        symbol_id = _function_symbol_id(transfer_id)
        symbols.append({
            "symbol_id": symbol_id,
            "kind": "function",
            "linkage": "module_local",
            "visibility": "private",
            "storage_class": "original_code",
            "logical_type": None,
            "physical_frame": None,
            "lifetime": "image",
            "permissions": {"read": True, "write": False, "execute": True},
            "original_rva": source["rva_start"],
        })
        definitions.append({
            "symbol_id": symbol_id,
            "definition_kind": "transfer_v2",
            "body": {
                "language": "executable-transfer-plan-v2",
                "member": "executable-transfer-plan.json",
                "transfer_id": transfer_id,
                "transfer_sha256": canonical_sha256_v3(transfer),
            },
            "source": dict(source),
        })
    headers = interface["runtime_headers"]
    header_origin = f"image:{interface['image_id']}:headers"
    header_symbol = _object_symbol_id(header_origin)
    symbols.append({
        "symbol_id": header_symbol,
        "kind": "data",
        "linkage": "module_local",
        "visibility": "loader",
        "storage_class": "image_headers",
        "logical_type": None,
        "physical_frame": None,
        "lifetime": "image",
        "permissions": {"read": True, "write": False, "execute": False},
        "original_rva": 0,
    })
    definitions.append({
        "symbol_id": header_symbol,
        "definition_kind": "image_object",
        "object": {
            "origin": header_origin,
            "extent": headers["size"],
            "header_bytes_sha256": headers["data_sha256"],
            "initialization": {
                "kind": "runtime_pe_headers",
                "member": "module-interface.json",
            },
        },
    })
    for raw in interface["sections"]:
        section = _mapping(raw, "module section")
        if section["executable"]:
            continue
        origin = str(section["default_object_origin"])
        symbol_id = _object_symbol_id(origin)
        symbols.append({
            "symbol_id": symbol_id,
            "kind": "data",
            "linkage": "module_local",
            "visibility": "private",
            "storage_class": "image_section",
            "logical_type": None,
            "physical_frame": None,
            "lifetime": "image",
            "permissions": dict(section["permissions"]),
            "original_rva": section["rva"],
        })
        definitions.append({
            "symbol_id": symbol_id,
            "definition_kind": "image_object",
            "object": {
                "origin": origin,
                "extent": section["mapped_size"],
                "section_index": section["index"],
                "section_name": section["name"],
            },
        })
    for section in required_loader_section_storage_sections(plan, interface):
        symbol_id = loader_section_storage_symbol_id(
            str(interface["image_id"]), int(section["index"])
        )
        symbols.append({
            "symbol_id": symbol_id,
            "kind": "loader_storage",
            "linkage": "module_local",
            "visibility": "loader",
            "storage_class": "executable_section_relocation_storage",
            "logical_type": None,
            "physical_frame": None,
            "lifetime": "image",
            "permissions": dict(section["permissions"]),
            "original_rva": section["rva"],
        })
        definitions.append({
            "symbol_id": symbol_id,
            "definition_kind": "loader_section_storage",
            "storage": {
                "extent": section["mapped_size"],
                "section_index": section["index"],
                "section_name": section["name"],
                "relocation_only": True,
            },
        })

    def add_anchor(
        *, symbol_id: str, anchor_kind: str, storage_class: str,
        rva: int, extent: int | None, lifetime: str, visibility: str,
        initialization: Mapping[str, Any],
    ) -> None:
        section = _section_at(interface, rva)
        if section is None or section["executable"]:
            holes.append({
                "kind": "data_anchor_object_missing",
                "subject": symbol_id,
                "detail": (
                    f"{anchor_kind} RVA {rva:#x} has no unique "
                    "non-executable section object"
                ),
            })
            return
        offset = rva - int(section["rva"])
        if extent is not None and offset + extent > int(section["mapped_size"]):
            holes.append({
                "kind": "data_anchor_extent_invalid",
                "subject": symbol_id,
                "detail": (
                    f"{anchor_kind} extent {extent} at RVA {rva:#x} "
                    "exceeds its containing section object"
                ),
            })
            return
        symbols.append({
            "symbol_id": symbol_id,
            "kind": "data_anchor",
            "linkage": "module_local",
            "visibility": visibility,
            "storage_class": storage_class,
            "logical_type": None,
            "physical_frame": None,
            "lifetime": lifetime,
            "permissions": dict(section["permissions"]),
            "original_rva": rva,
            "anchor_kind": anchor_kind,
        })
        definitions.append({
            "symbol_id": symbol_id,
            "definition_kind": "object_anchor",
            "anchor": {
                "parent_symbol": _object_symbol_id(
                    str(section["default_object_origin"])
                ),
                "offset": offset,
                "extent": extent,
                "initialization": dict(initialization),
            },
        })

    data_export_rvas = sorted({
        int(slot["rva"])
        for slot in interface["export_directory"]["slots"]
        if slot["kind"] == "data"
    })
    for rva in data_export_rvas:
        add_anchor(
            symbol_id=_data_anchor_symbol_id(rva),
            anchor_kind="data_export",
            storage_class="data_export_anchor",
            rva=rva,
            extent=None,
            lifetime="image",
            visibility="loader",
            initialization={
                "kind": "existing_image_bytes",
                "member": "module-interface.json",
            },
        )

    tls = interface["tls"]
    if tls is not None:
        template_rva = tls["template_rva"]
        if template_rva is not None:
            add_anchor(
                symbol_id=_tls_anchor_symbol_id("template", int(template_rva)),
                anchor_kind="tls_template",
                storage_class="tls_template",
                rva=int(template_rva),
                extent=int(tls["template_size"]) + int(tls["zero_fill_size"]),
                lifetime="thread",
                visibility="module",
                initialization={
                    "kind": "tls_template",
                    "member": "module-interface.json",
                    "template_sha256": tls["template_sha256"],
                    "template_size": tls["template_size"],
                    "zero_fill_size": tls["zero_fill_size"],
                },
            )
        index_rva = tls["index_rva"]
        if index_rva is not None:
            add_anchor(
                symbol_id=_tls_anchor_symbol_id("index", int(index_rva)),
                anchor_kind="tls_index_cell",
                storage_class="tls_index_cell",
                rva=int(index_rva), extent=4, lifetime="image",
                visibility="loader",
                initialization={
                    "kind": "loader_tls_index", "size": 4,
                },
            )
        callback_array_rva = tls["callback_array_rva"]
        if callback_array_rva is not None:
            add_anchor(
                symbol_id=_tls_anchor_symbol_id(
                    "callback-array", int(callback_array_rva)
                ),
                anchor_kind="tls_callback_array",
                storage_class="tls_callback_array",
                rva=int(callback_array_rva),
                extent=4 * (len(tls["callbacks"]) + 1),
                lifetime="image",
                visibility="loader",
                initialization={
                    "kind": "tls_callback_array",
                    "callback_count": len(tls["callbacks"]),
                    "member": "module-interface.json",
                },
            )
    for delay, row in _import_rows(interface):
        identity = {
            "dll": row["dll"],
            "symbol": row["symbol"],
            "ordinal": row["ordinal"],
        }
        identity_sha256 = canonical_sha256_v3(identity)
        contract = environment_contracts.get(identity_sha256)
        loader_service = (
            loader_services.get(identity_sha256)
            if contract is not None else None
        )
        symbols.append({
            "symbol_id": _import_symbol_id(str(row["slot_id"]), delay=delay),
            "kind": "unclassified_import",
            "linkage": "external",
            "visibility": "loader",
            "storage_class": "delay_iat_slot" if delay else "iat_slot",
            "logical_type": None,
            "physical_frame": None,
            "lifetime": "image",
            "permissions": None,
            "original_rva": row["iat_rva"],
            "declaration": {
                "namespace": "original_loader_delay_import_slot"
                if delay else "original_loader_import_slot",
                "image_id": interface["image_id"],
                "slot_id": row["slot_id"],
                "descriptor_index": row["descriptor_index"],
                "cell_index": row["cell_index"],
                "iat_rva": row["iat_rva"],
                "dll": row["dll"],
                "symbol": row["symbol"],
                "ordinal": row["ordinal"],
                "environment_contract_sha256": (
                    None if contract is None
                    else canonical_sha256_v3(dict(contract))
                ),
                "loader_service_contract_sha256": (
                    None if loader_service is None
                    else canonical_sha256_v3(dict(loader_service))
                ),
                "declaration_role": (
                    "loader_service" if loader_service is not None
                    else "machine_import"
                ),
            },
        })
    # The resolved environment is the checked catalog of callable loader
    # values available to an indirect call.  Declare that whole catalog here,
    # even when a contract has no statically named call site.  V2 may-reach
    # decides which declarations become active; the semantic linker must not
    # synthesize a second, subtly different external-symbol model later.
    semantic_imports: dict[str, dict[str, Any]] = {}

    def add_semantic_import(identity: Mapping[str, Any]) -> None:
        normalized = {
            "dll": str(identity["dll"]),
            "symbol": identity.get("symbol"),
            "ordinal": identity.get("ordinal"),
        }
        symbol_id = _semantic_import_symbol_id(normalized)
        previous = semantic_imports.get(symbol_id)
        if previous is not None and previous != normalized:
            _fail("semantic import identity hash collision")
        semantic_imports[symbol_id] = normalized

    for contract in environment_contracts.values():
        add_semantic_import(_mapping(
            contract.get("identity"), "resolved semantic-import identity"
        ))
    for transfer in plan["transfers"]:
        for raw_call in transfer["calls"]:
            call = _mapping(raw_call, "transfer call")
            if call["kind"] != "external_call":
                continue
            add_semantic_import(_semantic_import_identity(call))
    for symbol_id, identity in semantic_imports.items():
        identity_sha256 = canonical_sha256_v3(identity)
        contract = environment_contracts.get(identity_sha256)
        loader_service = (
            loader_services.get(identity_sha256)
            if contract is not None else None
        )
        raw_boundary = None if contract is None else contract.get("boundary")
        boundary = None if raw_boundary is None else _mapping(
            raw_boundary, "resolved import boundary"
        )
        schema = None if boundary is None else _mapping(
            boundary.get("schema"), "resolved boundary schema"
        )
        symbols.append({
            "symbol_id": symbol_id,
            "kind": "external_function",
            "linkage": "external",
            "visibility": "semantic_link",
            "storage_class": "original_semantic_import",
            "logical_type": (
                None if schema is None else schema.get("schema_sha256")
            ),
            "physical_frame": (
                None if boundary is None
                else boundary.get("physical_call_frame_v3")
            ),
            "lifetime": "process",
            "permissions": {"read": True, "write": False, "execute": True},
            "original_rva": None,
            "declaration": {
                "namespace": "original_semantic_import",
                **identity,
                "environment_contract_sha256": (
                    None if contract is None
                    else canonical_sha256_v3(dict(contract))
                ),
                "loader_service_contract_sha256": (
                    None if loader_service is None
                    else canonical_sha256_v3(dict(loader_service))
                ),
                "declaration_role": (
                    "loader_service" if loader_service is not None
                    else "machine_import"
                ),
            },
        })
    for provider in plan["runtime_provider_requirements"]:
        symbols.append({
            "symbol_id": _runtime_primitive_symbol_id(str(provider)),
            "kind": "runtime_primitive",
            "linkage": "external",
            "visibility": "platform",
            "storage_class": "generated_runtime_support",
            "logical_type": None,
            "physical_frame": None,
            "lifetime": "module",
            "permissions": None,
            "original_rva": None,
            "declaration": {
                "namespace": "generated_runtime_support",
                "provider_id": provider,
                "source": "executable-transfer-plan-v2",
            },
        })
    loader_symbols, loader_definitions, loader_holes = (
        project_load_config_declarations(interface)
    )
    symbols.extend(loader_symbols)
    definitions.extend(loader_definitions)
    holes.extend(loader_holes)
    resource_symbols, resource_definitions, resource_holes = (
        project_resource_declarations(interface)
    )
    symbols.extend(resource_symbols)
    definitions.extend(resource_definitions)
    holes.extend(resource_holes)
    exception_symbols, exception_definitions, _, exception_holes = (
        project_exception_transitions(
            checked_exceptions,
            {str(row["identity"]): row for row in plan["transfers"]},
        )
    )
    symbols.extend(exception_symbols)
    definitions.extend(exception_definitions)
    holes.extend(
        row for row in exception_holes
        if row["kind"] == "exception_transition_not_authoritative"
    )
    symbols.sort(key=lambda row: str(row["symbol_id"]))
    definitions.sort(key=lambda row: str(row["symbol_id"]))
    holes.sort(key=lambda row: (
        str(row["kind"]), str(row["subject"]), str(row["detail"])
    ))
    return symbols, definitions, holes


def _project_relocations(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
    checked_exceptions: tuple[CheckedExceptionTransitionV1, ...] = (),
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []
    transfer_by_rva = {
        int(row["source"]["rva_start"]): _function_symbol_id(str(row["identity"]))
        for row in plan["transfers"]
    }
    for delay, row in _import_rows(interface):
        rva = int(row["iat_rva"])
        section = _section_at(interface, rva)
        source_symbol = None
        offset = None
        if section is not None and not section["executable"]:
            source_symbol = _object_symbol_id(str(section["default_object_origin"]))
            offset = rva - int(section["rva"])
        result.append({
            "relocation_id": f"loader:{'delay-iat' if delay else 'iat'}:{row['slot_id']}",
            "kind": "delay_iat_slot" if delay else "iat_slot",
            "source_symbol": source_symbol,
            "source_rva": rva,
            "offset": offset,
            "site": {"kind": "loader_slot", "iat_rva": rva},
            "target_symbol": _import_symbol_id(str(row["slot_id"]), delay=delay),
            "target_rva": None,
            "selector_value": None,
            "addend": 0,
            "required_view": None,
            "status": "unresolved",
        })

    coordinate_counts: dict[tuple[str, int, int], int] = {}
    for raw in plan["direct_control_edges"]:
        edge = _mapping(raw, "direct control edge")
        source_rva = int(edge["source_rva"])
        target_rva = int(edge["target_rva"])
        edge_kind = str(edge["kind"])
        if edge_kind == "internal_call":
            continue
        if edge_kind != "control":
            _fail(f"unsupported direct control edge kind: {edge_kind}")
        coordinate = (edge_kind, source_rva, target_rva)
        occurrence = coordinate_counts.get(coordinate, 0)
        coordinate_counts[coordinate] = occurrence + 1
        relocation_id = (
            f"transfer:{edge_kind}:{source_rva:08x}:{target_rva:08x}:"
            f"{occurrence}"
        )
        source_symbol = transfer_by_rva.get(source_rva)
        target_symbol = transfer_by_rva.get(target_rva)
        result.append({
            "relocation_id": relocation_id,
            "kind": "internal_call" if edge_kind == "internal_call"
            else "direct_control",
            "source_symbol": source_symbol,
            "source_rva": source_rva,
            "offset": None,
            "site": {
                "kind": "transfer_outcome",
                "source_rva": source_rva,
            },
            "target_symbol": target_symbol,
            "target_rva": target_rva,
            "selector_value": None,
            "addend": 0,
            "required_view": {"kind": "code_capability"},
            "status": "resolved_local" if (
                source_symbol is not None and target_symbol is not None
            ) else "unresolved",
        })
        if source_symbol is None or target_symbol is None:
            holes.append({
                "kind": "internal_code_relocation_unresolved",
                "subject": relocation_id,
                "detail": (
                    f"transfer edge {source_rva:#x} -> {target_rva:#x} "
                    "does not resolve to two exact transfer symbols"
                ),
            })

    for transfer in plan["transfers"]:
        source_rva = int(transfer["source"]["rva_start"])
        source_symbol = transfer_by_rva[source_rva]
        for raw_call in transfer["calls"]:
            call = _mapping(raw_call, "transfer call")
            call_id = int(call["id"])
            instruction_rva = int(call["instruction_rva"])
            event_index = int(call["event_index"])
            site = {
                "kind": "call",
                "call_id": call_id,
                "event_index": event_index,
                "instruction_rva": instruction_rva,
                "return_rva": int(call["return_rva"]),
            }
            if call["kind"] == "internal_call":
                target_rva = int(call["target_rva"])
                target_symbol = transfer_by_rva.get(target_rva)
                relocation_id = (
                    f"transfer:internal-call:{source_rva:08x}:"
                    f"{call_id}:{instruction_rva:08x}:{target_rva:08x}"
                )
                result.append({
                    "relocation_id": relocation_id,
                    "kind": "internal_call",
                    "source_symbol": source_symbol,
                    "source_rva": source_rva,
                    "offset": None,
                    "site": site,
                    "target_symbol": target_symbol,
                    "target_rva": target_rva,
                    "selector_value": None,
                    "addend": 0,
                    "required_view": {"kind": "code_capability"},
                    "status": "resolved_local" if target_symbol is not None
                    else "unresolved",
                })
                if target_symbol is None:
                    holes.append({
                        "kind": "internal_code_relocation_unresolved",
                        "subject": relocation_id,
                        "detail": (
                            f"internal call at {instruction_rva:#x} targets "
                            f"{target_rva:#x}, which has no exact transfer symbol"
                        ),
                    })
                continue
            if call["kind"] == "indirect_call":
                target_node = int(call["target_node"])
                relocation_id = (
                    f"transfer:indirect-call:{source_rva:08x}:"
                    f"{call_id}:{instruction_rva:08x}:{target_node}"
                )
                result.append({
                    "relocation_id": relocation_id,
                    "kind": "indirect_call",
                    "source_symbol": source_symbol,
                    "source_rva": source_rva,
                    "offset": None,
                    "site": {**site, "target_expression_node": target_node},
                    "target_symbol": None,
                    "target_rva": None,
                    "selector_value": None,
                    "addend": 0,
                    "required_view": {"kind": "code_capability"},
                    "status": "unresolved_indirect",
                })
                holes.append({
                    "kind": "indirect_code_relocation_unlinked",
                    "subject": relocation_id,
                    "detail": (
                        f"indirect call at {instruction_rva:#x} requires a "
                        "checked finite code-capability target set"
                    ),
                })
                continue
            if call["kind"] != "external_call":
                _fail(f"unsupported transfer call kind: {call['kind']}")
            identity = _semantic_import_identity(call)
            target_symbol = _semantic_import_symbol_id(identity)
            relocation_id = (
                f"transfer:external-call:{source_rva:08x}:"
                f"{call_id}:{instruction_rva:08x}:"
                f"{canonical_sha256_v3(identity)[:24]}"
            )
            result.append({
                "relocation_id": relocation_id,
                "kind": "external_call",
                "source_symbol": source_symbol,
                "source_rva": source_rva,
                "offset": None,
                "site": site,
                "target_symbol": target_symbol,
                "target_rva": None,
                "selector_value": None,
                "addend": 0,
                "required_view": {"kind": "code_capability"},
                "status": "unresolved_external",
            })

    for raw in plan["finite_control_routes"]:
        inventory = _mapping(raw, "finite control route inventory")
        source_rva = int(inventory["source_rva"])
        source_symbol = transfer_by_rva.get(source_rva)
        for raw_route in inventory["routes"]:
            route = _mapping(raw_route, "finite control route")
            selector = int(route["selector_value"])
            target_rva = int(route["target_rva"])
            target_symbol = transfer_by_rva.get(target_rva)
            relocation_id = (
                f"transfer:finite-control:{source_rva:08x}:"
                f"{selector:08x}:{target_rva:08x}"
            )
            result.append({
                "relocation_id": relocation_id,
                "kind": "finite_control_target",
                "source_symbol": source_symbol,
                "source_rva": source_rva,
                "offset": None,
                "site": {
                    "kind": "finite_control_route",
                    "source_rva": source_rva,
                    "selector_value": selector,
                },
                "target_symbol": target_symbol,
                "target_rva": target_rva,
                "selector_value": selector,
                "addend": 0,
                "required_view": {"kind": "code_capability"},
                "status": "resolved_local" if (
                    source_symbol is not None and target_symbol is not None
                ) else "unresolved",
            })
            if source_symbol is None or target_symbol is None:
                holes.append({
                    "kind": "finite_code_relocation_unresolved",
                    "subject": relocation_id,
                    "detail": (
                        f"finite route {source_rva:#x}[{selector}] -> "
                        f"{target_rva:#x} does not resolve to two exact "
                        "transfer symbols"
                    ),
                })
    loader_relocations, loader_holes = project_load_config_relocations(
        plan, interface
    )
    result.extend(loader_relocations)
    holes.extend(loader_holes)
    base_relocations, base_holes = project_base_relocations(plan, interface)
    result.extend(base_relocations)
    holes.extend(base_holes)
    resource_relocations, resource_holes = project_resource_relocations(
        interface
    )
    result.extend(resource_relocations)
    holes.extend(resource_holes)
    _, _, exception_relocations, exception_holes = (
        project_exception_transitions(
            checked_exceptions,
            {str(row["identity"]): row for row in plan["transfers"]},
        )
    )
    result.extend(exception_relocations)
    holes.extend(
        row for row in exception_holes
        if row["kind"] == "exception_code_relocation_unresolved"
    )
    return (
        sorted(result, key=lambda row: str(row["relocation_id"])),
        sorted(holes, key=lambda row: (
            str(row["kind"]), str(row["subject"]), str(row["detail"])
        )),
    )


def _project_roots(
    plan: Mapping[str, Any], interface: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    transfer_by_rva = {
        int(row["source"]["rva_start"]): _function_symbol_id(str(row["identity"]))
        for row in plan["transfers"]
    }
    roots: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []

    def code_root(
        *, root_id: str, kind: str, rva: int, names: list[str] | None = None,
        ordinal: int | None = None, order: int | None = None,
    ) -> None:
        target = transfer_by_rva.get(rva)
        roots.append({
            "root_id": root_id,
            "kind": kind,
            "original_rva": rva,
            "target_symbol": target,
            "object_offset": None,
            "export_names": names or [],
            "ordinal": ordinal,
            "forwarder": None,
            "order": order,
        })
        if target is None:
            holes.append({
                "kind": "root_transfer_missing",
                "subject": root_id,
                "detail": f"no transfer begins at RVA {rva:#x}",
            })

    loader = interface["loader"]
    if loader["entry_rva"]:
        code_root(
            root_id=f"module:{loader['entry_kind']}",
            kind=str(loader["entry_kind"]),
            rva=int(loader["entry_rva"]),
        )
    for slot in interface["export_directory"]["slots"]:
        if slot["kind"] == "hole":
            continue
        root_id = f"export:ordinal:{slot['ordinal']}"
        if slot["kind"] == "code":
            code_root(
                root_id=root_id, kind="export", rva=int(slot["rva"]),
                names=list(slot["names"]), ordinal=int(slot["ordinal"]),
            )
        elif slot["kind"] == "data":
            section = _section_at(interface, int(slot["rva"]))
            target = (
                None if section is None or section["executable"] else
                _data_anchor_symbol_id(int(slot["rva"]))
            )
            roots.append({
                "root_id": root_id, "kind": "data_export",
                "original_rva": slot["rva"], "target_symbol": target,
                "object_offset": (
                    None if section is None else 0
                ),
                "export_names": list(slot["names"]),
                "ordinal": slot["ordinal"], "forwarder": None, "order": None,
            })
            if target is None:
                holes.append({
                    "kind": "data_export_object_missing", "subject": root_id,
                    "detail": "data export has no unique non-executable section object",
                })
        else:
            roots.append({
                "root_id": root_id, "kind": "forwarder",
                "original_rva": slot["rva"], "target_symbol": None,
                "object_offset": None, "export_names": list(slot["names"]),
                "ordinal": slot["ordinal"], "forwarder": slot["forwarder"],
                "order": None,
            })
    tls = interface["tls"]
    if tls is not None:
        for callback in tls["callbacks"]:
            code_root(
                root_id=f"tls-callback:{callback['order']}",
                kind="tls_callback", rva=int(callback["rva"]),
                order=int(callback["order"]),
            )
    roots.sort(key=lambda row: str(row["root_id"]))
    holes.sort(key=lambda row: (str(row["kind"]), str(row["subject"])))
    return roots, holes


def _migration_holes(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
    root_holes: list[dict[str, Any]],
    relocation_holes: list[dict[str, Any]],
    relocations: list[dict[str, Any]],
    platform_selection: Mapping[str, Any] | None,
    checked_exceptions: Sequence[CheckedExceptionTransitionV1],
) -> list[dict[str, Any]]:
    holes = [*root_holes, *relocation_holes]
    holes.extend({
        "kind": "upstream_transfer_blocker",
        "subject": str(row.get("unit_id") or row.get("identity") or "module"),
        "detail": json_dumps(row),
    } for row in plan["semantic_blockers"])
    holes.extend({
        "kind": "module_interface_blocker",
        "subject": str(row.get("category", "module")),
        "detail": json_dumps(row),
    } for row in interface["blockers"])
    required = [
        ("boundary_types_unlinked", "logical boundary types are not linked"),
        ("physical_frames_unlinked", "physical call frames are not linked"),
        ("effect_closure_unlinked", "root-reachable effect closure is not linked"),
        ("evidence_inventory_unlinked", "qualification evidence is not linked"),
        ("object_views_unlinked", "object interiors and optional views are not linked"),
    ]
    holes.extend({"kind": kind, "subject": "module", "detail": detail} for kind, detail in required)
    if platform_selection is None:
        holes.append({
            "kind": "qualified_platform_selection_missing",
            "subject": "module",
            "detail": "exact ISA occurrences have not been selected from qualified-platform-v1",
        })
    else:
        holes.extend({
            "kind": "qualified_platform_selection_incomplete",
            "subject": str(
                row.get("form_id")
                or row.get("unit_id")
                or row.get("code")
                or "module"
            ),
            "detail": json_dumps(row),
        } for row in platform_selection["issues"])
    if any(row["kind"] in {"iat_slot", "delay_iat_slot"} for row in relocations):
        holes.append({
            "kind": "loader_relocations_unlinked", "subject": "module",
            "detail": "IAT and delay-IAT declarations await semantic link classification",
        })
    expected_exception_count = sum(
        len(row.get("exception_occurrences", ()))
        for row in plan["transfers"]
    )
    if len(checked_exceptions) != expected_exception_count:
        holes.append({
            "kind": "exception_transitions_unlinked", "subject": "module",
            "detail": (
                "checked exception semantics do not cover transfer-v2"
            ),
        })
    return sorted(holes, key=lambda row: (
        str(row["kind"]), str(row["subject"]), str(row["detail"])
    ))


def _effect_index(
    plan: Mapping[str, Any],
    transfers: tuple[Any, ...],
    authority: MachineObjectAuthorityV2,
    symbols: list[dict[str, Any]],
    checked_exceptions: tuple[CheckedExceptionTransitionV1, ...] = (),
) -> dict[str, Any]:
    def reference(field: str) -> dict[str, Any]:
        rows = plan[field]
        return {
            "member": "executable-transfer-plan.json",
            "field": field,
            "count": len(rows),
            "sha256": canonical_sha256_v3(rows),
        }

    source_symbol_by_unit = {
        str(row["identity"]): _function_symbol_id(str(row["identity"]))
        for row in plan["transfers"]
    }
    sources_by_provider: dict[str, list[str]] = {}
    for transfer in transfers:
        source_symbol = source_symbol_by_unit.get(str(transfer.identity))
        if source_symbol is None:
            _fail("typed transfer has no semantic function declaration")
        for provider in runtime_provider_requirements_v2(
            (transfer,), layer="transfer_plan"
        ):
            sources_by_provider.setdefault(provider, []).append(source_symbol)
    if set(sources_by_provider) != set(plan["runtime_provider_requirements"]):
        _fail("per-definition runtime requirements disagree with the transfer plan")
    runtime_primitive_dependencies = [
        {
            "provider_id": provider,
            "target_symbol": _runtime_primitive_symbol_id(provider),
            "source_symbols": sorted(sources_by_provider[provider]),
        }
        for provider in sorted(sources_by_provider)
    ]
    symbol_ids = {str(row["symbol_id"]) for row in symbols}
    object_symbol_bindings = [
        {
            "object_id": rule.identity,
            "target_symbol": (
                _object_symbol_id(rule.identity)
                if _object_symbol_id(rule.identity) in symbol_ids else None
            ),
        }
        for rule in authority.rules
    ]

    result = {
        "source": "executable-transfer-plan-v2",
        "direct_control_edges": reference("direct_control_edges"),
        "finite_control_routes": reference("finite_control_routes"),
        "atomic_effect_authority": reference("atomic_effect_authority"),
        "runtime_provider_requirements": reference(
            "runtime_provider_requirements"
        ),
        "runtime_primitive_dependencies": runtime_primitive_dependencies,
        "object_symbol_bindings": object_symbol_bindings,
        "root_closure": "unlinked",
    }
    checked_projection = [row.payload() for row in checked_exceptions]
    result["exceptional_transitions"] = {
        "source": "transfer_v2_resolved_environment",
        "count": len(checked_projection),
        "checked_projection_sha256": canonical_sha256_v3(
            checked_projection
        ),
        "checked_projection": checked_projection,
    }
    return result


def _selection_reference(
    selection: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if selection is None:
        return None
    return {
        "member": "qualified-platform-selection.json",
        "status": selection["status"],
        "identity": selection["selection_sha256"],
        "content_sha256": sha256_bytes(_canonical_bytes(selection)),
        "counts": dict(selection["counts"]),
    }


def _evidence_inventory(
    *,
    plan: Mapping[str, Any],
    plan_content_sha256: str,
    interface: Mapping[str, Any],
    interface_content_sha256: str,
    authority: MachineObjectAuthorityV2,
    authority_content_sha256: str,
    selection: Mapping[str, Any] | None,
    requirements: Mapping[str, Any] | None,
    requirements_content_sha256: str | None,
    platform: Mapping[str, Any] | None,
    resolved_environment: ResolvedExternalEnvironmentV1 | None,
    environment_content_sha256: str | None,
) -> list[dict[str, Any]]:
    evidence = [{
        "kind": "module_interface",
        "identity": interface["interface_sha256"],
        "content_sha256": interface_content_sha256,
    }, {
        "kind": "transfer_plan",
        "identity": plan["plan_sha256"],
        "content_sha256": plan_content_sha256,
    }, {
        "kind": "machine_object_authority",
        "identity": authority.authority_sha256,
        "content_sha256": authority_content_sha256,
    }]
    if selection is not None:
        assert requirements is not None
        assert requirements_content_sha256 is not None
        assert platform is not None
        evidence.extend(({
            "kind": "exact_isa_requirements",
            "identity": requirements["requirements_sha256"],
            "content_sha256": requirements_content_sha256,
        }, {
            "kind": "qualified_platform",
            "identity": platform["platform_sha256"],
            "content_sha256": selection["bindings"][
                "platform_content_sha256"
            ],
        }, {
            "kind": "qualified_platform_occurrence_selection",
            "identity": selection["selection_sha256"],
            "content_sha256": canonical_sha256_v3(selection),
        }))
    if resolved_environment is not None:
        assert environment_content_sha256 is not None
        evidence.append({
            "kind": "resolved_external_environment",
            "identity": resolved_environment.identity,
            "content_sha256": environment_content_sha256,
        })
    if len({row["kind"] for row in evidence}) != len(evidence):
        _fail("semantic evidence kinds are not unique")
    return evidence


def _definitions_with_evidence_dependencies(
    definitions: Sequence[Mapping[str, Any]],
    evidence: Sequence[Mapping[str, Any]],
    selection: Mapping[str, Any] | None,
    checked_exceptions: Sequence[CheckedExceptionTransitionV1],
) -> list[dict[str, Any]]:
    """Bind every semantic definition to exact rows in the evidence catalog."""

    evidence_index = {
        str(row["kind"]): index for index, row in enumerate(evidence)
    }
    occurrence_units = {
        str(row["unit_id"])
        for row in (() if selection is None else selection["occurrences"])
    }
    exception_units = {row.unit_id for row in checked_exceptions}
    result: list[dict[str, Any]] = []
    for raw in definitions:
        row = dict(raw)
        if "evidence_dependencies" in row:
            _fail("semantic definition already carries evidence dependencies")
        kind = row.get("definition_kind")
        dependencies: set[str]
        if kind == "transfer_v2":
            body = _mapping(row.get("body"), "transfer definition body")
            unit_id = str(body.get("transfer_id"))
            dependencies = {"transfer_plan"}
            if unit_id in occurrence_units:
                dependencies.update({
                    "exact_isa_requirements",
                    "qualified_platform",
                    "qualified_platform_occurrence_selection",
                })
            if unit_id in exception_units:
                dependencies.add("resolved_external_environment")
        elif kind == "checked_exception_transition":
            dependencies = {
                "transfer_plan", "resolved_external_environment",
            }
        elif kind in {
            "image_object", "object_anchor", "resource_data",
            "resource_directory", "resource_entry", "load_config_table",
        }:
            dependencies = {
                "module_interface", "machine_object_authority",
            }
        elif kind == "loader_section_storage":
            dependencies = {"module_interface"}
        else:
            _fail(f"semantic definition kind has no evidence policy: {kind}")
        try:
            indices = sorted(evidence_index[item] for item in dependencies)
        except KeyError as exc:
            _fail(
                f"semantic definition requires absent evidence: {exc.args[0]}"
            )
        row["evidence_dependencies"] = indices
        result.append(row)
    return result


def _counts(
    payload: Mapping[str, Any], plan: Mapping[str, Any],
    selection: Mapping[str, Any] | None,
) -> dict[str, int]:
    form_status = (
        {} if selection is None else {
            row["form_id"]: row["status"] for row in selection["forms"]
        }
    )
    return {
        "transfers": len(plan["transfers"]),
        "symbols": len(payload["symbols"]),
        "definitions": len(payload["definitions"]),
        "relocations": len(payload["relocations"]),
        "roots": len(payload["roots"]),
        "evidence": len(payload["evidence"]),
        "holes": len(payload["holes"]),
        "isa_forms": 0 if selection is None else len(selection["forms"]),
        "isa_occurrences": (
            0 if selection is None else len(selection["occurrences"])
        ),
        "isa_occurrences_qualified": (
            0 if selection is None else sum(
                form_status[row["form_id"]] == "qualified"
                for row in selection["occurrences"]
            )
        ),
    }


def _selection_inputs(
    *, isa_requirements: Path | None, qualified_platform: Path | None,
    plan: Mapping[str, Any], interface: Mapping[str, Any],
) -> tuple[
    dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None,
    str | None,
]:
    if (isa_requirements is None) != (qualified_platform is None):
        _fail("ISA requirements and qualified platform must be supplied together")
    if isa_requirements is None:
        return None, None, None, None
    requirements = _read_json_payload(
        Path(isa_requirements), "exact ISA requirements"
    )
    requirements_content_sha256 = sha256_bytes(_canonical_bytes(requirements))
    selection, platform, certificate = (
        select_isa_requirements_from_platform_v1(
            requirements, Path(qualified_platform), transfer_plan=plan
        )
    )
    bindings = selection["bindings"]
    if (
        bindings["binary_sha256"] != interface["identity"]["pe_sha256"]
        or bindings["binary_sha256"] != plan["bindings"]["pe_sha256"]
        or bindings["machine_ir_sha256"]
        != plan["bindings"]["machine_ir_sha256"]
    ):
        _fail("qualified-platform selection binds a different exact machine universe")
    units = {str(row["unit_id"]): row for row in plan["unit_inventory"]}
    for occurrence in selection["occurrences"]:
        unit = units.get(str(occurrence["unit_id"]))
        if unit is None:
            _fail("qualified-platform selection names an unknown transfer-plan unit")
        if not (
            int(unit["rva_start"]) <= int(occurrence["rva_start"])
            < int(occurrence["rva_end"]) <= int(unit["rva_end"])
        ):
            _fail("qualified-platform occurrence lies outside its exact unit")
    return selection, requirements, platform, requirements_content_sha256


def write_semantic_object_v1(
    *, transfer_plan: Path, module_interface: Path,
    machine_object_authority: Path, out: Path,
    resolved_external_environment: Path | None = None,
    isa_requirements: Path | None = None,
    qualified_platform: Path | None = None,
    link_members: bool = False,
) -> dict[str, Any]:
    """Write one deterministic, non-authorizing semantic-object migration shadow."""

    plan, plan_file_sha256 = _read_canonical_json(
        transfer_plan, "executable transfer plan"
    )
    interface, interface_file_sha256 = _read_canonical_json(
        module_interface, "PE32 module interface"
    )
    authority_payload, authority_file_sha256 = _read_canonical_json(
        machine_object_authority, "machine object authority"
    )
    plan, transfers = parse_executable_transfer_plan(plan)
    interface = dict(Pe32ModuleInterfaceV2.parse(interface).payload)
    authority = MachineObjectAuthorityV2.parse(authority_payload)
    if plan["bindings"].get("pe_sha256") != interface["identity"]["pe_sha256"]:
        _fail("semantic-object transfer and module PE identities disagree")
    if authority.bindings.get("module_interface_sha256") != interface_file_sha256:
        _fail("semantic-object object authority is stale for its module interface")
    resolved_environment = None
    environment_file_sha256 = None
    if resolved_external_environment is not None:
        environment_payload, environment_file_sha256 = _read_canonical_json(
            resolved_external_environment, "resolved external environment"
        )
        resolved_environment = ResolvedExternalEnvironmentV1.parse(
            environment_payload, module_interface=interface
        )
    selection, requirements, platform, requirements_content_sha256 = (
        _selection_inputs(
            isa_requirements=isa_requirements,
            qualified_platform=qualified_platform,
            plan=plan,
            interface=interface,
        )
    )
    checked_exceptions = load_exception_projection_inputs(
        transfers=transfers,
        resolved_environment=resolved_environment,
    )
    symbols, definitions, declaration_holes = _project_symbols(
        plan, interface, checked_exceptions, resolved_environment
    )
    relocations, relocation_holes = _project_relocations(
        plan, interface, checked_exceptions
    )
    roots, root_holes = _project_roots(plan, interface)
    holes = _migration_holes(
        plan, interface, [*root_holes, *declaration_holes],
        relocation_holes, relocations, selection, checked_exceptions
    )
    evidence = _evidence_inventory(
        plan=plan,
        plan_content_sha256=plan_file_sha256,
        interface=interface,
        interface_content_sha256=interface_file_sha256,
        authority=authority,
        authority_content_sha256=authority_file_sha256,
        selection=selection,
        requirements=requirements,
        requirements_content_sha256=requirements_content_sha256,
        platform=platform,
        resolved_environment=resolved_environment,
        environment_content_sha256=environment_file_sha256,
    )
    definitions = _definitions_with_evidence_dependencies(
        definitions, evidence, selection, checked_exceptions
    )
    members = {
        "module_interface": {
            "path": "module-interface.json",
            "identity": interface["interface_sha256"],
            "content_sha256": interface_file_sha256,
        },
        "transfer_plan": {
            "path": "executable-transfer-plan.json",
            "identity": plan["plan_sha256"],
            "content_sha256": plan_file_sha256,
        },
        "machine_object_authority": {
            "path": "machine-object-authority.json",
            "identity": authority.authority_sha256,
            "content_sha256": authority_file_sha256,
        },
    }
    if selection is not None:
        assert requirements is not None
        assert platform is not None
        assert requirements_content_sha256 is not None
        members.update({
            "isa_requirements": {
                "path": "isa-requirements.json",
                "identity": requirements["requirements_sha256"],
                "content_sha256": requirements_content_sha256,
            },
            "qualified_platform": {
                "path": "qualified-platform.json",
                "identity": platform["platform_sha256"],
                "content_sha256": selection["bindings"][
                    "platform_content_sha256"
                ],
            },
            "qualified_platform_isa_certificate": {
                "path": "isa-form-qualification-certificate.json",
                "identity": selection["bindings"]["certificate_sha256"],
                "content_sha256": platform["members"][
                    "isa_form_qualification_certificate"
                ]["content_sha256"],
            },
            "platform_selection": {
                "path": "qualified-platform-selection.json",
                "identity": selection["selection_sha256"],
                "content_sha256": sha256_bytes(_canonical_bytes(selection)),
            },
        })
    if resolved_environment is not None:
        assert environment_file_sha256 is not None
        members["resolved_external_environment"] = {
            "path": "resolved-external-environment.json",
            "identity": resolved_environment.identity,
            "content_sha256": environment_file_sha256,
        }
    payload: dict[str, Any] = {
        "format": SEMANTIC_OBJECT_FORMAT,
        "status": "complete",
        "role": "checked_relocatable",
        "authority": False,
        "bindings": {
            "pe_sha256": interface["identity"]["pe_sha256"],
            "image_id": interface["image_id"],
            "module_interface_sha256": interface["interface_sha256"],
            "module_interface_content_sha256": interface_file_sha256,
            "transfer_plan_sha256": plan["plan_sha256"],
            "transfer_plan_content_sha256": plan_file_sha256,
            "machine_object_authority_sha256": authority.authority_sha256,
            "machine_object_authority_content_sha256": authority_file_sha256,
            "exact_universe_sha256": plan["bindings"]["exact_universe_sha256"],
            "operation_registry_sha256": plan["operation_registry_sha256"],
            "isa_requirements_sha256": (
                None if requirements is None else requirements["requirements_sha256"]
            ),
            "qualified_platform_sha256": (
                None if platform is None else platform["platform_sha256"]
            ),
            "platform_selection_sha256": (
                None if selection is None else selection["selection_sha256"]
            ),
            "resolved_external_environment_sha256": (
                None if resolved_environment is None
                else resolved_environment.identity
            ),
            "resolved_external_environment_content_sha256": (
                environment_file_sha256
            ),
        },
        "members": members,
        "symbols": symbols,
        "definitions": definitions,
        "relocations": relocations,
        "effect_index": _effect_index(
            plan, transfers, authority, symbols, checked_exceptions,
        ),
        "roots": roots,
        "platform_selection": _selection_reference(selection),
        "evidence": evidence,
        "holes": holes,
    }
    payload["counts"] = _counts(payload, plan, selection)
    payload["semantic_object_sha256"] = canonical_sha256_v3(payload)
    destination = Path(out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    package_members = [
        (Path(transfer_plan), "executable-transfer-plan.json"),
        (Path(module_interface), "module-interface.json"),
        (Path(machine_object_authority), "machine-object-authority.json"),
    ]
    if isa_requirements is not None and qualified_platform is not None:
        assert requirements is not None
        write_json(destination.parent / "isa-requirements.json", requirements)
        assert selection is not None
        write_json(
            destination.parent / "qualified-platform-selection.json",
            selection,
        )
        package_members.extend((
            (Path(qualified_platform), "qualified-platform.json"),
            (
                Path(qualified_platform).parent
                / "isa-form-qualification-certificate.json",
                "isa-form-qualification-certificate.json",
            ),
        ))
    if resolved_external_environment is not None:
        package_members.append((
            Path(resolved_external_environment),
            "resolved-external-environment.json",
        ))
    for source, name in package_members:
        member = destination.parent / name
        if member.exists() and member.resolve() == source.resolve():
            continue
        if member.exists() or member.is_symlink():
            if member.is_dir() and not member.is_symlink():
                shutil.rmtree(member)
            else:
                member.unlink()
        if link_members:
            member.symlink_to(source.resolve())
        elif source.is_dir():
            shutil.copytree(source, member)
        else:
            shutil.copyfile(source, member)
    write_json(destination, payload)
    return payload


from .semantic_object_validation import (  # noqa: E402
    _validate_bindings,
    _validate_members,
    _validate_projection,
)


@dataclass(frozen=True)
class SemanticObjectV1:
    payload: Mapping[str, Any]
    transfer_plan: Mapping[str, Any]
    transfers: tuple[Any, ...]
    module_interface: Mapping[str, Any]
    machine_object_authority: MachineObjectAuthorityV2
    resolved_external_environment: ResolvedExternalEnvironmentV1 | None = None
    platform_selection: Mapping[str, Any] | None = None
    isa_requirements: Mapping[str, Any] | None = None
    qualified_platform: Mapping[str, Any] | None = None
    checked_exception_transitions: tuple[
        CheckedExceptionTransitionV1, ...
    ] = ()
    package_root: Path | None = None

    @property
    def identity(self) -> str:
        return str(self.payload["semantic_object_sha256"])

    @classmethod
    def parse(
        cls, value: object, *, transfer_plan: object,
        module_interface: object, machine_object_authority: object,
        resolved_external_environment: object | None = None,
        isa_requirements: Path | None = None,
        qualified_platform: Path | None = None,
        require_complete: bool = False,
    ) -> "SemanticObjectV1":
        payload = dict(_mapping(value, "semantic object"))
        if set(payload) != _FIELDS:
            _fail("semantic-object fields are incomplete")
        if payload.get("format") != SEMANTIC_OBJECT_FORMAT:
            _fail("semantic-object format is unsupported")
        declared = _sha256(payload["semantic_object_sha256"], "semantic-object SHA-256")
        core = {key: item for key, item in payload.items() if key != "semantic_object_sha256"}
        if declared != canonical_sha256_v3(core):
            _fail("semantic-object self hash is stale")
        plan, transfers = parse_executable_transfer_plan(transfer_plan)
        interface = Pe32ModuleInterfaceV2.parse(module_interface).payload
        authority = MachineObjectAuthorityV2.parse(machine_object_authority)
        if plan["bindings"].get("pe_sha256") != interface["identity"]["pe_sha256"]:
            _fail("semantic-object transfer and module PE identities disagree")
        if authority.bindings.get("module_interface_sha256") != sha256_bytes(
            _canonical_bytes(interface)
        ):
            _fail("semantic-object object authority is stale for its module interface")
        environment = (
            None if resolved_external_environment is None
            else ResolvedExternalEnvironmentV1.parse(
                resolved_external_environment, module_interface=interface
            )
        )
        environment_content_sha256 = (
            None if environment is None
            else sha256_bytes(_canonical_bytes(environment.payload))
        )
        selection, requirements, platform, _ = _selection_inputs(
            isa_requirements=isa_requirements,
            qualified_platform=qualified_platform,
            plan=plan,
            interface=interface,
        )
        checked_exceptions = load_exception_projection_inputs(
            transfers=transfers,
            resolved_environment=environment,
        )
        _validate_members(
            payload, plan, interface, authority, selection, requirements, platform,
            environment,
            environment_content_sha256,
        )
        _validate_bindings(
            payload, plan, interface, authority, selection, requirements, platform,
            environment,
            environment_content_sha256,
        )
        _validate_projection(
            payload, plan, interface, authority, selection, requirements, platform,
            checked_exceptions, environment,
            environment_content_sha256, transfers,
        )
        if (
            payload.get("status") != "complete"
            or payload.get("role") != "checked_relocatable"
            or payload.get("authority") is not False
        ):
            _fail("semantic-object v1 must be a checked non-authorizing relocatable")
        if payload["counts"] != _counts(payload, plan, selection):
            _fail("semantic-object counts are stale")
        return cls(
            payload, plan, transfers, dict(interface), authority, environment, selection,
            requirements, platform, checked_exceptions,
        )

    @classmethod
    def load(
        cls, path: Path, *, require_complete: bool = False,
    ) -> "SemanticObjectV1":
        source = Path(path)
        payload, _ = _read_canonical_json(source, "semantic object")
        plan, _ = _read_canonical_json(
            source.parent / "executable-transfer-plan.json",
            "semantic-object transfer-plan member",
        )
        plan_sha256 = _sha256(
            plan.get("plan_sha256"), "semantic-object transfer-plan SHA-256"
        )
        if plan_sha256 != canonical_sha256_v3({
            key: value for key, value in plan.items()
            if key != "plan_sha256"
        }):
            _fail("semantic-object transfer-plan self hash is stale")
        interface, _ = _read_canonical_json(
            source.parent / "module-interface.json",
            "semantic-object module-interface member",
        )
        authority, _ = _read_canonical_json(
            source.parent / "machine-object-authority.json",
            "semantic-object machine-object-authority member",
        )
        members = _mapping(payload.get("members"), "semantic-object members")
        has_platform = "qualified_platform" in members
        if has_platform != ("isa_requirements" in members):
            _fail("semantic-object platform package members are only partially present")
        isa_requirements = (
            source.parent / "isa-requirements.json" if has_platform else None
        )
        qualified_platform = (
            source.parent / "qualified-platform.json" if has_platform else None
        )
        resolved_environment = (
            source.parent / "resolved-external-environment.json"
            if "resolved_external_environment" in members else None
        )
        resolved_environment_payload = (
            None if resolved_environment is None
            else _read_canonical_json(
                resolved_environment,
                "semantic-object resolved-environment member",
            )[0]
        )
        parsed = cls.parse(
            payload,
            transfer_plan=plan,
            module_interface=interface,
            machine_object_authority=authority,
            resolved_external_environment=resolved_environment_payload,
            isa_requirements=isa_requirements,
            qualified_platform=qualified_platform,
            require_complete=require_complete,
        )
        if has_platform:
            stored_selection, _ = _read_canonical_json(
                source.parent / "qualified-platform-selection.json",
                "semantic-object platform-selection member",
            )
            if stored_selection != parsed.platform_selection:
                _fail("semantic-object platform-selection member is stale")
        return cls(
            parsed.payload,
            parsed.transfer_plan,
            parsed.transfers,
            parsed.module_interface,
            parsed.machine_object_authority,
            parsed.resolved_external_environment,
            parsed.platform_selection,
            parsed.isa_requirements,
            parsed.qualified_platform,
            parsed.checked_exception_transitions,
            source.parent,
        )

    @classmethod
    def load_link_view(cls, path: Path) -> "SemanticObjectV1":
        """Open the content-bound link view without replaying transfer-v2.

        This is a production-link optimization, not a second public codec. It
        validates package/self hashes, strict non-transfer members, bindings,
        definition identities, and the exact transfer member identity. The
        conservative linker consumes only declarations and transfer-v2 site
        inventory already bound by that package. Independent replay continues
        to use :meth:`load` and rechecks the may graph from packaged inputs.
        """

        source = Path(path)
        payload, _ = _read_canonical_json(source, "semantic object")
        if set(payload) != _FIELDS:
            _fail("semantic-object fields are incomplete")
        if payload.get("format") != SEMANTIC_OBJECT_FORMAT:
            _fail("semantic-object format is unsupported")
        declared = _sha256(
            payload.get("semantic_object_sha256"), "semantic-object SHA-256"
        )
        core = {
            key: item for key, item in payload.items()
            if key != "semantic_object_sha256"
        }
        if declared != canonical_sha256_v3(core):
            _fail("semantic-object self hash is stale")
        _rows(payload.get("holes"), "semantic-object holes")
        if (
            payload.get("status") != "complete"
            or payload.get("role") != "checked_relocatable"
            or payload.get("authority") is not False
        ):
            _fail("semantic-object v1 must be a checked non-authorizing relocatable")

        members = _mapping(payload.get("members"), "semantic-object members")
        plan, _ = _read_canonical_json(
            source.parent / "executable-transfer-plan.json",
            "semantic-object transfer-plan member",
        )
        plan_sha256 = _sha256(
            plan.get("plan_sha256"), "semantic-object transfer-plan SHA-256"
        )
        if plan_sha256 != canonical_sha256_v3({
            key: value for key, value in plan.items()
            if key != "plan_sha256"
        }):
            _fail("semantic-object transfer-plan self hash is stale")
        interface_raw, _ = _read_canonical_json(
            source.parent / "module-interface.json",
            "semantic-object module-interface member",
        )
        authority_raw, _ = _read_canonical_json(
            source.parent / "machine-object-authority.json",
            "semantic-object machine-object-authority member",
        )
        interface = Pe32ModuleInterfaceV2.parse(interface_raw).payload
        authority = MachineObjectAuthorityV2.parse(authority_raw)

        has_platform = "qualified_platform" in members
        if has_platform != ("isa_requirements" in members):
            _fail("semantic-object platform package members are only partially present")
        isa_requirements_path = (
            source.parent / "isa-requirements.json" if has_platform else None
        )
        qualified_platform_path = (
            source.parent / "qualified-platform.json" if has_platform else None
        )
        selection, requirements, platform, _ = _selection_inputs(
            isa_requirements=isa_requirements_path,
            qualified_platform=qualified_platform_path,
            plan=plan,
            interface=interface,
        )
        effect_index = _mapping(
            payload.get("effect_index"), "semantic-object effect index"
        )
        exception_reference = _mapping(
            effect_index.get("exceptional_transitions"),
            "semantic-object exception projection",
        )
        if set(exception_reference) != {
            "source", "count",
            "checked_projection_sha256", "checked_projection",
        }:
            _fail("semantic-object exception projection fields are incomplete")
        raw_checked_exceptions = _rows(
            exception_reference.get("checked_projection"),
            "semantic-object checked exception projection",
        )
        checked_exceptions = tuple(sorted(
            checked_exception_transition_from_payload_v1(row)
            for row in raw_checked_exceptions
        ))
        if (
            exception_reference.get("count") != len(checked_exceptions)
            or exception_reference.get("checked_projection_sha256")
            != canonical_sha256_v3(raw_checked_exceptions)
        ):
            _fail("semantic-object checked exception projection is stale")
        if exception_reference.get("source") != (
            "transfer_v2_resolved_environment"
        ):
            _fail("semantic-object exception projection source is stale")
        environment_raw = (
            None
            if "resolved_external_environment" not in members
            else _read_canonical_json(
                source.parent / "resolved-external-environment.json",
                "semantic-object resolved-environment member",
            )[0]
        )
        environment = (
            None if environment_raw is None
            else ResolvedExternalEnvironmentV1.parse(
                environment_raw, module_interface=interface
            )
        )
        environment_content_sha256 = (
            None if environment is None
            else sha256_bytes(_canonical_bytes(environment.payload))
        )
        _validate_members(
            payload, plan, interface, authority, selection, requirements,
            platform, environment,
            environment_content_sha256,
        )
        _validate_bindings(
            payload, plan, interface, authority, selection, requirements,
            platform, environment,
            environment_content_sha256,
        )
        if payload.get("counts") != _counts(payload, plan, selection):
            _fail("semantic-object counts are stale")

        symbols = {
            str(_mapping(row, "semantic symbol").get("symbol_id")): _mapping(
                row, "semantic symbol"
            )
            for row in _rows(payload.get("symbols"), "semantic-object symbols")
        }
        transfer_rows: list[_LinkTransferReference] = []
        seen_units: set[str] = set()
        seen_rvas: set[int] = set()
        definition_rows = _rows(
            payload.get("definitions"), "semantic-object definitions"
        )
        base_definitions: list[dict[str, Any]] = []
        for raw in definition_rows:
            definition = _mapping(raw, "semantic definition")
            base_definitions.append({
                key: value for key, value in definition.items()
                if key != "evidence_dependencies"
            })
            if definition.get("definition_kind") != "transfer_v2":
                continue
            symbol_id = definition.get("symbol_id")
            body = _mapping(
                definition.get("body"), "transfer-v2 definition body"
            )
            unit_id = body.get("transfer_id")
            symbol = symbols.get(str(symbol_id))
            rva = None if symbol is None else symbol.get("original_rva")
            if (
                not isinstance(symbol_id, str) or not symbol_id
                or not isinstance(unit_id, str) or not unit_id
                or symbol_id != _function_symbol_id(unit_id)
                or symbol is None or symbol.get("kind") != "function"
                or not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
                or unit_id in seen_units or rva in seen_rvas
            ):
                _fail("semantic transfer definitions are malformed or duplicated")
            seen_units.add(unit_id)
            seen_rvas.add(rva)
            transfer_rows.append(_LinkTransferReference(unit_id, rva))
        transfer_rows.sort(key=lambda row: row.rva_start)
        compiled_transfers = _mapping(
            plan.get("counts"), "transfer-plan counts"
        ).get("compiled_transfers")
        if (
            not isinstance(compiled_transfers, int)
            or isinstance(compiled_transfers, bool)
            or compiled_transfers != len(transfer_rows)
        ):
            _fail("semantic transfer definitions do not cover the declared universe")
        expected_definitions = _definitions_with_evidence_dependencies(
            base_definitions,
            _rows(payload.get("evidence"), "semantic-object evidence"),
            selection,
            checked_exceptions,
        )
        if definition_rows != expected_definitions:
            _fail("semantic definition evidence dependencies are stale")
        if has_platform:
            stored_selection, _ = _read_canonical_json(
                source.parent / "qualified-platform-selection.json",
                "semantic-object platform-selection member",
            )
            if stored_selection != selection:
                _fail("semantic-object platform-selection member is stale")
        return cls(
            payload, plan, tuple(transfer_rows), dict(interface), authority,
            environment, selection, requirements, platform,
            checked_exceptions, source.parent,
        )

    @property
    def transfer_plan_path(self) -> Path:
        if self.package_root is None:
            _fail("parsed semantic object has no package member paths")
        return self.package_root / "executable-transfer-plan.json"

    @property
    def module_interface_path(self) -> Path:
        if self.package_root is None:
            _fail("parsed semantic object has no package member paths")
        return self.package_root / "module-interface.json"

    @property
    def machine_object_authority_path(self) -> Path:
        if self.package_root is None:
            _fail("parsed semantic object has no package member paths")
        return self.package_root / "machine-object-authority.json"

    @property
    def resolved_external_environment_path(self) -> Path:
        if (
            self.package_root is None
            or self.resolved_external_environment is None
        ):
            _fail("semantic object has no resolved-environment member")
        return self.package_root / "resolved-external-environment.json"

def load_semantic_object_v1(
    path: Path, *, require_complete: bool = False,
) -> SemanticObjectV1:
    return SemanticObjectV1.load(path, require_complete=require_complete)


@dataclass(frozen=True)
class _LinkTransferReference:
    identity: str
    rva_start: int


__all__ = [
    "MAX_SEMANTIC_OBJECT_BYTES", "SemanticObjectError", "SemanticObjectV1",
    "load_semantic_object_v1", "write_semantic_object_v1",
]
