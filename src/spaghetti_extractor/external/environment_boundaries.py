"""Canonical boundary lowering owned by external-environment resolution."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.dialects.ia32 import IA32DialectCheckerV1
from ..calls.frame import physical_frame_abi_sha256_v1
from ..errors import ToolkitInputError
from .machine_callback_boundary import (
    MachineCallbackBoundaryError,
    interface_callback_boundary_catalog_v1,
    machine_callback_boundary_catalog_v1,
)
from .machine_import_profiles import MachineImportIdentity, SelectedMachineImportContract
from .resolved import ExternalEnvironmentError
from .service_protocols import (
    external_service_outcomes_v1,
    parse_checked_external_service_protocol_v1,
)


def _identity_payload(identity: MachineImportIdentity) -> dict[str, Any]:
    return {
        "dll": identity.dll,
        "symbol": identity.value if identity.kind == "symbol" else None,
        "ordinal": identity.value if identity.kind == "ordinal" else None,
    }

def _identity_from_row(value: Mapping[str, Any], *, context: str) -> MachineImportIdentity:
    return MachineImportIdentity.from_mapping(value, context=context)

def lower_machine_import_boundary_v1(
    contract: SelectedMachineImportContract,
    *,
    abi_dialect: str,
    subject_kind: str = "import",
    subject_id: str | None = None,
    image_selector: str | None = None,
    transfer_kind: str = "import",
) -> dict[str, Any]:
    """Lower one checked machine-import profile to the canonical boundary model.

    Runtime profiles intentionally describe physical machine words rather than
    guessed C prototypes.  This projection therefore stays word-exact: a word
    is refined to a pointer only when an explicit memory footprint or callback
    protocol requires that interpretation.  The original footprint remains an
    exact memory view so offsets and size expressions are not weakened to fit
    the portable type model.
    """

    payload = contract.contract
    raw_out_pointers = payload.get("out_pointer_relations", [])
    if not isinstance(raw_out_pointers, list) or not all(
        isinstance(row, Mapping) for row in raw_out_pointers
    ):
        raise ExternalEnvironmentError(
            "machine-import out-pointer relations are malformed"
        )
    argument_words = (
        contract.argument_words
        if contract.arity_kind == "fixed"
        else payload.get("minimum_argument_words")
    )
    if not isinstance(argument_words, int) or argument_words < 0:
        raise ExternalEnvironmentError(
            "machine-import boundary lacks a checked bounded arity"
        )
    abi_template = payload.get("abi_template")
    convention = {
        "pe32-cdecl-v1": "cdecl",
        "pe32-stdcall-v1": "stdcall",
    }.get(abi_template)
    if convention is None:
        raise ExternalEnvironmentError(
            "machine-import boundary has an unsupported physical ABI"
        )

    canonical_boundary = payload.get("canonical_boundary")
    if canonical_boundary is not None:
        return _lower_canonical_machine_boundary_v1(
            contract=contract,
            canonical_boundary=canonical_boundary,
            abi_dialect=abi_dialect,
            convention=convention,
            argument_words=argument_words,
            subject_kind=subject_kind,
            subject_id=subject_id,
            image_selector=image_selector,
            transfer_kind=transfer_kind,
        )

    identity = _identity_payload(contract.identity)
    boundary_key = canonical_sha256_v3({
        "identity": identity,
        "profile_sha256": contract.profile_sha256,
        "entry_key": contract.entry_key,
        "entry_index": contract.entry_index,
        "payload": payload,
        "abi_dialect": abi_dialect,
    })[:20]
    schema_id = f"machine-import-{boundary_key}"
    signature_id = "invoke"

    footprints = payload.get("memory_footprints", [])
    if not isinstance(footprints, list):
        raise ExternalEnvironmentError(
            "machine-import boundary memory footprints are malformed"
        )
    views_by_argument: dict[int, list[Mapping[str, Any]]] = {}
    memory_views: list[dict[str, Any]] = []
    for view_index, raw in enumerate(footprints):
        if not isinstance(raw, Mapping):
            raise ExternalEnvironmentError(
                "machine-import boundary memory footprint is malformed"
            )
        base_argument = raw.get("base_argument")
        if (
            not isinstance(base_argument, int)
            or isinstance(base_argument, bool)
            or not 0 <= base_argument < argument_words
        ):
            raise ExternalEnvironmentError(
                "machine-import boundary footprint base is outside its frame"
            )
        views_by_argument.setdefault(base_argument, []).append(raw)
        memory_views.append({
            "id": f"memory-view-{view_index}",
            "base_parameter_id": f"argument-{base_argument}",
            "authority_selector": None,
            "origin_policy": "resolve_unique_machine_object",
            "access": raw.get("access"),
            "offset": raw.get("offset"),
            "size": raw.get("size"),
            "nullable": raw.get("nullable"),
        })

    raw_memory_relations = payload.get("memory_relations", [])
    if not isinstance(raw_memory_relations, list):
        raise ExternalEnvironmentError(
            "machine-import boundary memory relations are malformed"
        )
    memory_relations: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_memory_relations):
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {
                "kind", "destination_argument", "source_argument",
                "size_argument", "scale",
            }
            or raw.get("kind") != "byte_copy"
        ):
            raise ExternalEnvironmentError(
                f"machine-import memory relation {index} is unsupported"
            )
        arguments = (
            raw.get("destination_argument"),
            raw.get("source_argument"),
            raw.get("size_argument"),
        )
        scale = raw.get("scale")
        if (
            any(
                not isinstance(argument, int)
                or isinstance(argument, bool)
                or not 0 <= argument < argument_words
                for argument in arguments
            )
            or arguments[0] == arguments[1]
            or not isinstance(scale, int)
            or isinstance(scale, bool)
            or scale <= 0
        ):
            raise ExternalEnvironmentError(
                f"machine-import memory relation {index} is malformed"
            )
        memory_relations.append(dict(raw))

    callback_protocol = payload.get("callback_protocol")
    callback_source_argument: int | None = None
    callback_function_type: dict[str, Any] | None = None
    callback_pointer_type: dict[str, Any] | None = None
    if isinstance(callback_protocol, Mapping):
        source = callback_protocol.get("source")
        signature = callback_protocol.get("signature")
        if (
            isinstance(source, Mapping)
            and source.get("kind") == "argument_word"
            and isinstance(source.get("argument"), int)
            and isinstance(signature, Mapping)
        ):
            callback_source_argument = int(source["argument"])
            if not 0 <= callback_source_argument < argument_words:
                raise ExternalEnvironmentError(
                    "machine-import callback source is outside its frame"
                )
            callback_words = signature.get("argument_words")
            callback_abi = signature.get("abi_template")
            callback_convention = {
                "pe32-cdecl-v1": "cdecl",
                "pe32-stdcall-v1": "stdcall",
            }.get(callback_abi)
            if (
                not isinstance(callback_words, int)
                or callback_words < 0
                or callback_convention is None
            ):
                raise ExternalEnvironmentError(
                    "machine-import callback signature is unsupported"
                )
            callback_result = signature.get("result")
            callback_result_type = (
                "unit"
                if isinstance(callback_result, Mapping)
                and callback_result.get("kind") == "void"
                else "u32"
            )
            callback_function_type = {
                "id": "callback-function",
                "kind": "function",
                "result_type_id": callback_result_type,
                "parameter_type_ids": ["u32"] * callback_words,
                "variadic": False,
                "calling_convention": callback_convention,
            }
            callback_pointer_type = {
                "id": "callback-pointer",
                "kind": "pointer",
                "pointee_type_id": "callback-function",
                "qualifiers": [],
            }

    if (
        callback_source_argument is not None
        and callback_source_argument in views_by_argument
    ):
        raise ExternalEnvironmentError(
            "machine-import argument is ambiguously both callback and memory view"
        )

    result_relations = payload.get("result_register_relations", [])
    if not isinstance(result_relations, list):
        raise ExternalEnvironmentError(
            "machine-import result relations are malformed"
        )
    result_registers = {
        row.get("register") for row in result_relations if isinstance(row, Mapping)
    }
    if not result_registers:
        result_type = "unit"
    elif result_registers == {"eax"}:
        result_type = "u32"
    elif result_registers == {"eax", "edx"}:
        result_type = "u64"
    else:
        raise ExternalEnvironmentError(
            "machine-import result relation cannot be represented by the checked IA-32 frame"
        )

    types: list[dict[str, Any]] = [
        {"id": "unit", "kind": "void"},
        {"id": "u8", "kind": "integer", "width_bits": 8, "signed": False},
        {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
        {"id": "u64", "kind": "integer", "width_bits": 64, "signed": False},
    ]
    pointer_type_ids: dict[int, str] = {}
    for argument in sorted(views_by_argument):
        type_id = f"argument-{argument}-pointer"
        pointer_type_ids[argument] = type_id
        types.append({
            "id": type_id,
            "kind": "pointer",
            "pointee_type_id": "u8",
            "qualifiers": [],
        })
    if callback_function_type is not None and callback_pointer_type is not None:
        types.extend((callback_function_type, callback_pointer_type))

    parameter_type_ids: list[str] = []
    parameters: list[dict[str, Any]] = []
    for argument in range(argument_words):
        argument_id = f"argument-{argument}"
        relevant_views = views_by_argument.get(argument, [])
        if argument == callback_source_argument:
            type_id = "callback-pointer"
            interpretation = "callback"
            access = "none"
            nullable = bool(
                callback_protocol.get("source", {}).get("sentinels", [])
            )
        elif relevant_views:
            type_id = pointer_type_ids[argument]
            interpretation = "view"
            accesses = {str(row.get("access")) for row in relevant_views}
            access = (
                "read_write"
                if accesses == {"read", "write"} or "read_write" in accesses
                else next(iter(accesses))
            )
            nullable = all(row.get("nullable") is True for row in relevant_views)
        else:
            type_id = "u32"
            interpretation = "value"
            access = "none"
            nullable = False
        parameter_type_ids.append(type_id)
        parameters.append({
            "id": argument_id,
            "type_id": type_id,
            "interpretation": interpretation,
            "nullable": nullable,
            "access": access,
            # Exact offsets, scaling, and termination bounds live in
            # memory_views below; do not silently approximate them here.
            "extent": {"kind": "none", "bytes": None, "value_id": None},
            "resource_kind": None,
            "provider_domain": None,
        })

    types.append({
        "id": "import-function",
        "kind": "function",
        "result_type_id": result_type,
        "parameter_type_ids": parameter_type_ids,
        "variadic": contract.arity_kind == "variadic",
        "calling_convention": convention,
    })
    results = [] if result_type == "unit" else [{
        "id": "result",
        "type_id": result_type,
        "interpretation": "value",
        "nullable": False,
        "access": "none",
        "extent": {"kind": "none", "bytes": None, "value_id": None},
        "resource_kind": None,
        "provider_domain": None,
    }]
    schema = BoundarySchemaV1.create(
        schema_id=schema_id,
        types=types,
        signatures=[{
            "id": signature_id,
            "function_type_id": "import-function",
            "parameters": parameters,
            "results": results,
        }],
    )
    layout_type_ids = {
        row["id"] for row in types if row["kind"] == "pointer"
    }
    layouts: list[dict[str, Any]] = [
        {
            "type_id": "u8", "size_bits": 8, "alignment_bits": 8,
            "value_bits": 8, "abi_class": "integer", "fields": [],
            "padding": [],
        },
        {
            "type_id": "u32", "size_bits": 32, "alignment_bits": 32,
            "value_bits": 32, "abi_class": "integer", "fields": [],
            "padding": [],
        },
        {
            "type_id": "u64", "size_bits": 64, "alignment_bits": 32,
            "value_bits": 64, "abi_class": "integer", "fields": [],
            "padding": [],
        },
    ]
    layouts.extend({
        "type_id": type_id, "size_bits": 32, "alignment_bits": 32,
        "value_bits": 32, "abi_class": "pointer", "fields": [],
        "padding": [],
    } for type_id in sorted(layout_type_ids))
    layout = TargetDataLayoutV1.create(
        target="i686-pc-windows-pe32",
        abi_dialect=abi_dialect,
        byte_order="little",
        pointer_width_bits=32,
        packing="natural",
        schema=schema,
        layouts=layouts,
    )
    if subject_id is None:
        subject_id = (
            f"{contract.identity.dll}.{contract.identity.value}"
            if contract.identity.kind == "symbol"
            else f"{contract.identity.dll}.ordinal-{contract.identity.value}"
        )
    external_service_protocol = parse_checked_external_service_protocol_v1(
        payload.get("external_service_protocol"),
        argument_words=argument_words,
        context="machine-import external service protocol",
    )
    service_outcomes = external_service_outcomes_v1(
        external_service_protocol
    )
    frame = IA32DialectCheckerV1(abi_dialect).lower_boundary(
        subject={
            "kind": subject_kind,
            "id": subject_id,
            "image_selector": image_selector,
        },
        schema=schema,
        layout=layout,
        signature_id=signature_id,
        transfer_kind=transfer_kind,
        outcomes=(
            service_outcomes
            if service_outcomes
            else ("no_return",)
            if payload.get("disposition") == "terminates"
            else ("normal",)
        ),
    )
    return {
        "schema": schema.to_payload(),
        "target_data_layout": layout.to_payload(),
        "physical_call_frame_v3": frame.to_payload(),
        "memory_views": memory_views,
        "memory_relations": memory_relations,
        "callback_protocol": callback_protocol,
        "external_service_protocol": external_service_protocol,
        "out_pointer_relations": [
            dict(row) for row in raw_out_pointers
        ],
    }

def _lower_canonical_machine_boundary_v1(
    *,
    contract: SelectedMachineImportContract,
    canonical_boundary: object,
    abi_dialect: str,
    convention: str,
    argument_words: int,
    subject_kind: str,
    subject_id: str | None,
    image_selector: str | None,
    transfer_kind: str,
) -> dict[str, Any]:
    """Re-lower a header-derived canonical C boundary for one subject.

    This path carries only physical ABI.  Memory footprints, callbacks,
    lifecycle, and world effects must still arrive through their owning
    checked contracts; accepting them here would turn C spelling into semantic
    authority.
    """

    payload = contract.contract
    if not isinstance(canonical_boundary, Mapping) or set(canonical_boundary) != {
        "boundary_schema", "target_data_layout", "signature_id",
    }:
        raise ExternalEnvironmentError(
            "machine-import canonical boundary is malformed"
        )
    forbidden_semantics = {
        "memory_footprints", "memory_relations", "out_pointer_relations",
        "out_interface_relations", "callback_protocol", "callback_source",
        "callback_abi", "callback_lifetime",
    }
    for field in forbidden_semantics:
        value = payload.get(field)
        if value not in (None, [], ()):
            raise ExternalEnvironmentError(
                "canonical physical boundary carries unrelated semantic fields"
            )
    try:
        schema = BoundarySchemaV1.parse(canonical_boundary["boundary_schema"])
        layout = TargetDataLayoutV1.parse(
            canonical_boundary["target_data_layout"], schema=schema
        )
    except (ToolkitInputError, ValueError, TypeError) as exc:
        raise ExternalEnvironmentError(
            f"machine-import canonical boundary is invalid: {exc}"
        ) from exc
    signature_id = canonical_boundary.get("signature_id")
    if not isinstance(signature_id, str) or signature_id not in schema.signature_index:
        raise ExternalEnvironmentError(
            "machine-import canonical boundary has no selected signature"
        )
    signature = schema.signature_index[signature_id]
    function = schema.type_index[signature.function_type_id]
    if (
        function.body.get("calling_convention") != convention
        or layout.abi_dialect != abi_dialect
    ):
        raise ExternalEnvironmentError(
            "machine-import canonical boundary disagrees with its selected ABI"
        )
    if subject_id is None:
        subject_id = (
            f"{contract.identity.dll}.{contract.identity.value}"
            if contract.identity.kind == "symbol"
            else f"{contract.identity.dll}.ordinal-{contract.identity.value}"
        )
    external_service_protocol = parse_checked_external_service_protocol_v1(
        payload.get("external_service_protocol"),
        argument_words=argument_words,
        context="canonical machine-import external service protocol",
    )
    service_outcomes = external_service_outcomes_v1(
        external_service_protocol
    )
    frame = IA32DialectCheckerV1(abi_dialect).lower_boundary(
        subject={
            "kind": subject_kind,
            "id": subject_id,
            "image_selector": image_selector,
        },
        schema=schema,
        layout=layout,
        signature_id=signature_id,
        transfer_kind=transfer_kind,
        outcomes=(
            service_outcomes
            if service_outcomes
            else ("no_return",)
            if payload.get("disposition") == "terminates"
            else ("normal",)
        ),
    )
    stack_bytes = max(
        (
            int(fragment.location.stack_offset_bytes or 0)
            + int(fragment.location.width_bits) // 8
            - 4
            for argument in frame.transport.arguments
            for fragment in argument.fragments
            if fragment.location.kind == "stack"
        ),
        default=0,
    )
    if stack_bytes != argument_words * 4:
        raise ExternalEnvironmentError(
            "machine-import canonical boundary disagrees with its physical word arity"
        )
    return {
        "schema": schema.to_payload(),
        "target_data_layout": layout.to_payload(),
        "physical_call_frame_v3": frame.to_payload(),
        "memory_views": [],
        "memory_relations": [],
        "callback_protocol": None,
        "external_service_protocol": external_service_protocol,
        "out_pointer_relations": [],
    }

def _module_export_boundary_catalogs(
    *,
    module: Mapping[str, Any],
    contracts: Mapping[MachineImportIdentity, SelectedMachineImportContract],
    abi_dialect: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Derive one checked provider frame for each contracted code EAT target.

    Machine contracts describe an ABI at a DLL symbol, independent of whether
    the current module is importing or providing it.  Re-lowering the selected
    contract with an export subject gives the provider end of the same edge.
    EAT aliases are grouped by target RVA so one capability and bridge address
    is produced.  Multiple matching aliases are accepted only when their
    caller-visible physical ABIs agree exactly.

    Missing contracts are deliberately not environment blockers: an unrooted
    export need not be implemented, while the semantic linker emits a precise
    hole if that export is in the active realization universe.
    """

    export_directory = module.get("export_directory")
    if export_directory is None:
        return [], []
    image_id = module.get("image_id")
    if not isinstance(image_id, str) or not image_id:
        raise ExternalEnvironmentError("module interface has no image identity")
    if not isinstance(export_directory, Mapping):
        raise ExternalEnvironmentError("module export directory is malformed")
    # pe32-module-interface-v2 represents an absent PE export directory as a
    # canonical empty EAT object, rather than as JSON null.  It is important
    # that this is an exact recognition: accepting merely an empty ``slots``
    # list would hide contradictory geometry (or a stale DLL identity) instead
    # of failing closed.
    if dict(export_directory) == {
        "dll_name": None,
        "metadata": None,
        "ordinal_base": 0,
        "slot_count": 0,
        "holes": [],
        "slots": [],
        "name_table": [],
    }:
        return [], []
    dll_name = export_directory.get("dll_name")
    slots = export_directory.get("slots")
    if not isinstance(dll_name, str) or not dll_name or not isinstance(slots, list):
        raise ExternalEnvironmentError("module export directory is malformed")
    provider_dll = dll_name.lower()
    by_rva: dict[int, list[Mapping[str, Any]]] = {}
    for index, raw in enumerate(slots):
        if not isinstance(raw, Mapping):
            raise ExternalEnvironmentError(
                f"module export slot {index} is malformed"
            )
        if raw.get("kind") != "code":
            continue
        rva = raw.get("rva")
        ordinal = raw.get("ordinal")
        names = raw.get("names")
        if (
            not isinstance(rva, int)
            or isinstance(rva, bool)
            or rva < 0
            or not isinstance(ordinal, int)
            or isinstance(ordinal, bool)
            or ordinal < 0
            or not isinstance(names, list)
            or any(not isinstance(name, str) or not name for name in names)
        ):
            raise ExternalEnvironmentError(
                f"module code export slot {index} is malformed"
            )
        by_rva.setdefault(rva, []).append(raw)

    catalogs: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for target_rva, target_slots in sorted(by_rva.items()):
        aliases = sorted(
            (
                {"name": name, "ordinal": int(slot["ordinal"])}
                for slot in target_slots
                for name in (list(slot["names"]) if slot["names"] else [None])
            ),
            key=lambda row: (
                int(row["ordinal"]),
                "" if row["name"] is None else str(row["name"]),
            ),
        )
        matched: dict[tuple[str, str | int], SelectedMachineImportContract] = {}
        for alias in aliases:
            ordinal_identity = MachineImportIdentity(
                provider_dll, "ordinal", int(alias["ordinal"])
            )
            ordinal_contract = contracts.get(ordinal_identity)
            if ordinal_contract is not None:
                matched[("ordinal", int(alias["ordinal"]))] = ordinal_contract
            name = alias["name"]
            if isinstance(name, str):
                symbol_identity = MachineImportIdentity(
                    provider_dll, "symbol", name
                )
                symbol_contract = contracts.get(symbol_identity)
                if symbol_contract is not None:
                    matched[("symbol", name)] = symbol_contract
        if not matched:
            continue

        lowered: list[tuple[tuple[str, str | int], SelectedMachineImportContract, dict[str, Any]]] = []
        canonical_subject = next(
            (
                str(alias["name"])
                for alias in aliases
                if isinstance(alias["name"], str)
            ),
            f"ordinal:{aliases[0]['ordinal']}",
        )
        for identity_key, contract in sorted(
            matched.items(), key=lambda row: (row[0][0], str(row[0][1]))
        ):
            try:
                boundary = lower_machine_import_boundary_v1(
                    contract,
                    abi_dialect=abi_dialect,
                    subject_kind="export",
                    subject_id=canonical_subject,
                    image_selector=image_id,
                    transfer_kind="export",
                )
            except (ExternalEnvironmentError, ValueError) as exc:
                blockers.append({
                    "category": "module_export_boundary_unresolved",
                    "target_rva": target_rva,
                    "aliases": aliases,
                    "detail": str(exc),
                })
                lowered = []
                break
            lowered.append((identity_key, contract, boundary))
        if not lowered:
            continue
        abi_identities = {
            physical_frame_abi_sha256_v1(
                boundary["physical_call_frame_v3"]
            )
            for _, _, boundary in lowered
        }
        if len(abi_identities) != 1:
            blockers.append({
                "category": "module_export_alias_abi_conflict",
                "target_rva": target_rva,
                "aliases": aliases,
                "matching_contracts": [
                    {
                        "kind": identity_key[0],
                        "value": identity_key[1],
                        "profile_id": contract.profile_id,
                        "profile_sha256": contract.profile_sha256,
                        "entry_key": contract.entry_key,
                        "entry_index": contract.entry_index,
                    }
                    for identity_key, contract, _ in lowered
                ],
            })
            continue
        _, _, boundary = lowered[0]
        schema = boundary["schema"]
        layout = boundary["target_data_layout"]
        frame = boundary["physical_call_frame_v3"]
        physical_abi_sha256 = next(iter(abi_identities))
        catalog: dict[str, Any] = {
            "subject": f"export:{canonical_subject}",
            "kind": "checked_module_export",
            "logical_image_id": image_id,
            "target_rva": target_rva,
            "aliases": aliases,
            "physical_abi_sha256": physical_abi_sha256,
            "checked_call_protocol_id": (
                f"machine-call-protocol-v1:{physical_abi_sha256}"
            ),
            "contract_bindings": [
                {
                    "identity": {
                        "dll": provider_dll,
                        "symbol": (
                            identity_key[1]
                            if identity_key[0] == "symbol" else None
                        ),
                        "ordinal": (
                            identity_key[1]
                            if identity_key[0] == "ordinal" else None
                        ),
                    },
                    "profile_id": contract.profile_id,
                    "profile_sha256": contract.profile_sha256,
                    "entry_key": contract.entry_key,
                    "entry_index": contract.entry_index,
                }
                for identity_key, contract, _ in lowered
            ],
            "artifacts": {
                "boundary_schema": {
                    "sha256": schema["schema_sha256"],
                    "payload": schema,
                },
                "target_data_layout": {
                    "sha256": layout["layout_sha256"],
                    "payload": layout,
                },
                "physical_call_frame_v3": {
                    "sha256": canonical_sha256_v3(frame),
                    "payload": frame,
                },
            },
        }
        catalog["status_sha256"] = canonical_sha256_v3(catalog)
        catalogs.append(catalog)
    return catalogs, blockers

def _machine_boundary_catalogs(
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate inline machine boundaries into the environment catalog."""

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        boundary = row.get("boundary")
        identity = row.get("identity")
        contract = row.get("contract")
        if (
            not isinstance(boundary, Mapping)
            or not isinstance(identity, Mapping)
            or not isinstance(contract, Mapping)
        ):
            continue
        schema = boundary.get("schema")
        layout = boundary.get("target_data_layout")
        frame = boundary.get("physical_call_frame_v3")
        if not all(isinstance(item, Mapping) for item in (schema, layout, frame)):
            continue
        schema_id = schema.get("schema_id")
        if not isinstance(schema_id, str):
            continue
        role = (
            f"support:{row.get('support')}"
            if isinstance(row.get("support"), str)
            else str(row.get("import_kind", "ordinary"))
        )
        catalog = grouped.get(schema_id)
        if catalog is None:
            symbol = identity.get("symbol")
            ordinal = identity.get("ordinal")
            external_id = (
                str(symbol)
                if isinstance(symbol, str)
                else f"ordinal-{ordinal}"
            )
            subject = f"call:{identity.get('dll')}.{external_id}"
            catalog = {
                "subject": subject,
                "kind": "checked_machine_import",
                "roles": [],
                "identity": dict(identity),
                "contract_binding": {
                    key: contract.get(key)
                    for key in (
                        "profile_id", "profile_sha256", "entry_key", "entry_index"
                    )
                },
                "artifacts": {
                    "boundary_schema": {
                        "sha256": schema.get("schema_sha256"),
                        "payload": schema,
                    },
                    "target_data_layout": {
                        "sha256": layout.get("layout_sha256"),
                        "payload": layout,
                    },
                    "physical_call_frame_v3": {
                        "sha256": canonical_sha256_v3(frame),
                        "payload": frame,
                    },
                },
                "memory_views": boundary.get("memory_views", []),
                "callback_protocol": boundary.get("callback_protocol"),
                "external_service_protocol": boundary.get(
                    "external_service_protocol"
                ),
            }
            grouped[schema_id] = catalog
        elif (
            catalog["identity"] != dict(identity)
            or catalog["artifacts"]["physical_call_frame_v3"]["payload"] != frame
        ):
            raise ExternalEnvironmentError(
                f"machine boundary schema identity {schema_id!r} is ambiguous"
            )
        catalog["roles"].append(role)
    for catalog in grouped.values():
        catalog["roles"] = sorted(set(catalog["roles"]))
        catalog["status_sha256"] = canonical_sha256_v3({
            key: value for key, value in catalog.items()
            if key != "status_sha256"
        })
    return sorted(grouped.values(), key=lambda row: row["subject"])

def _machine_callback_catalogs(
    rows: Sequence[Mapping[str, Any]],
    *,
    abi_dialect: str,
    authored_subjects: set[str],
) -> list[dict[str, Any]]:
    """Compile profile-owned callback ABIs not refined by authored intent."""

    catalogs: dict[str, dict[str, Any]] = {}
    for row in rows:
        try:
            catalog = machine_callback_boundary_catalog_v1(
                row, abi_dialect=abi_dialect
            )
        except (MachineCallbackBoundaryError, ValueError) as exc:
            raise ExternalEnvironmentError(str(exc)) from exc
        if catalog is None or catalog["subject"] in authored_subjects:
            continue
        subject = str(catalog["subject"])
        previous = catalogs.get(subject)
        if previous is not None and previous != catalog:
            raise ExternalEnvironmentError(
                f"machine callback subject {subject!r} is ambiguous"
            )
        catalogs[subject] = catalog
    return [catalogs[key] for key in sorted(catalogs)]

def _interface_callback_catalogs(
    interfaces: Sequence[Mapping[str, Any]], *, abi_dialect: str,
) -> list[dict[str, Any]]:
    """Compile checked callback frames from pinned interface method facts."""

    catalogs: dict[str, dict[str, Any]] = {}
    for interface in interfaces:
        profile_id = interface.get("profile_id")
        profile_sha256 = interface.get("profile_sha256")
        interface_id = interface.get("interface_id")
        methods = interface.get("methods")
        if not isinstance(methods, list):
            raise ExternalEnvironmentError(
                "interface method callback catalog is malformed"
            )
        for method in methods:
            if not isinstance(method, Mapping):
                raise ExternalEnvironmentError(
                    "interface method callback entry is malformed"
                )
            target_core = {
                "profile_id": profile_id,
                "profile_sha256": profile_sha256,
                "interface_id": interface_id,
                "method": dict(method),
            }
            target = {
                **target_core,
                "method_contract_sha256": canonical_sha256_v3(target_core),
            }
            try:
                catalog = interface_callback_boundary_catalog_v1(
                    target, abi_dialect=abi_dialect
                )
            except (MachineCallbackBoundaryError, ValueError) as exc:
                raise ExternalEnvironmentError(str(exc)) from exc
            if catalog is None:
                continue
            subject = str(catalog["subject"])
            previous = catalogs.get(subject)
            if previous is not None and previous != catalog:
                raise ExternalEnvironmentError(
                    f"interface callback subject {subject!r} is ambiguous"
                )
            catalogs[subject] = catalog
    return [catalogs[key] for key in sorted(catalogs)]
