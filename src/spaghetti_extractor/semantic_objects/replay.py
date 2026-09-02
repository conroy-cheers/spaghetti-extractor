"""Independent veto-only replay of a ``semantic-object-v1`` package.

This checker deliberately does not import the semantic-object constructor or
its projection helpers.  It rebuilds the important coordinate sets directly
from the strict upstream members, catching common-mode construction bugs.
It never grants authority.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .object_authority import MachineObjectAuthorityV2
from ..external.resolved import ResolvedExternalEnvironmentV1
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..qualified_platform.selection import (
    select_isa_requirements_from_platform_v1,
)
from ..transfer.plan import parse_executable_transfer_plan
from ..transfer.exception_semantics import derive_checked_exception_transitions_v1
from ..util import sha256_bytes
from .formats import SEMANTIC_OBJECT_FORMAT
from .exception_replay import replay_exception_projection
from .replay_primitives import (
    _array,
    _canonical_bytes,
    _data_anchor_id,
    _fail,
    _function_id,
    _import_id,
    _load,
    _load_config_anchor_id,
    _object,
    _object_id,
    _resource_anchor_id,
    _runtime_id,
    _selection_reference,
    _semantic_import_id,
    _semantic_import_identity,
    _tls_anchor_id,
)
from .replay_relocations import (
    _load_config_tables,
    _replay_base_relocations,
    _replay_load_config_relocations,
    _replay_resource_relocations,
    _resource_storage,
    _section_at,
)






def replay_semantic_object_v1(path: Path) -> dict[str, Any]:
    """Replay independently and return non-authorizing comparison metrics."""

    source = Path(path)
    artifact = _load(source, "semantic object")
    plan_raw = _load(
        source.parent / "executable-transfer-plan.json", "transfer-plan member"
    )
    interface_raw = _load(
        source.parent / "module-interface.json", "module-interface member"
    )
    authority_raw = _load(
        source.parent / "machine-object-authority.json",
        "machine-object-authority member",
    )
    plan, transfers = parse_executable_transfer_plan(plan_raw)
    interface = Pe32ModuleInterfaceV2.parse(interface_raw).payload
    authority = MachineObjectAuthorityV2.parse(authority_raw)
    authority_content_sha256 = sha256_bytes(_canonical_bytes(authority.to_payload()))
    if authority.bindings.get("module_interface_sha256") != sha256_bytes(
        _canonical_bytes(interface)
    ):
        _fail("machine-object authority binds a different module interface")
    if artifact.get("format") != SEMANTIC_OBJECT_FORMAT:
        _fail("format is unsupported")
    declared = artifact.get("semantic_object_sha256")
    core = {
        key: value for key, value in artifact.items()
        if key != "semantic_object_sha256"
    }
    if declared != canonical_sha256_v3(core):
        _fail("self hash is stale")
    if (
        artifact.get("status") != "complete"
        or artifact.get("role") != "checked_relocatable"
        or artifact.get("authority") is not False
    ):
        _fail("semantic object is not a checked non-authorizing relocatable")
    members = artifact.get("members")
    expected_members = {
        "module_interface": {
            "path": "module-interface.json",
            "identity": interface["interface_sha256"],
            "content_sha256": sha256_bytes(_canonical_bytes(interface)),
        },
        "transfer_plan": {
            "path": "executable-transfer-plan.json",
            "identity": plan["plan_sha256"],
            "content_sha256": sha256_bytes(_canonical_bytes(plan)),
        },
        "machine_object_authority": {
            "path": "machine-object-authority.json",
            "identity": authority.authority_sha256,
            "content_sha256": authority_content_sha256,
        },
    }
    selection = None
    requirements = None
    platform = None
    checked_exceptions = ()
    environment = None
    environment_content_sha256 = None
    has_platform = "qualified_platform" in _object(
        artifact.get("members"), "members"
    )
    if has_platform:
        requirements = _load(
            source.parent / "isa-requirements.json", "ISA requirements member"
        )
        selection, platform, certificate = (
            select_isa_requirements_from_platform_v1(
                requirements,
                source.parent / "qualified-platform.json",
                transfer_plan=plan,
            )
        )
        expected_members.update({
            "isa_requirements": {
                "path": "isa-requirements.json",
                "identity": requirements["requirements_sha256"],
                "content_sha256": sha256_bytes(_canonical_bytes(requirements)),
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
                "identity": certificate["certificate_sha256"],
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
        stored_selection = _load(
            source.parent / "qualified-platform-selection.json",
            "qualified-platform selection member",
        )
        if stored_selection != selection:
            _fail("qualified-platform selection member is stale")
        if (
            selection["bindings"]["binary_sha256"]
            != plan["bindings"]["pe_sha256"]
            or selection["bindings"]["machine_ir_sha256"]
            != plan["bindings"]["machine_ir_sha256"]
        ):
            _fail("platform selection binds a different exact machine universe")
    elif "isa_requirements" in artifact["members"]:
        _fail("platform package members are only partially present")
    if "resolved_external_environment" in _object(
        artifact["members"], "members"
    ):
        environment_payload = _load(
            source.parent / "resolved-external-environment.json",
            "resolved external environment member",
        )
        environment = ResolvedExternalEnvironmentV1.parse(
            environment_payload, module_interface=interface
        )
        environment_content_sha256 = sha256_bytes(
            _canonical_bytes(environment.payload)
        )
        expected_members["resolved_external_environment"] = {
            "path": "resolved-external-environment.json",
            "identity": environment.identity,
            "content_sha256": environment_content_sha256,
        }
    checked_exceptions = (
        ()
        if environment is None
        else derive_checked_exception_transitions_v1(
            transfers=transfers, environment=environment
        )
    )
    if members != expected_members:
        _fail("member identities disagree")
    bindings = _object(artifact.get("bindings"), "bindings")
    if (
        bindings.get("machine_object_authority_sha256")
        != authority.authority_sha256
        or bindings.get("machine_object_authority_content_sha256")
        != authority_content_sha256
    ):
        _fail("machine-object-authority bindings are stale")
    expected_environment_bindings = (
        None if environment is None else environment.identity,
        environment_content_sha256,
    )
    if (
        bindings.get("resolved_external_environment_sha256"),
        bindings.get("resolved_external_environment_content_sha256"),
    ) != expected_environment_bindings:
        _fail("resolved-external-environment bindings are stale")
    expected_evidence = [{
        "kind": "module_interface",
        "identity": interface["interface_sha256"],
        "content_sha256": sha256_bytes(_canonical_bytes(interface)),
    }, {
        "kind": "transfer_plan",
        "identity": plan["plan_sha256"],
        "content_sha256": sha256_bytes(_canonical_bytes(plan)),
    }, {
        "kind": "machine_object_authority",
        "identity": authority.authority_sha256,
        "content_sha256": authority_content_sha256,
    }]
    if selection is not None:
        assert requirements is not None
        assert platform is not None
        expected_evidence.extend(({
            "kind": "exact_isa_requirements",
            "identity": requirements["requirements_sha256"],
            "content_sha256": sha256_bytes(_canonical_bytes(requirements)),
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
    if environment is not None:
        assert environment_content_sha256 is not None
        expected_evidence.append({
            "kind": "resolved_external_environment",
            "identity": environment.identity,
            "content_sha256": environment_content_sha256,
        })
    observed_evidence = _array(artifact.get("evidence"), "evidence")
    if observed_evidence != expected_evidence:
        _fail("semantic-object evidence inventory is stale")
    if artifact.get("platform_selection") != _selection_reference(selection):
        _fail("qualified-platform occurrence selection is stale")

    symbols = {
        str(row.get("symbol_id")): row
        for row in map(lambda value: _object(value, "symbol"), _array(artifact.get("symbols"), "symbols"))
    }
    definition_rows = [
        _object(value, "definition")
        for value in _array(artifact.get("definitions"), "definitions")
    ]
    evidence_index = {
        str(row["kind"]): index for index, row in enumerate(expected_evidence)
    }
    occurrence_units = {
        str(row["unit_id"])
        for row in (() if selection is None else selection["occurrences"])
    }
    exception_units = {row.unit_id for row in checked_exceptions}
    definitions: dict[str, dict[str, Any]] = {}
    for row in definition_rows:
        body = {
            key: value for key, value in row.items()
            if key != "evidence_dependencies"
        }
        kind = body.get("definition_kind")
        if kind == "transfer_v2":
            transfer_body = _object(body.get("body"), "transfer definition body")
            unit_id = str(transfer_body.get("transfer_id"))
            dependency_kinds = {"transfer_plan"}
            if unit_id in occurrence_units:
                dependency_kinds.update({
                    "exact_isa_requirements", "qualified_platform",
                    "qualified_platform_occurrence_selection",
                })
            if unit_id in exception_units:
                dependency_kinds.add("resolved_external_environment")
        elif kind == "checked_exception_transition":
            dependency_kinds = {
                "transfer_plan", "resolved_external_environment",
            }
        elif kind in {
            "image_object", "object_anchor", "resource_data",
            "resource_directory", "resource_entry", "load_config_table",
        }:
            dependency_kinds = {
                "module_interface", "machine_object_authority",
            }
        elif kind == "loader_section_storage":
            dependency_kinds = {"module_interface"}
        else:
            _fail(f"semantic definition has no evidence policy: {kind}")
        try:
            expected_dependencies = sorted(
                evidence_index[item] for item in dependency_kinds
            )
        except KeyError as exc:
            _fail(f"semantic definition requires absent evidence: {exc.args[0]}")
        if row.get("evidence_dependencies") != expected_dependencies:
            _fail("semantic definition evidence dependencies are stale")
        definitions[str(row.get("symbol_id"))] = body
    if len(symbols) != len(artifact["symbols"]) or len(definitions) != len(artifact["definitions"]):
        _fail("symbol or definition identities are duplicated")

    expected_function_ids: set[str] = set()
    transfer_by_rva: dict[int, str] = {}
    for raw in plan["transfers"]:
        transfer = _object(raw, "transfer")
        transfer_id = str(transfer["identity"])
        symbol_id = _function_id(transfer_id)
        expected_function_ids.add(symbol_id)
        transfer_by_rva[int(transfer["source"]["rva_start"])] = symbol_id
        symbol = symbols.get(symbol_id)
        definition = definitions.get(symbol_id)
        if symbol is None or definition is None:
            _fail(f"transfer definition is missing: {transfer_id}")
        if (
            symbol.get("kind") != "function"
            or symbol.get("original_rva") != transfer["source"]["rva_start"]
            or definition.get("source") != transfer["source"]
            or definition.get("body") != {
                "language": "executable-transfer-plan-v2",
                "member": "executable-transfer-plan.json",
                "transfer_id": transfer_id,
                "transfer_sha256": canonical_sha256_v3(transfer),
            }
        ):
            _fail(f"transfer definition is stale: {transfer_id}")
    observed_function_ids = {
        symbol_id for symbol_id, row in symbols.items() if row.get("kind") == "function"
    }
    if observed_function_ids != expected_function_ids:
        _fail("function symbol inventory is not exact")

    expected_data_ids: set[str] = set()
    headers = interface["runtime_headers"]
    header_origin = f"image:{interface['image_id']}:headers"
    header_id = _object_id(header_origin)
    expected_data_ids.add(header_id)
    if symbols.get(header_id) != {
        "symbol_id": header_id,
        "kind": "data",
        "linkage": "module_local",
        "visibility": "loader",
        "storage_class": "image_headers",
        "logical_type": None,
        "physical_frame": None,
        "lifetime": "image",
        "permissions": {"read": True, "write": False, "execute": False},
        "original_rva": 0,
    } or definitions.get(header_id) != {
        "symbol_id": header_id,
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
    }:
        _fail("runtime PE-header object is stale")
    for raw in interface["sections"]:
        section = _object(raw, "module section")
        if section["executable"]:
            continue
        symbol_id = _object_id(str(section["default_object_origin"]))
        expected_data_ids.add(symbol_id)
        symbol, definition = symbols.get(symbol_id), definitions.get(symbol_id)
        if (
            symbol is None or definition is None
            or symbol.get("kind") != "data"
            or symbol.get("permissions") != section["permissions"]
            or definition.get("object", {}).get("extent") != section["mapped_size"]
        ):
            _fail(f"section object is stale: {symbol_id}")
    if {key for key, row in symbols.items() if row.get("kind") == "data"} != expected_data_ids:
        _fail("data symbol inventory is not exact")

    expected_loader_storage_ids: set[str] = set()
    transfer_ranges = [
        (
            int(row["source"]["rva_start"]),
            int(row["source"]["rva_end"]),
        )
        for row in plan["transfers"]
    ]
    for block in interface["base_relocations"]:
        for relocation in block["relocations"]:
            if int(relocation["type"]) == 0:
                continue
            rva = int(relocation["target_rva"])
            width = int(relocation["width"])
            section = _section_at(interface, rva)
            if section is None or not section["executable"]:
                continue
            matches = [
                True for start, end in transfer_ranges
                if start <= rva and rva + width <= end
            ]
            if len(matches) == 1:
                continue
            symbol_id = (
                f"original:loader-storage:image:{interface['image_id']}:"
                f"section:{section['index']}"
            )
            expected_loader_storage_ids.add(symbol_id)
            if symbols.get(symbol_id) != {
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
            } or definitions.get(symbol_id) != {
                "symbol_id": symbol_id,
                "definition_kind": "loader_section_storage",
                "storage": {
                    "extent": section["mapped_size"],
                    "section_index": section["index"],
                    "section_name": section["name"],
                    "relocation_only": True,
                },
            }:
                _fail(f"loader section storage is stale: {symbol_id}")
    if {
        key for key, row in symbols.items()
        if row.get("kind") == "loader_storage"
    } != expected_loader_storage_ids:
        _fail("loader section storage inventory is not exact")

    expected_anchor_ids: set[str] = set()

    def check_anchor(
        *, symbol_id: str, anchor_kind: str, storage_class: str,
        rva: int, extent: int | None, lifetime: str, visibility: str,
        initialization: Mapping[str, Any],
    ) -> None:
        section = _section_at(interface, rva)
        if (
            section is None or section["executable"]
            or (
                extent is not None
                and rva - int(section["rva"]) + extent
                > int(section["mapped_size"])
            )
        ):
            return
        expected_anchor_ids.add(symbol_id)
        if symbols.get(symbol_id) != {
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
        }:
            _fail(f"typed data-anchor symbol is stale: {symbol_id}")
        if definitions.get(symbol_id) != {
            "symbol_id": symbol_id,
            "definition_kind": "object_anchor",
            "anchor": {
                "parent_symbol": _object_id(
                    str(section["default_object_origin"])
                ),
                "offset": rva - int(section["rva"]),
                "extent": extent,
                "initialization": dict(initialization),
            },
        }:
            _fail(f"typed data-anchor definition is stale: {symbol_id}")

    def check_resource_anchor(
        *, symbol_id: str, anchor_kind: str, storage_class: str,
        rva: int, extent: int, initialization: Mapping[str, Any],
    ) -> None:
        storage = _resource_storage(interface, rva, extent)
        if storage is None:
            return
        parent_symbol, offset, permissions = storage
        expected_anchor_ids.add(symbol_id)
        if symbols.get(symbol_id) != {
            "symbol_id": symbol_id,
            "kind": "data_anchor",
            "linkage": "module_local",
            "visibility": "loader",
            "storage_class": storage_class,
            "logical_type": None,
            "physical_frame": None,
            "lifetime": "image",
            "permissions": permissions,
            "original_rva": rva,
            "anchor_kind": anchor_kind,
        }:
            _fail(f"resource data-anchor symbol is stale: {symbol_id}")
        if definitions.get(symbol_id) != {
            "symbol_id": symbol_id,
            "definition_kind": "object_anchor",
            "anchor": {
                "parent_symbol": parent_symbol,
                "offset": offset,
                "extent": extent,
                "initialization": dict(initialization),
            },
        }:
            _fail(f"resource data-anchor definition is stale: {symbol_id}")

    for rva in sorted({
        int(slot["rva"])
        for slot in interface["export_directory"]["slots"]
        if slot["kind"] == "data"
    }):
        check_anchor(
            symbol_id=_data_anchor_id(rva), anchor_kind="data_export",
            storage_class="data_export_anchor", rva=rva, extent=None,
            lifetime="image", visibility="loader",
            initialization={
                "kind": "existing_image_bytes",
                "member": "module-interface.json",
            },
        )
    tls = interface["tls"]
    if tls is not None:
        if tls["template_rva"] is not None:
            rva = int(tls["template_rva"])
            check_anchor(
                symbol_id=_tls_anchor_id("template", rva),
                anchor_kind="tls_template", storage_class="tls_template",
                rva=rva,
                extent=int(tls["template_size"]) + int(tls["zero_fill_size"]),
                lifetime="thread", visibility="module",
                initialization={
                    "kind": "tls_template", "member": "module-interface.json",
                    "template_sha256": tls["template_sha256"],
                    "template_size": tls["template_size"],
                    "zero_fill_size": tls["zero_fill_size"],
                },
            )
        if tls["index_rva"] is not None:
            rva = int(tls["index_rva"])
            check_anchor(
                symbol_id=_tls_anchor_id("index", rva),
                anchor_kind="tls_index_cell", storage_class="tls_index_cell",
                rva=rva, extent=4, lifetime="image", visibility="loader",
                initialization={"kind": "loader_tls_index", "size": 4},
            )
        if tls["callback_array_rva"] is not None:
            rva = int(tls["callback_array_rva"])
            check_anchor(
                symbol_id=_tls_anchor_id("callback-array", rva),
                anchor_kind="tls_callback_array",
                storage_class="tls_callback_array", rva=rva,
                extent=4 * (len(tls["callbacks"]) + 1),
                lifetime="image", visibility="loader",
                initialization={
                    "kind": "tls_callback_array",
                    "callback_count": len(tls["callbacks"]),
                    "member": "module-interface.json",
                },
            )
    load_config = interface["load_config"]
    if load_config is not None:
        directory_rva = int(load_config["directory_rva"])
        check_anchor(
            symbol_id=_load_config_anchor_id(
                "directory", "load-config", directory_rva
            ),
            anchor_kind="load_config_directory",
            storage_class="load_config_directory",
            rva=directory_rva,
            extent=int(load_config["structure_size"]),
            lifetime="image",
            visibility="loader",
            initialization={
                "kind": "load_config_directory",
                "member": "module-interface.json",
                "directory_size": load_config["directory_size"],
                "structure_size": load_config["structure_size"],
            },
        )
        image_base = int(interface["loader"]["preferred_base"])
        for table in _load_config_tables(load_config):
            if table["table_va"] == 0 and table["count"] == 0:
                continue
            table_rva = int(table["table_va"]) - image_base
            check_anchor(
                symbol_id=_load_config_anchor_id(
                    "table", str(table["name"]), table_rva
                ),
                anchor_kind="load_config_table",
                storage_class="load_config_table",
                rva=table_rva,
                extent=int(table["count"]) * int(table["entry_stride"]),
                lifetime="image",
                visibility="loader",
                initialization={
                    "kind": "load_config_table",
                    "member": "module-interface.json",
                    "name": table["name"],
                    "count": table["count"],
                    "entry_stride": table["entry_stride"],
                    "entries": table["entries"],
                },
            )
    resources = interface["resources"]
    if resources is not None:
        base_rva = int(resources["directory_rva"])
        names: dict[int, Mapping[str, Any]] = {}
        for directory in resources["directories"]:
            relative = int(directory["relative_offset"])
            check_resource_anchor(
                symbol_id=_resource_anchor_id("directory", relative),
                anchor_kind="resource_directory",
                storage_class="resource_directory",
                rva=base_rva + relative,
                extent=16 + 8 * len(directory["entries"]),
                initialization={
                    "kind": "resource_directory",
                    "member": "module-interface.json",
                    "directory_id": directory["directory_id"],
                },
            )
            for entry in directory["entries"]:
                name = entry["name"]
                if name["kind"] == "string":
                    names[int(name["relative_offset"])] = name
        for relative, name in sorted(names.items()):
            check_resource_anchor(
                symbol_id=_resource_anchor_id("name", relative),
                anchor_kind="resource_name",
                storage_class="resource_name",
                rva=base_rva + relative,
                extent=2 + len(bytes.fromhex(str(name["utf16le_hex"]))),
                initialization={
                    "kind": "resource_name",
                    "member": "module-interface.json",
                    "text": name["text"],
                    "utf16le_hex": name["utf16le_hex"],
                },
            )
        for data in resources["data_entries"]:
            relative = int(data["relative_offset"])
            check_resource_anchor(
                symbol_id=_resource_anchor_id("data-entry", relative),
                anchor_kind="resource_data_entry",
                storage_class="resource_data_entry",
                rva=base_rva + relative,
                extent=16,
                initialization={
                    "kind": "resource_data_entry",
                    "member": "module-interface.json",
                    "data_id": data["data_id"],
                    "code_page": data["code_page"],
                    "reserved": data["reserved"],
                },
            )
            check_resource_anchor(
                symbol_id=_resource_anchor_id("content", relative),
                anchor_kind="resource_content",
                storage_class="resource_content",
                rva=int(data["data_rva"]),
                extent=int(data["size"]),
                initialization={
                    "kind": "resource_content",
                    "member": "module-interface.json",
                    "data_id": data["data_id"],
                    "content_sha256": data["content_sha256"],
                    "size": data["size"],
                    "code_page": data["code_page"],
                },
            )
    if {
        key for key, row in symbols.items()
        if row.get("kind") == "data_anchor"
    } != expected_anchor_ids:
        _fail("typed data-anchor inventory is not exact")

    environment_contracts: dict[str, Mapping[str, Any]] = {}
    loader_services: dict[str, Mapping[str, Any]] = {}
    if environment is not None:
        environment_rows = list(
            environment.payload["machine_import_contracts"]
        )
        for raw_service in environment.payload["loader_service_contracts"]:
            service = _object(raw_service, "resolved loader-service contract")
            catalog = service.get("resolution_catalog", [])
            if not isinstance(catalog, list):
                _fail("resolved loader-service resolution catalog is malformed")
            for raw_target in catalog:
                target = _object(
                    raw_target, "resolved dynamic-export contract"
                )
                if target.get("dynamic_export_kind") == "code":
                    environment_rows.append(target)
        for raw in environment_rows:
            contract = _object(raw, "resolved machine-import contract")
            identity = _object(
                contract.get("identity"), "resolved machine-import identity"
            )
            if contract.get("boundary") is None:
                continue
            _object(
                contract.get("boundary"), "resolved machine-import boundary"
            )
            key = canonical_sha256_v3(dict(identity))
            if key in environment_contracts:
                if environment_contracts[key] == contract:
                    continue
                _fail("resolved environment duplicates an import identity")
            environment_contracts[key] = contract
        for raw in environment.payload["loader_service_contracts"]:
            contract = _object(raw, "resolved loader-service contract")
            identity = _object(
                contract.get("identity"), "resolved loader-service identity"
            )
            profile = _object(
                contract.get("contract"),
                "resolved loader-service profile contract",
            )
            profile_payload = _object(
                profile.get("payload"),
                "resolved loader-service profile payload",
            )
            if not isinstance(profile_payload.get("loader_service"), Mapping):
                continue
            key = canonical_sha256_v3(dict(identity))
            if key in loader_services:
                _fail("resolved environment duplicates a loader-service identity")
            loader_services[key] = contract
            catalog = contract.get("resolution_catalog", [])
            if not isinstance(catalog, list):
                _fail("resolved loader-service resolution catalog is malformed")
            for raw_target in catalog:
                target = _object(
                    raw_target, "resolved dynamic-export contract"
                )
                if target.get("dynamic_export_kind") != "code":
                    continue
                target_identity = _object(
                    target.get("identity"), "dynamic-export identity"
                )
                target_key = canonical_sha256_v3(dict(target_identity))
                prior = loader_services.get(target_key)
                if prior is not None and prior != contract:
                    _fail("dynamic-export identity has ambiguous loader services")
                loader_services[target_key] = contract

    imports = [
        (False, row) for row in interface["imports"]
    ] + [
        (True, cell)
        for descriptor in interface["delay_imports"]
        for cell in descriptor["cells"]
    ]
    expected_import_ids = {
        _import_id(str(row["slot_id"]), delay) for delay, row in imports
    }
    if {
        key for key, row in symbols.items()
        if row.get("kind") == "unclassified_import"
    } != expected_import_ids:
        _fail("import symbol inventory is not exact")
    for delay, row in imports:
        symbol = symbols[_import_id(str(row["slot_id"]), delay)]
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
        if symbol.get("declaration") != {
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
        }:
            _fail("original import declaration identity is stale")

    # Reconstruct the same complete callable catalog as object construction.
    # A transfer may reach a checked function value through an IAT datum or
    # another indirect dispatch without containing a statically named
    # external-call row, so transfer-local identities alone are not the
    # semantic declaration universe.  The independent replay deliberately
    # rebuilds this union instead of trusting the stored symbol inventory.
    semantic_imports: dict[str, dict[str, Any]] = {}

    def add_semantic_import(identity: Mapping[str, Any]) -> None:
        normalized = {
            "dll": str(identity["dll"]),
            "symbol": identity.get("symbol"),
            "ordinal": identity.get("ordinal"),
        }
        symbol_id = _semantic_import_id(normalized)
        previous = semantic_imports.get(symbol_id)
        if previous is not None and previous != normalized:
            _fail("semantic import identity hash collision")
        semantic_imports[symbol_id] = normalized

    for contract in environment_contracts.values():
        add_semantic_import(_object(
            contract.get("identity"), "resolved semantic-import identity"
        ))
    for transfer in plan["transfers"]:
        for raw_call in transfer["calls"]:
            call = _object(raw_call, "transfer call")
            if call["kind"] != "external_call":
                continue
            add_semantic_import(_semantic_import_identity(call))
    expected_semantic_import_ids = set(semantic_imports)
    if {
        key for key, row in symbols.items()
        if row.get("kind") == "external_function"
    } != expected_semantic_import_ids:
        _fail("original semantic-import declaration inventory is not exact")
    for symbol_id, identity in semantic_imports.items():
        identity_sha256 = canonical_sha256_v3(identity)
        contract = environment_contracts.get(identity_sha256)
        loader_service = (
            loader_services.get(identity_sha256)
            if contract is not None else None
        )
        raw_boundary = None if contract is None else contract.get("boundary")
        boundary = (
            None if raw_boundary is None
            else _object(raw_boundary, "resolved import boundary")
        )
        schema = (
            None if boundary is None
            else _object(boundary.get("schema"), "resolved boundary schema")
        )
        if symbols[symbol_id] != {
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
        }:
            _fail("original semantic-import declaration is stale")

    expected_runtime_ids = {
        _runtime_id(str(provider))
        for provider in plan["runtime_provider_requirements"]
    }
    if {
        key for key, row in symbols.items()
        if row.get("kind") == "runtime_primitive"
    } != expected_runtime_ids:
        _fail("runtime-primitive declaration inventory is not exact")
    for provider in plan["runtime_provider_requirements"]:
        symbol = symbols[_runtime_id(str(provider))]
        if symbol.get("declaration") != {
            "namespace": "generated_runtime_support",
            "provider_id": provider,
            "source": "executable-transfer-plan-v2",
        }:
            _fail("generated runtime-support declaration is stale")
    (
        expected_exception_symbols,
        expected_exception_definitions,
        expected_exception_relocations,
    ) = replay_exception_projection(checked_exceptions, plan)
    if {
        key: row for key, row in symbols.items()
        if row.get("kind") == "exception_transition"
    } != expected_exception_symbols:
        _fail("checked exceptional-transition declarations are stale")
    for symbol_id, definition in expected_exception_definitions.items():
        if definitions.get(symbol_id) != definition:
            _fail("checked exceptional-transition definition is stale")
    if set(symbols) != (
        expected_function_ids | expected_data_ids
        | expected_anchor_ids | expected_import_ids
        | expected_semantic_import_ids | expected_runtime_ids
        | expected_loader_storage_ids | set(expected_exception_symbols)
    ):
        _fail("semantic symbol inventory contains an undeclared namespace")
    if set(definitions) != (
        expected_function_ids | expected_data_ids | expected_anchor_ids
        | expected_loader_storage_ids
        | set(expected_exception_definitions)
    ):
        _fail("semantic definition inventory contains an undeclared definition")

    relocations = _array(artifact.get("relocations"), "relocations")
    expected_relocations: list[dict[str, Any]] = []
    for delay, row in imports:
        rva = int(row["iat_rva"])
        section = _section_at(interface, rva)
        source_symbol = None
        offset = None
        if section is not None and not section["executable"]:
            source_symbol = _object_id(str(section["default_object_origin"]))
            offset = rva - int(section["rva"])
        expected_relocations.append({
            "relocation_id": (
                f"loader:{'delay-iat' if delay else 'iat'}:{row['slot_id']}"
            ),
            "kind": "delay_iat_slot" if delay else "iat_slot",
            "source_symbol": source_symbol,
            "source_rva": rva,
            "offset": offset,
            "site": {"kind": "loader_slot", "iat_rva": rva},
            "target_symbol": _import_id(str(row["slot_id"]), delay),
            "target_rva": None,
            "selector_value": None,
            "addend": 0,
            "required_view": None,
            "status": "unresolved",
        })

    coordinate_counts: dict[tuple[str, int, int], int] = {}
    for raw in plan["direct_control_edges"]:
        edge = _object(raw, "direct control edge")
        edge_kind = str(edge["kind"])
        if edge_kind == "internal_call":
            continue
        if edge_kind != "control":
            _fail(f"unsupported direct control edge kind: {edge_kind}")
        source_rva = int(edge["source_rva"])
        target_rva = int(edge["target_rva"])
        coordinate = (edge_kind, source_rva, target_rva)
        occurrence = coordinate_counts.get(coordinate, 0)
        coordinate_counts[coordinate] = occurrence + 1
        source_symbol = transfer_by_rva.get(source_rva)
        target_symbol = transfer_by_rva.get(target_rva)
        expected_relocations.append({
            "relocation_id": (
                f"transfer:{edge_kind}:{source_rva:08x}:{target_rva:08x}:"
                f"{occurrence}"
            ),
            "kind": "internal_call" if edge_kind == "internal_call"
            else "direct_control",
            "source_symbol": source_symbol,
            "source_rva": source_rva,
            "offset": None,
            "site": {
                "kind": "transfer_outcome", "source_rva": source_rva,
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
    for transfer in plan["transfers"]:
        source_rva = int(transfer["source"]["rva_start"])
        source_symbol = transfer_by_rva[source_rva]
        for raw_call in transfer["calls"]:
            call = _object(raw_call, "transfer call")
            call_id = int(call["id"])
            instruction_rva = int(call["instruction_rva"])
            site = {
                "kind": "call",
                "call_id": call_id,
                "event_index": int(call["event_index"]),
                "instruction_rva": instruction_rva,
                "return_rva": int(call["return_rva"]),
            }
            if call["kind"] == "internal_call":
                target_rva = int(call["target_rva"])
                target_symbol = transfer_by_rva.get(target_rva)
                expected_relocations.append({
                    "relocation_id": (
                        f"transfer:internal-call:{source_rva:08x}:"
                        f"{call_id}:{instruction_rva:08x}:{target_rva:08x}"
                    ),
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
                continue
            if call["kind"] == "indirect_call":
                target_node = int(call["target_node"])
                expected_relocations.append({
                    "relocation_id": (
                        f"transfer:indirect-call:{source_rva:08x}:"
                        f"{call_id}:{instruction_rva:08x}:{target_node}"
                    ),
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
                continue
            if call["kind"] != "external_call":
                _fail(f"unsupported transfer call kind: {call['kind']}")
            identity = _semantic_import_identity(call)
            expected_relocations.append({
                "relocation_id": (
                    f"transfer:external-call:{source_rva:08x}:"
                    f"{call_id}:{instruction_rva:08x}:"
                    f"{canonical_sha256_v3(identity)[:24]}"
                ),
                "kind": "external_call",
                "source_symbol": source_symbol,
                "source_rva": source_rva,
                "offset": None,
                "site": site,
                "target_symbol": _semantic_import_id(identity),
                "target_rva": None,
                "selector_value": None,
                "addend": 0,
                "required_view": {"kind": "code_capability"},
                "status": "unresolved_external",
            })
    for raw in plan["finite_control_routes"]:
        inventory = _object(raw, "finite control route inventory")
        source_rva = int(inventory["source_rva"])
        source_symbol = transfer_by_rva.get(source_rva)
        for raw_route in inventory["routes"]:
            route = _object(raw_route, "finite control route")
            selector = int(route["selector_value"])
            target_rva = int(route["target_rva"])
            target_symbol = transfer_by_rva.get(target_rva)
            expected_relocations.append({
                "relocation_id": (
                    f"transfer:finite-control:{source_rva:08x}:"
                    f"{selector:08x}:{target_rva:08x}"
                ),
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
    expected_relocations.extend(
        _replay_load_config_relocations(plan, interface)
    )
    expected_relocations.extend(
        _replay_base_relocations(plan, interface)
    )
    expected_relocations.extend(
        _replay_resource_relocations(interface)
    )
    expected_relocations.extend(expected_exception_relocations)
    expected_relocations.sort(key=lambda row: str(row["relocation_id"]))
    if relocations != expected_relocations:
        _fail("typed relocation inventory does not replay from exact inputs")

    expected_roots: dict[str, tuple[str, int, str | None]] = {}
    loader = interface["loader"]
    if loader["entry_rva"]:
        rva = int(loader["entry_rva"])
        expected_roots[f"module:{loader['entry_kind']}"] = (
            str(loader["entry_kind"]), rva, transfer_by_rva.get(rva)
        )
    for slot in interface["export_directory"]["slots"]:
        if slot["kind"] == "hole":
            continue
        root_id, rva = f"export:ordinal:{slot['ordinal']}", int(slot["rva"])
        target = transfer_by_rva.get(rva) if slot["kind"] == "code" else None
        if slot["kind"] == "data":
            section = _section_at(interface, rva)
            target = (
                None if section is None or section["executable"] else
                _data_anchor_id(rva)
            )
        expected_roots[root_id] = (
            "export" if slot["kind"] == "code" else
            "data_export" if slot["kind"] == "data" else "forwarder",
            rva, target,
        )
    if interface["tls"] is not None:
        for callback in interface["tls"]["callbacks"]:
            rva = int(callback["rva"])
            expected_roots[f"tls-callback:{callback['order']}"] = (
                "tls_callback", rva, transfer_by_rva.get(rva)
            )
    observed_roots = {
        str(row.get("root_id")): (
            str(row.get("kind")), int(row.get("original_rva")),
            row.get("target_symbol"),
        )
        for row in map(lambda value: _object(value, "root"), _array(artifact.get("roots"), "roots"))
    }
    if observed_roots != expected_roots:
        _fail("root coordinates do not replay from the loader surface")

    effects = _object(artifact.get("effect_index"), "effect index")
    for field in (
        "direct_control_edges", "finite_control_routes",
        "atomic_effect_authority", "runtime_provider_requirements",
    ):
        reference = _object(effects.get(field), f"effect reference {field}")
        if reference != {
            "member": "executable-transfer-plan.json", "field": field,
            "count": len(plan[field]), "sha256": canonical_sha256_v3(plan[field]),
        }:
            _fail(f"effect reference is stale: {field}")
    exception_reference = effects.get("exceptional_transitions")
    checked_projection = [row.payload() for row in checked_exceptions]
    expected_exception_reference = {
        "source": "transfer_v2_resolved_environment",
        "count": len(checked_projection),
        "checked_projection_sha256": canonical_sha256_v3(
            checked_projection
        ),
        "checked_projection": checked_projection,
    }
    if exception_reference != expected_exception_reference:
        _fail("exceptional-transition effect reference is stale")
    hole_kinds = {
        str(_object(row, "hole").get("kind"))
        for row in _array(artifact.get("holes"), "holes")
    }
    if not {
        "boundary_types_unlinked", "physical_frames_unlinked",
        "effect_closure_unlinked", "evidence_inventory_unlinked",
        "object_views_unlinked",
    } <= hole_kinds:
        _fail("mandatory migration holes were silently removed")
    if selection is None and "qualified_platform_selection_missing" not in hole_kinds:
        _fail("missing qualified-platform selection was not reported")
    expected_exception_count = sum(
        len(row.get("exception_occurrences", ()))
        for row in plan["transfers"]
    )
    if (
        (len(checked_exceptions) != expected_exception_count)
        != ("exception_transitions_unlinked" in hole_kinds)
    ):
        _fail("exception-transition coverage hole is stale")
    expected_incomplete_exceptions = sum(
        not row.authorizing for row in checked_exceptions
    )
    if sum(
        _object(row, "hole").get("kind")
        == "exception_transition_not_authoritative"
        for row in artifact["holes"]
    ) != expected_incomplete_exceptions:
        _fail("exceptional-transition authority holes are stale")
    if selection is not None:
        expected_platform_hole_count = len(selection["issues"])
        if sum(
            _object(row, "hole").get("kind")
            == "qualified_platform_selection_incomplete"
            for row in artifact["holes"]
        ) != expected_platform_hole_count:
            _fail("qualified-platform selection holes are stale")
    counts = _object(artifact.get("counts"), "counts")
    observed_counts = {
        "transfers": len(plan["transfers"]), "symbols": len(symbols),
        "definitions": len(definitions), "relocations": len(relocations),
        "roots": len(observed_roots), "evidence": len(artifact["evidence"]),
        "holes": len(artifact["holes"]),
        "isa_forms": 0 if selection is None else len(selection["forms"]),
        "isa_occurrences": (
            0 if selection is None else len(selection["occurrences"])
        ),
        "isa_occurrences_qualified": (
            0 if selection is None else sum(
                {
                    form["form_id"]: form["status"]
                    for form in selection["forms"]
                }[row["form_id"]] == "qualified"
                for row in selection["occurrences"]
            )
        ),
    }
    if counts != observed_counts:
        _fail("counts are stale")
    return {
        "authority": False,
        "semantic_object_sha256": declared,
        "transfer_plan_sha256": plan["plan_sha256"],
        "module_interface_sha256": interface["interface_sha256"],
        "platform_selection_sha256": (
            None if selection is None else selection["selection_sha256"]
        ),
        "counts": observed_counts,
    }


__all__ = ["replay_semantic_object_v1"]
