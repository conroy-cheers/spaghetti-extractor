"""Faithful semantic projection of typed PE32 loader metadata.

This module consumes only facts already accepted by
``pe32-module-interface-v2``.  It never reads PE bytes and never infers a
pointer from executable behavior.  Exact targets become relocations; anything
that cannot be named by an existing transfer or section object remains a typed
link hole.
"""

from __future__ import annotations

from typing import Any, Mapping


_TYPED_TABLE_FIELDS = {
    "guard_address_taken_iat_entries": 104,
    "guard_long_jump_targets": 112,
    "guard_eh_continuation_targets": 164,
}
_TYPED_TABLE_ENTRY_KINDS = {
    "guard_address_taken_iat_entries": "guard_address_taken_iat_entry",
    "guard_long_jump_targets": "guard_long_jump_target",
    "guard_eh_continuation_targets": "guard_eh_continuation_target",
}


def _function_id(transfer_id: str) -> str:
    return f"original:function:{transfer_id}"


def _object_id(origin: str) -> str:
    return f"original:object:{origin}"


def _import_id(slot_id: str, *, delay: bool = False) -> str:
    namespace = "delay-import" if delay else "import"
    return f"external:{namespace}:{slot_id}"


def load_config_anchor_id(role: str, name: str, rva: int) -> str:
    return f"original:load-config:{role}:{name}:{rva:08x}"


def resource_anchor_id(role: str, relative_offset: int) -> str:
    return f"original:resource:{role}:{relative_offset:08x}"


def _section_at(
    interface: Mapping[str, Any], rva: int,
) -> Mapping[str, Any] | None:
    matches = [
        row for row in interface["sections"]
        if int(row["rva"]) <= rva
        < int(row["rva"]) + int(row["mapped_size"])
    ]
    return matches[0] if len(matches) == 1 else None


def _data_object_at(
    interface: Mapping[str, Any], rva: int,
) -> tuple[str, int] | None:
    headers = interface["runtime_headers"]
    if 0 <= rva < int(headers["size"]):
        return _object_id(f"image:{interface['image_id']}:headers"), rva
    section = _section_at(interface, rva)
    if section is None or section["executable"]:
        return None
    return (
        _object_id(str(section["default_object_origin"])),
        rva - int(section["rva"]),
    )


def _resource_anchor(
    interface: Mapping[str, Any], *, symbol_id: str, anchor_kind: str,
    storage_class: str, rva: int, extent: int,
    initialization: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    parent = _data_object_at(interface, rva)
    headers = interface["runtime_headers"]
    if 0 <= rva < int(headers["size"]):
        available = int(headers["size"]) - rva
        permissions = {"read": True, "write": False, "execute": False}
    else:
        section = _section_at(interface, rva)
        available = 0 if section is None else (
            int(section["rva"]) + int(section["mapped_size"]) - rva
        )
        permissions = None if section is None else dict(section["permissions"])
    if parent is None or permissions is None or bool(permissions["execute"]):
        return None, None, {
            "kind": "resource_anchor_object_missing",
            "subject": symbol_id,
            "detail": (
                f"{anchor_kind} RVA {rva:#x} has no unique "
                "non-executable mapped object"
            ),
        }
    if extent > available:
        return None, None, {
            "kind": "resource_anchor_extent_invalid",
            "subject": symbol_id,
            "detail": (
                f"{anchor_kind} extent {extent} at RVA {rva:#x} exceeds "
                "its containing mapped object"
            ),
        }
    return ({
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
    }, {
        "symbol_id": symbol_id,
        "definition_kind": "object_anchor",
        "anchor": {
            "parent_symbol": parent[0],
            "offset": parent[1],
            "extent": extent,
            "initialization": dict(initialization),
        },
    }, None)


def project_resource_declarations(
    interface: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Project the exact resource tree, name strings, and leaf contents."""

    resources = interface["resources"]
    if resources is None:
        return [], [], []
    symbols: list[dict[str, Any]] = []
    definitions: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []
    base_rva = int(resources["directory_rva"])

    def add(
        *, role: str, relative_offset: int, anchor_kind: str,
        storage_class: str, rva: int, extent: int,
        initialization: Mapping[str, Any],
    ) -> None:
        symbol, definition, hole = _resource_anchor(
            interface,
            symbol_id=resource_anchor_id(role, relative_offset),
            anchor_kind=anchor_kind,
            storage_class=storage_class,
            rva=rva,
            extent=extent,
            initialization=initialization,
        )
        if symbol is not None and definition is not None:
            symbols.append(symbol)
            definitions.append(definition)
        if hole is not None:
            holes.append(hole)

    names: dict[int, Mapping[str, Any]] = {}
    for directory in resources["directories"]:
        relative = int(directory["relative_offset"])
        add(
            role="directory", relative_offset=relative,
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
        add(
            role="name", relative_offset=relative,
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
        add(
            role="data-entry", relative_offset=relative,
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
        add(
            role="content", relative_offset=relative,
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
    return symbols, definitions, holes


def project_resource_relocations(
    interface: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Project root-relative tree links and RVA-bearing content links."""

    resources = interface["resources"]
    if resources is None:
        return [], []
    rows: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []
    base_rva = int(resources["directory_rva"])
    declared, _, _ = project_resource_declarations(interface)
    available = {str(row["symbol_id"]) for row in declared}
    for directory in resources["directories"]:
        source_relative = int(directory["relative_offset"])
        source_symbol = resource_anchor_id("directory", source_relative)
        for entry in directory["entries"]:
            index = int(entry["entry_index"])
            name = entry["name"]
            if name["kind"] == "string":
                name_relative = int(name["relative_offset"])
                target_symbol = resource_anchor_id("name", name_relative)
                relocation_id = (
                    f"loader:resource-name:{source_relative:08x}:{index}"
                )
                status = "resolved_local" if (
                    source_symbol in available and target_symbol in available
                ) else "unresolved"
                rows.append({
                    "relocation_id": relocation_id,
                    "kind": "resource_name_reference",
                    "source_symbol": source_symbol,
                    "source_rva": base_rva + source_relative,
                    "offset": 16 + index * 8,
                    "site": {"kind": "resource_name_field", "entry_index": index},
                    "target_symbol": target_symbol,
                    "target_rva": base_rva + name_relative,
                    "selector_value": None,
                    "addend": name_relative,
                    "required_view": {
                        "kind": "resource_tree_reference",
                        "encoding": "root_relative_offset_with_high_bit",
                    },
                    "status": status,
                })
                if status != "resolved_local":
                    holes.append({
                        "kind": "resource_name_relocation_unresolved",
                        "subject": relocation_id,
                        "detail": "resource name does not resolve to mapped storage",
                    })
            target = entry["target"]
            target_relative = int(target["relative_offset"])
            target_role = "directory" if target["kind"] == "directory" else "data-entry"
            target_symbol = resource_anchor_id(target_role, target_relative)
            relocation_id = (
                f"loader:resource-target:{source_relative:08x}:{index}"
            )
            status = "resolved_local" if (
                source_symbol in available and target_symbol in available
            ) else "unresolved"
            rows.append({
                "relocation_id": relocation_id,
                "kind": "resource_directory_reference"
                if target["kind"] == "directory" else "resource_data_entry_reference",
                "source_symbol": source_symbol,
                "source_rva": base_rva + source_relative,
                "offset": 20 + index * 8,
                "site": {"kind": "resource_target_field", "entry_index": index},
                "target_symbol": target_symbol,
                "target_rva": base_rva + target_relative,
                "selector_value": (
                    name["id"] if name["kind"] == "id" else name["text"]
                ),
                "addend": target_relative,
                "required_view": {
                    "kind": "resource_tree_reference",
                    "encoding": "root_relative_offset"
                    + ("_with_high_bit" if target["kind"] == "directory" else ""),
                },
                "status": status,
            })
            if status != "resolved_local":
                holes.append({
                    "kind": "resource_tree_relocation_unresolved",
                    "subject": relocation_id,
                    "detail": "resource tree edge does not resolve to mapped storage",
                })
    for data in resources["data_entries"]:
        relative = int(data["relative_offset"])
        source_symbol = resource_anchor_id("data-entry", relative)
        target_symbol = resource_anchor_id("content", relative)
        relocation_id = f"loader:resource-content:{relative:08x}"
        status = "resolved_local" if (
            source_symbol in available and target_symbol in available
        ) else "unresolved"
        rows.append({
            "relocation_id": relocation_id,
            "kind": "resource_content_reference",
            "source_symbol": source_symbol,
            "source_rva": base_rva + relative,
            "offset": 0,
            "site": {"kind": "resource_data_rva_field"},
            "target_symbol": target_symbol,
            "target_rva": data["data_rva"],
            "selector_value": None,
            "addend": int(data["data_rva"]),
            "required_view": {
                "kind": "object_reference", "encoding": "image_rva",
            },
            "status": status,
        })
        if status != "resolved_local":
            holes.append({
                "kind": "resource_content_relocation_unresolved",
                "subject": relocation_id,
                "detail": "resource content does not resolve to mapped storage",
            })
    return rows, holes


def _table_specs(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    safe = config["safe_seh"]
    if safe is not None:
        specs.append({
            "name": "safe_seh_handlers",
            "field_offset": 64,
            "table_va": int(safe["table_va"]),
            "count": int(safe["count"]),
            "entry_stride": 4,
            "entries": list(safe["handler_rvas"]),
            "entry_kind": "safe_seh_handler",
        })
    cfg = config["cfg"]
    if cfg is not None:
        specs.append({
            "name": "cfg_functions",
            "field_offset": 80,
            "table_va": int(cfg["function_table_va"]),
            "count": int(cfg["function_count"]),
            "entry_stride": int(cfg["entry_stride"]),
            "entries": list(cfg["function_rvas"]),
            "entry_kind": "cfg_function",
        })
    for table in config["typed_tables"]:
        name = str(table["name"])
        specs.append({
            "name": name,
            "field_offset": _TYPED_TABLE_FIELDS[name],
            "table_va": int(table["table_va"]),
            "count": int(table["count"]),
            "entry_stride": int(table["entry_stride"]),
            "entries": list(table["entries"]),
            "entry_kind": _TYPED_TABLE_ENTRY_KINDS[name],
        })
    return specs


def _anchor(
    interface: Mapping[str, Any], *, symbol_id: str, anchor_kind: str,
    storage_class: str, rva: int, extent: int,
    initialization: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    section = _section_at(interface, rva)
    if section is None or section["executable"]:
        return None, None, {
            "kind": "load_config_anchor_object_missing",
            "subject": symbol_id,
            "detail": (
                f"{anchor_kind} RVA {rva:#x} has no unique "
                "non-executable section object"
            ),
        }
    offset = rva - int(section["rva"])
    if offset + extent > int(section["mapped_size"]):
        return None, None, {
            "kind": "load_config_anchor_extent_invalid",
            "subject": symbol_id,
            "detail": (
                f"{anchor_kind} extent {extent} at RVA {rva:#x} exceeds "
                "its containing section object"
            ),
        }
    return ({
        "symbol_id": symbol_id,
        "kind": "data_anchor",
        "linkage": "module_local",
        "visibility": "loader",
        "storage_class": storage_class,
        "logical_type": None,
        "physical_frame": None,
        "lifetime": "image",
        "permissions": dict(section["permissions"]),
        "original_rva": rva,
        "anchor_kind": anchor_kind,
    }, {
        "symbol_id": symbol_id,
        "definition_kind": "object_anchor",
        "anchor": {
            "parent_symbol": _object_id(str(section["default_object_origin"])),
            "offset": offset,
            "extent": extent,
            "initialization": dict(initialization),
        },
    }, None)


def project_load_config_declarations(
    interface: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Project load-config storage and typed tables as address anchors."""

    config = interface["load_config"]
    if config is None:
        return [], [], []
    symbols: list[dict[str, Any]] = []
    definitions: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []

    directory_rva = int(config["directory_rva"])
    directory_id = load_config_anchor_id(
        "directory", "load-config", directory_rva
    )
    symbol, definition, hole = _anchor(
        interface,
        symbol_id=directory_id,
        anchor_kind="load_config_directory",
        storage_class="load_config_directory",
        rva=directory_rva,
        extent=int(config["structure_size"]),
        initialization={
            "kind": "load_config_directory",
            "member": "module-interface.json",
            "directory_size": config["directory_size"],
            "structure_size": config["structure_size"],
        },
    )
    if symbol is not None and definition is not None:
        symbols.append(symbol)
        definitions.append(definition)
    if hole is not None:
        holes.append(hole)

    image_base = int(interface["loader"]["preferred_base"])
    for table in _table_specs(config):
        if table["table_va"] == 0 and table["count"] == 0:
            continue
        table_rva = table["table_va"] - image_base
        table_id = load_config_anchor_id("table", table["name"], table_rva)
        symbol, definition, hole = _anchor(
            interface,
            symbol_id=table_id,
            anchor_kind="load_config_table",
            storage_class="load_config_table",
            rva=table_rva,
            extent=table["count"] * table["entry_stride"],
            initialization={
                "kind": "load_config_table",
                "member": "module-interface.json",
                "name": table["name"],
                "count": table["count"],
                "entry_stride": table["entry_stride"],
                "entries": table["entries"],
            },
        )
        if symbol is not None and definition is not None:
            symbols.append(symbol)
            definitions.append(definition)
        if hole is not None:
            holes.append(hole)
    return symbols, definitions, holes


def _target_for_rva(
    *, interface: Mapping[str, Any], transfer_by_rva: Mapping[int, str],
    import_by_rva: Mapping[int, str], target_rva: int, target_kind: str,
) -> tuple[str | None, int, Mapping[str, Any], str]:
    if target_kind == "import_slot":
        symbol = import_by_rva.get(target_rva)
        return symbol, 0, {"kind": "loader_import_slot"}, (
            "resolved_local" if symbol is not None else "unresolved"
        )
    if target_kind == "code":
        symbol = transfer_by_rva.get(target_rva)
        return symbol, 0, {"kind": "code_capability"}, (
            "resolved_local" if symbol is not None else "unresolved"
        )
    data_target = _data_object_at(interface, target_rva)
    if data_target is None:
        return None, 0, {
            "kind": "object_reference", "pointer_kind": target_kind,
        }, "unresolved"
    return (
        data_target[0], data_target[1],
        {"kind": "object_reference", "pointer_kind": target_kind},
        "resolved_local",
    )


def project_load_config_relocations(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Project exact load-config pointers and table entries as relocations."""

    config = interface["load_config"]
    if config is None:
        return [], []
    image_base = int(interface["loader"]["preferred_base"])
    directory_rva = int(config["directory_rva"])
    directory_id = load_config_anchor_id(
        "directory", "load-config", directory_rva
    )
    directory_section = _section_at(interface, directory_rva)
    directory_source = (
        directory_id
        if (
            directory_section is not None
            and not directory_section["executable"]
            and directory_rva - int(directory_section["rva"])
            + int(config["structure_size"])
            <= int(directory_section["mapped_size"])
        )
        else None
    )
    transfer_by_rva = {
        int(row["source"]["rva_start"]): _function_id(str(row["identity"]))
        for row in plan["transfers"]
    }
    import_by_rva = {
        int(row["iat_rva"]): _import_id(str(row["slot_id"]), delay=False)
        for row in interface["imports"]
    }
    import_by_rva.update({
        int(cell["iat_rva"]): _import_id(str(cell["slot_id"]), delay=True)
        for descriptor in interface["delay_imports"]
        for cell in descriptor["cells"]
    })
    relocations: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []

    def add(
        *, relocation_id: str, kind: str, field_offset: int,
        site: Mapping[str, Any], target_symbol: str | None,
        target_rva: int | None, addend: int,
        required_view: Mapping[str, Any] | None, status: str,
        hole_kind: str | None = None,
    ) -> None:
        relocations.append({
            "relocation_id": relocation_id,
            "kind": kind,
            "source_symbol": directory_source,
            "source_rva": directory_rva + field_offset,
            "offset": field_offset,
            "site": dict(site),
            "target_symbol": target_symbol,
            "target_rva": target_rva,
            "selector_value": None,
            "addend": addend,
            "required_view": (
                None if required_view is None else dict(required_view)
            ),
            "status": status,
        })
        if hole_kind is not None:
            holes.append({
                "kind": hole_kind,
                "subject": relocation_id,
                "detail": (
                    f"load-config target at field offset {field_offset:#x} "
                    "does not resolve to an exact semantic symbol"
                ),
            })

    for pointer in config["pointer_fields"]:
        name = str(pointer["name"])
        field_offset = int(pointer["field_offset"])
        target = pointer["target"]
        target_kind = str(target["kind"])
        target_rva = (
            None if target.get("rva") is None else int(target["rva"])
        )
        symbol = None
        addend = 0
        view = None
        status = "resolved_null"
        hole_kind = None
        if target_kind == "external":
            status = "unresolved"
            hole_kind = "load_config_pointer_target_unresolved"
            view = {
                "kind": "load_config_pointer",
                "pointer_kind": pointer["pointer_kind"],
            }
        elif target_kind == "image_rva":
            assert target_rva is not None
            semantic_kind = (
                "code" if pointer["pointer_kind"] == "va_code"
                else str(pointer["pointer_kind"])
            )
            symbol, addend, view, status = _target_for_rva(
                interface=interface,
                transfer_by_rva=transfer_by_rva,
                import_by_rva=import_by_rva,
                target_rva=target_rva,
                target_kind=semantic_kind,
            )
            if status == "unresolved":
                hole_kind = "load_config_pointer_target_unresolved"
        add(
            relocation_id=f"loader:load-config:pointer:{name}",
            kind="load_config_pointer",
            field_offset=field_offset,
            site={
                "kind": "load_config_field",
                "name": name,
                "field_offset": field_offset,
                "value_va": pointer["value_va"],
                "pointer_kind": pointer["pointer_kind"],
                "realization_policy": pointer["realization_policy"],
            },
            target_symbol=symbol,
            target_rva=target_rva,
            addend=addend,
            required_view=view,
            status=status,
            hole_kind=hole_kind,
        )

    for table in _table_specs(config):
        name = str(table["name"])
        field_offset = int(table["field_offset"])
        table_rva = (
            None if table["table_va"] == 0
            else int(table["table_va"]) - image_base
        )
        table_id = (
            None if table_rva is None else
            load_config_anchor_id("table", name, table_rva)
        )
        table_section = (
            None if table_rva is None else _section_at(interface, table_rva)
        )
        table_resolved = (
            table_id is not None and table_section is not None
            and not table_section["executable"]
            and table_rva + table["count"] * table["entry_stride"]
            <= int(table_section["rva"]) + int(table_section["mapped_size"])
        )
        add(
            relocation_id=f"loader:load-config:table-pointer:{name}",
            kind="load_config_table_pointer",
            field_offset=field_offset,
            site={
                "kind": "load_config_table_field",
                "name": name,
                "field_offset": field_offset,
                "table_va": table["table_va"],
                "count": table["count"],
                "entry_stride": table["entry_stride"],
            },
            target_symbol=table_id if table_resolved else None,
            target_rva=table_rva,
            addend=0,
            required_view=(
                None if table_rva is None else
                {"kind": "object_reference", "pointer_kind": "va_table"}
            ),
            status=(
                "resolved_null" if table_rva is None
                else "resolved_local" if table_resolved else "unresolved"
            ),
            hole_kind=(
                None if table_rva is None or table_resolved else
                "load_config_table_target_unresolved"
            ),
        )
        if table_rva is None:
            continue
        source_symbol = table_id if table_resolved else None
        for index, entry in enumerate(table["entries"]):
            entry_rva = int(entry)
            if name == "guard_address_taken_iat_entries":
                target_kind = "import_slot"
                capability_role = "address_taken_iat"
            else:
                target_kind = "code"
                capability_role = {
                    "safe_seh_handlers": "exception_handler",
                    "cfg_functions": "indirect_call_target",
                    "guard_long_jump_targets": "nonlocal_continuation",
                    "guard_eh_continuation_targets": "exception_continuation",
                }[name]
            symbol, addend, view, status = _target_for_rva(
                interface=interface,
                transfer_by_rva=transfer_by_rva,
                import_by_rva=import_by_rva,
                target_rva=entry_rva,
                target_kind=target_kind,
            )
            if target_kind == "code":
                view = {**view, "capability_role": capability_role}
            relocation_id = (
                f"loader:load-config:table-entry:{name}:{index}:"
                f"{entry_rva:08x}"
            )
            relocations.append({
                "relocation_id": relocation_id,
                "kind": str(table["entry_kind"]),
                "source_symbol": source_symbol,
                "source_rva": table_rva + index * table["entry_stride"],
                "offset": index * table["entry_stride"],
                "site": {
                    "kind": "load_config_table_entry",
                    "name": name,
                    "index": index,
                    "entry_stride": table["entry_stride"],
                },
                "target_symbol": symbol,
                "target_rva": entry_rva,
                "selector_value": None,
                "addend": addend,
                "required_view": dict(view),
                "status": status,
            })
            if status == "unresolved":
                holes.append({
                    "kind": "load_config_table_entry_unresolved",
                    "subject": relocation_id,
                    "detail": (
                        f"load-config table {name} entry {index} targets "
                        f"RVA {entry_rva:#x} without an exact semantic symbol"
                    ),
                })
    return (
        sorted(relocations, key=lambda row: str(row["relocation_id"])),
        sorted(holes, key=lambda row: (
            str(row["kind"]), str(row["subject"]), str(row["detail"])
        )),
    )


def project_base_relocations(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Project the exact original PE relocation inventory into semantic links."""

    transfers = [
        (
            int(row["source"]["rva_start"]),
            int(row["source"]["rva_end"]),
            _function_id(str(row["identity"])),
        )
        for row in plan["transfers"]
    ]
    transfer_at_start = {start: symbol for start, _, symbol in transfers}
    image_base = int(interface["loader"]["preferred_base"])
    image_size = int(interface["loader"]["image_size"])
    rows: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []

    def source(rva: int, width: int) -> tuple[str | None, int | None]:
        headers = interface["runtime_headers"]
        if 0 <= rva and rva + width <= int(headers["size"]):
            return _object_id(f"image:{interface['image_id']}:headers"), rva
        section = _section_at(interface, rva)
        if section is None or rva + width > int(section["rva"]) + int(section["mapped_size"]):
            return None, None
        if not section["executable"]:
            return (
                _object_id(str(section["default_object_origin"])),
                rva - int(section["rva"]),
            )
        matches = [
            (start, symbol) for start, end, symbol in transfers
            if start <= rva and rva + width <= end
        ]
        return (
            (matches[0][1], rva - matches[0][0])
            if len(matches) == 1 else (
                loader_section_storage_symbol_id(
                    str(interface["image_id"]), int(section["index"])
                ),
                rva - int(section["rva"]),
            )
        )

    for block in interface["base_relocations"]:
        for relocation in block["relocations"]:
            if int(relocation["type"]) == 0:
                continue
            target_rva = int(relocation["target_rva"])
            width = int(relocation["width"])
            source_symbol, source_offset = source(target_rva, width)
            preferred_value = int(relocation["preferred_value"])
            kind = str(relocation["kind"])
            semantic_target_rva = None
            target_symbol = None
            addend = 0
            required_view: dict[str, Any] = {
                "kind": "base_relocation_fragment",
                "relocation_kind": kind,
            }
            status = "unresolved_fragment"
            hole_kind = "fragmented_base_relocation_unlinked"
            if kind == "highlow":
                candidate_rva = preferred_value - image_base
                if 0 <= candidate_rva < image_size:
                    semantic_target_rva = candidate_rva
                    section = _section_at(interface, candidate_rva)
                    data_target = _data_object_at(interface, candidate_rva)
                    if section is not None and section["executable"]:
                        target_symbol = transfer_at_start.get(candidate_rva)
                        required_view = {"kind": "code_capability"}
                    elif data_target is not None:
                        target_symbol, addend = data_target
                        required_view = {"kind": "object_reference"}
                    if target_symbol is not None:
                        status = "resolved_local"
                        hole_kind = ""
                    else:
                        status = "unresolved"
                        hole_kind = "base_relocation_target_unresolved"
                else:
                    status = "unresolved"
                    hole_kind = "base_relocation_target_unresolved"
            relocation_id = (
                f"loader:base-relocation:{int(block['index'])}:"
                f"{int(relocation['slot_index'])}:{target_rva:08x}"
            )
            rows.append({
                "relocation_id": relocation_id,
                "kind": "image_base_relocation",
                "source_symbol": source_symbol,
                "source_rva": target_rva,
                "offset": source_offset,
                "site": {
                    "kind": "pe_base_relocation",
                    "block_index": block["index"],
                    "page_rva": block["page_rva"],
                    "slot_index": relocation["slot_index"],
                    "consumed_slots": relocation["consumed_slots"],
                    "type": relocation["type"],
                    "relocation_kind": kind,
                    "width": width,
                    "preferred_value": preferred_value,
                    "adjustment": relocation["adjustment"],
                },
                "target_symbol": target_symbol,
                "target_rva": semantic_target_rva,
                "selector_value": None,
                "addend": addend,
                "required_view": required_view,
                "status": status,
            })
            if source_symbol is None:
                holes.append({
                    "kind": "base_relocation_source_unresolved",
                    "subject": relocation_id,
                    "detail": (
                        f"base-relocation source RVA {target_rva:#x} does not "
                        "belong to one exact transfer or section object"
                    ),
                })
            if hole_kind:
                holes.append({
                    "kind": hole_kind,
                    "subject": relocation_id,
                    "detail": (
                        f"{kind} relocation at RVA {target_rva:#x} with "
                        f"preferred value {preferred_value:#x} has no exact "
                        "semantic target"
                    ),
                })
    return (
        sorted(rows, key=lambda row: str(row["relocation_id"])),
        sorted(holes, key=lambda row: (
            str(row["kind"]), str(row["subject"]), str(row["detail"])
        )),
    )


def loader_section_storage_symbol_id(image_id: str, section_index: int) -> str:
    """Name executable section bytes used only as loader relocation storage."""

    return (
        f"original:loader-storage:image:{image_id}:section:{section_index}"
    )


def required_loader_section_storage_sections(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
) -> tuple[Mapping[str, Any], ...]:
    """Find executable sections with relocation sources outside transfer bodies."""

    transfers = [
        (
            int(row["source"]["rva_start"]),
            int(row["source"]["rva_end"]),
        )
        for row in plan["transfers"]
    ]
    required: dict[int, Mapping[str, Any]] = {}
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
                True for start, end in transfers
                if start <= rva and rva + width <= end
            ]
            if len(matches) != 1:
                required[int(section["index"])] = section
    return tuple(required[index] for index in sorted(required))


__all__ = [
    "loader_section_storage_symbol_id",
    "required_loader_section_storage_sections",
    "load_config_anchor_id", "project_base_relocations",
    "project_load_config_declarations", "project_load_config_relocations",
]
