"""Independent PE relocation replay helpers for semantic objects."""

from __future__ import annotations

from typing import Any, Mapping

from .replay_primitives import (
    _function_id,
    _import_id,
    _load_config_anchor_id,
    _object,
    _object_id,
    _resource_anchor_id,
)

def _load_config_tables(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    safe = config["safe_seh"]
    if safe is not None:
        rows.append({
            "name": "safe_seh_handlers", "field_offset": 64,
            "table_va": int(safe["table_va"]), "count": int(safe["count"]),
            "entry_stride": 4, "entries": list(safe["handler_rvas"]),
            "entry_kind": "safe_seh_handler",
        })
    cfg = config["cfg"]
    if cfg is not None:
        rows.append({
            "name": "cfg_functions", "field_offset": 80,
            "table_va": int(cfg["function_table_va"]),
            "count": int(cfg["function_count"]),
            "entry_stride": int(cfg["entry_stride"]),
            "entries": list(cfg["function_rvas"]),
            "entry_kind": "cfg_function",
        })
    fields = {
        "guard_address_taken_iat_entries": (
            104, "guard_address_taken_iat_entry"
        ),
        "guard_long_jump_targets": (112, "guard_long_jump_target"),
        "guard_eh_continuation_targets": (
            164, "guard_eh_continuation_target"
        ),
    }
    for table in config["typed_tables"]:
        name = str(table["name"])
        field_offset, entry_kind = fields[name]
        rows.append({
            "name": name, "field_offset": field_offset,
            "table_va": int(table["table_va"]),
            "count": int(table["count"]),
            "entry_stride": int(table["entry_stride"]),
            "entries": list(table["entries"]), "entry_kind": entry_kind,
        })
    return rows


def _section_at(interface: Mapping[str, Any], rva: int) -> Mapping[str, Any] | None:
    for raw in interface["sections"]:
        section = _object(raw, "module section")
        if int(section["rva"]) <= rva < int(section["rva"]) + int(section["mapped_size"]):
            return section
    return None


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


def _resource_storage(
    interface: Mapping[str, Any], rva: int, extent: int,
) -> tuple[str, int, dict[str, bool]] | None:
    parent = _data_object_at(interface, rva)
    headers = interface["runtime_headers"]
    if 0 <= rva < int(headers["size"]):
        available = int(headers["size"]) - rva
        permissions = {"read": True, "write": False, "execute": False}
    else:
        section = _section_at(interface, rva)
        if section is None:
            return None
        available = int(section["rva"]) + int(section["mapped_size"]) - rva
        permissions = dict(section["permissions"])
    if (
        parent is None or permissions["execute"] or extent > available
    ):
        return None
    return parent[0], parent[1], permissions


def _replay_load_config_relocations(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Independently reconstruct exact loader-metadata relocation rows."""

    config = interface["load_config"]
    if config is None:
        return []
    image_base = int(interface["loader"]["preferred_base"])
    directory_rva = int(config["directory_rva"])
    directory_section = _section_at(interface, directory_rva)
    directory_id = _load_config_anchor_id(
        "directory", "load-config", directory_rva
    )
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
    functions = {
        int(row["source"]["rva_start"]): _function_id(str(row["identity"]))
        for row in plan["transfers"]
    }
    imports = {
        int(row["iat_rva"]): _import_id(str(row["slot_id"]), False)
        for row in interface["imports"]
    }
    imports.update({
        int(cell["iat_rva"]): _import_id(str(cell["slot_id"]), True)
        for descriptor in interface["delay_imports"]
        for cell in descriptor["cells"]
    })
    rows: list[dict[str, Any]] = []

    def target(
        rva: int, kind: str,
    ) -> tuple[str | None, int, dict[str, Any], str]:
        if kind == "import_slot":
            symbol = imports.get(rva)
            return symbol, 0, {"kind": "loader_import_slot"}, (
                "resolved_local" if symbol is not None else "unresolved"
            )
        if kind == "code":
            symbol = functions.get(rva)
            return symbol, 0, {"kind": "code_capability"}, (
                "resolved_local" if symbol is not None else "unresolved"
            )
        data = _data_object_at(interface, rva)
        view = {"kind": "object_reference", "pointer_kind": kind}
        if data is None:
            return None, 0, view, "unresolved"
        return data[0], data[1], view, "resolved_local"

    for pointer in config["pointer_fields"]:
        name = str(pointer["name"])
        offset = int(pointer["field_offset"])
        locator = pointer["target"]
        locator_kind = str(locator["kind"])
        target_rva = (
            None if locator.get("rva") is None else int(locator["rva"])
        )
        symbol: str | None = None
        addend = 0
        view: dict[str, Any] | None = None
        status = "resolved_null"
        if locator_kind == "external":
            status = "unresolved"
            view = {
                "kind": "load_config_pointer",
                "pointer_kind": pointer["pointer_kind"],
            }
        elif locator_kind == "image_rva":
            assert target_rva is not None
            semantic_kind = (
                "code" if pointer["pointer_kind"] == "va_code"
                else str(pointer["pointer_kind"])
            )
            symbol, addend, view, status = target(target_rva, semantic_kind)
        rows.append({
            "relocation_id": f"loader:load-config:pointer:{name}",
            "kind": "load_config_pointer",
            "source_symbol": directory_source,
            "source_rva": directory_rva + offset,
            "offset": offset,
            "site": {
                "kind": "load_config_field", "name": name,
                "field_offset": offset, "value_va": pointer["value_va"],
                "pointer_kind": pointer["pointer_kind"],
                "realization_policy": pointer["realization_policy"],
            },
            "target_symbol": symbol,
            "target_rva": target_rva,
            "selector_value": None,
            "addend": addend,
            "required_view": view,
            "status": status,
        })

    capability_roles = {
        "safe_seh_handlers": "exception_handler",
        "cfg_functions": "indirect_call_target",
        "guard_long_jump_targets": "nonlocal_continuation",
        "guard_eh_continuation_targets": "exception_continuation",
    }
    for table in _load_config_tables(config):
        name = str(table["name"])
        offset = int(table["field_offset"])
        table_rva = (
            None if int(table["table_va"]) == 0
            else int(table["table_va"]) - image_base
        )
        table_id = (
            None if table_rva is None else
            _load_config_anchor_id("table", name, table_rva)
        )
        section = None if table_rva is None else _section_at(interface, table_rva)
        resolved = (
            table_id is not None and section is not None
            and not section["executable"]
            and table_rva + int(table["count"]) * int(table["entry_stride"])
            <= int(section["rva"]) + int(section["mapped_size"])
        )
        rows.append({
            "relocation_id": f"loader:load-config:table-pointer:{name}",
            "kind": "load_config_table_pointer",
            "source_symbol": directory_source,
            "source_rva": directory_rva + offset,
            "offset": offset,
            "site": {
                "kind": "load_config_table_field", "name": name,
                "field_offset": offset, "table_va": table["table_va"],
                "count": table["count"],
                "entry_stride": table["entry_stride"],
            },
            "target_symbol": table_id if resolved else None,
            "target_rva": table_rva,
            "selector_value": None,
            "addend": 0,
            "required_view": (
                None if table_rva is None else
                {"kind": "object_reference", "pointer_kind": "va_table"}
            ),
            "status": (
                "resolved_null" if table_rva is None
                else "resolved_local" if resolved else "unresolved"
            ),
        })
        if table_rva is None:
            continue
        for index, raw_entry in enumerate(table["entries"]):
            entry = int(raw_entry)
            target_kind = (
                "import_slot"
                if name == "guard_address_taken_iat_entries" else "code"
            )
            symbol, addend, view, status = target(entry, target_kind)
            if target_kind == "code":
                view = {**view, "capability_role": capability_roles[name]}
            rows.append({
                "relocation_id": (
                    f"loader:load-config:table-entry:{name}:{index}:"
                    f"{entry:08x}"
                ),
                "kind": table["entry_kind"],
                "source_symbol": table_id if resolved else None,
                "source_rva": table_rva + index * int(table["entry_stride"]),
                "offset": index * int(table["entry_stride"]),
                "site": {
                    "kind": "load_config_table_entry", "name": name,
                    "index": index, "entry_stride": table["entry_stride"],
                },
                "target_symbol": symbol,
                "target_rva": entry,
                "selector_value": None,
                "addend": addend,
                "required_view": view,
                "status": status,
            })
    return sorted(rows, key=lambda row: str(row["relocation_id"]))


def _replay_base_relocations(
    plan: Mapping[str, Any], interface: Mapping[str, Any],
) -> list[dict[str, Any]]:
    transfers = [
        (
            int(row["source"]["rva_start"]),
            int(row["source"]["rva_end"]),
            _function_id(str(row["identity"])),
        )
        for row in plan["transfers"]
    ]
    function_starts = {start: symbol for start, _, symbol in transfers}
    image_base = int(interface["loader"]["preferred_base"])
    image_size = int(interface["loader"]["image_size"])
    rows: list[dict[str, Any]] = []

    def source(rva: int, width: int) -> tuple[str | None, int | None]:
        headers = interface["runtime_headers"]
        if 0 <= rva and rva + width <= int(headers["size"]):
            return _object_id(f"image:{interface['image_id']}:headers"), rva
        section = _section_at(interface, rva)
        if (
            section is None
            or rva + width
            > int(section["rva"]) + int(section["mapped_size"])
        ):
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
                (
                    f"original:loader-storage:image:{interface['image_id']}:"
                    f"section:{section['index']}"
                ),
                rva - int(section["rva"]),
            )
        )

    for block in interface["base_relocations"]:
        for relocation in block["relocations"]:
            if int(relocation["type"]) == 0:
                continue
            source_rva = int(relocation["target_rva"])
            width = int(relocation["width"])
            source_symbol, source_offset = source(source_rva, width)
            preferred_value = int(relocation["preferred_value"])
            relocation_kind = str(relocation["kind"])
            target_rva = None
            target_symbol = None
            addend = 0
            view: dict[str, Any] = {
                "kind": "base_relocation_fragment",
                "relocation_kind": relocation_kind,
            }
            status = "unresolved_fragment"
            if relocation_kind == "highlow":
                candidate_rva = preferred_value - image_base
                if 0 <= candidate_rva < image_size:
                    target_rva = candidate_rva
                    section = _section_at(interface, candidate_rva)
                    data = _data_object_at(interface, candidate_rva)
                    if section is not None and section["executable"]:
                        target_symbol = function_starts.get(candidate_rva)
                        view = {"kind": "code_capability"}
                    elif data is not None:
                        target_symbol, addend = data
                        view = {"kind": "object_reference"}
                    status = (
                        "resolved_local"
                        if target_symbol is not None else "unresolved"
                    )
                else:
                    status = "unresolved"
            rows.append({
                "relocation_id": (
                    f"loader:base-relocation:{int(block['index'])}:"
                    f"{int(relocation['slot_index'])}:{source_rva:08x}"
                ),
                "kind": "image_base_relocation",
                "source_symbol": source_symbol,
                "source_rva": source_rva,
                "offset": source_offset,
                "site": {
                    "kind": "pe_base_relocation",
                    "block_index": block["index"],
                    "page_rva": block["page_rva"],
                    "slot_index": relocation["slot_index"],
                    "consumed_slots": relocation["consumed_slots"],
                    "type": relocation["type"],
                    "relocation_kind": relocation_kind,
                    "width": width,
                    "preferred_value": preferred_value,
                    "adjustment": relocation["adjustment"],
                },
                "target_symbol": target_symbol,
                "target_rva": target_rva,
                "selector_value": None,
                "addend": addend,
                "required_view": view,
                "status": status,
            })
    return sorted(rows, key=lambda row: str(row["relocation_id"]))


def _replay_resource_relocations(
    interface: Mapping[str, Any],
) -> list[dict[str, Any]]:
    resources = interface["resources"]
    if resources is None:
        return []
    rows: list[dict[str, Any]] = []
    base_rva = int(resources["directory_rva"])
    available: set[str] = set()
    for directory in resources["directories"]:
        relative = int(directory["relative_offset"])
        if _resource_storage(
            interface, base_rva + relative,
            16 + 8 * len(directory["entries"]),
        ) is not None:
            available.add(_resource_anchor_id("directory", relative))
        for entry in directory["entries"]:
            name = entry["name"]
            if name["kind"] == "string":
                name_relative = int(name["relative_offset"])
                if _resource_storage(
                    interface, base_rva + name_relative,
                    2 + len(bytes.fromhex(str(name["utf16le_hex"]))),
                ) is not None:
                    available.add(_resource_anchor_id("name", name_relative))
    for data in resources["data_entries"]:
        relative = int(data["relative_offset"])
        if _resource_storage(interface, base_rva + relative, 16) is not None:
            available.add(_resource_anchor_id("data-entry", relative))
        if _resource_storage(
            interface, int(data["data_rva"]), int(data["size"])
        ) is not None:
            available.add(_resource_anchor_id("content", relative))
    for directory in resources["directories"]:
        source_relative = int(directory["relative_offset"])
        source_symbol = _resource_anchor_id("directory", source_relative)
        for entry in directory["entries"]:
            index = int(entry["entry_index"])
            name = entry["name"]
            if name["kind"] == "string":
                name_relative = int(name["relative_offset"])
                target_symbol = _resource_anchor_id("name", name_relative)
                rows.append({
                    "relocation_id": (
                        f"loader:resource-name:{source_relative:08x}:{index}"
                    ),
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
                    "status": "resolved_local" if (
                        source_symbol in available and target_symbol in available
                    ) else "unresolved",
                })
            target = entry["target"]
            target_relative = int(target["relative_offset"])
            target_role = (
                "directory" if target["kind"] == "directory" else "data-entry"
            )
            target_symbol = _resource_anchor_id(target_role, target_relative)
            rows.append({
                "relocation_id": (
                    f"loader:resource-target:{source_relative:08x}:{index}"
                ),
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
                "status": "resolved_local" if (
                    source_symbol in available and target_symbol in available
                ) else "unresolved",
            })
    for data in resources["data_entries"]:
        relative = int(data["relative_offset"])
        source_symbol = _resource_anchor_id("data-entry", relative)
        target_symbol = _resource_anchor_id("content", relative)
        rows.append({
            "relocation_id": f"loader:resource-content:{relative:08x}",
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
            "status": "resolved_local" if (
                source_symbol in available and target_symbol in available
            ) else "unresolved",
        })
    return sorted(rows, key=lambda row: str(row["relocation_id"]))
