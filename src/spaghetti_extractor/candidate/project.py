"""Checked multi-image PE32 project planning and completion receipts."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import (
    NATIVE_INGRESS_PLAN_FORMAT,
    PE32_MODULE_DEPLOYMENT_FORMAT,
    PE32_MODULE_INTERFACE_FORMAT,
    PE32_LOAD_OBSERVATION_FORMAT,
    PE32_OBSERVED_LOAD_GRAPH_FORMAT,
    PE32_PROJECT_COMPLETION_FORMAT,
    PE32_PROJECT_INTENT_FORMAT,
    PE32_PROJECT_LOAD_PLAN_FORMAT,
)
from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..pe32.image import parse_pe_image
from ..roundtrip_fuzz.image_io import load_spx_load_image_contract
from ..util import sha256_file, write_json
from .imports import NativeImportSlot


_OWNERSHIP = frozenset({"target", "runtime"})
_IMPLEMENTATIONS = frozenset({"behavioral_c", "native_host"})


def write_pe32_module_interface(
    *,
    image_id: str,
    original_pe: Path,
    load_image_contract: Path,
    out: Path,
) -> dict[str, Any]:
    """Emit the complete typed loader-visible surface of one IA-32 PE32 image."""

    image_id = _text(image_id, "image ID")
    original_pe = Path(original_pe)
    contract_path = Path(load_image_contract)
    contract = load_spx_load_image_contract(contract_path, original_pe=original_pe)
    parsed = parse_pe_image(original_pe)
    try:
        if parsed.machine != "i386" or parsed.bitness != 32:
            raise ToolkitInputError("multi-image PE32 requires an IA-32 PE32 image")
        if parsed.export_parse_error is not None:
            raise ToolkitInputError(
                f"{image_id} export directory is not exact: {parsed.export_parse_error}"
            )
        slots = tuple(
            NativeImportSlot(
                image_id=image_id,
                descriptor_index=descriptor.index,
                cell_index=cell.index,
                dll=descriptor.dll.lower(),
                symbol=cell.symbol,
                ordinal=cell.ordinal,
                iat_rva=cell.iat_rva,
                iat_va=contract.identity.preferred_base + cell.iat_rva,
            )
            for descriptor in contract.imports
            for cell in descriptor.cells
        )
        blockers: list[dict[str, Any]] = []
        export_surface = _export_surface_v2(parsed)
        delay_imports, delay_import_blockers = _delay_import_surface_v2(parsed, image_id)
        blockers.extend(delay_import_blockers)
        load_config, load_config_blockers = _load_config_surface_v2(parsed)
        blockers.extend(load_config_blockers)
        directories, directory_blockers = _directory_surface_v2(parsed, load_config)
        blockers.extend(directory_blockers)
        tls = None if contract.tls is None else contract.tls.to_payload()
        section_rows = [
            {
                "index": section.index,
                "name": section.name,
                "rva": section.rva,
                "mapped_size": section.mapped_size,
                "raw_size": section.raw_size,
                "characteristics": section.characteristics,
                "executable": section.executable,
                "permissions": {
                    "read": bool(section.characteristics & 0x40000000),
                    "write": bool(section.characteristics & 0x80000000),
                    "execute": bool(section.characteristics & 0x20000000),
                },
                "default_object_origin": (
                    None
                    if section.executable
                    else f"image:{image_id}:section:{section.index}"
                ),
            }
            for section in contract.sections
        ]
        payload = {
            "format": PE32_MODULE_INTERFACE_FORMAT,
            "status": "complete" if not blockers else "incomplete",
            "image_id": image_id,
            "kind": "dll" if parsed.is_dll else "executable",
            "identity": {
                "pe_sha256": parsed.sha256,
                "file_size": parsed.size,
                "load_image_contract_sha256": sha256_file(contract_path),
                "load_image_contract_id": contract.hashes.contract_sha256,
            },
            "loader": {
                "preferred_base": parsed.image_base,
                "image_size": parsed.size_of_image,
                "entry_rva": parsed.entrypoint_rva,
                "entry_kind": (
                    None
                    if parsed.entrypoint_rva == 0
                    else "dll_entry" if parsed.is_dll else "process_entry"
                ),
                "subsystem": parsed.subsystem,
                "coff_characteristics": parsed.coff_characteristics,
                "dll_characteristics": int(parsed.pe.OPTIONAL_HEADER.DllCharacteristics),
                "stack": {
                    "reserve": int(parsed.pe.OPTIONAL_HEADER.SizeOfStackReserve),
                    "commit": int(parsed.pe.OPTIONAL_HEADER.SizeOfStackCommit),
                },
            },
            "imports": [slot.payload() for slot in slots],
            "import_descriptors": [
                descriptor.to_payload() for descriptor in contract.imports
            ],
            "delay_imports": delay_imports,
            "export_directory": export_surface,
            "tls": tls,
            "sections": section_rows,
            "load_config": load_config,
            "directories": directories,
            "blockers": blockers,
            "counts": {
                "import_slots": len(slots),
                "import_descriptors": len(contract.imports),
                "delay_import_slots": sum(
                    len(row["cells"]) for row in delay_imports
                ),
                "export_slots": export_surface["slot_count"],
                "export_names": len(export_surface["name_table"]),
                "data_exports": sum(
                    row["kind"] == "data" for row in export_surface["slots"]
                ),
                "tls_callbacks": len(parsed.tls_callback_rvas or ()),
                "blockers": len(blockers),
            },
            "policy": {
                "layout_compatibility": "not_promised",
                "cross_image_addresses": "loader_abi_only",
                "pointer_bearing_directories": "typed_or_fail_closed",
                "bound_import_metadata": "clear_on_composition",
            },
        }
        payload["interface_sha256"] = canonical_sha256_v3(payload)
    finally:
        parsed.pe.close()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "module-interface.json", payload)
    return payload


def _export_surface_v2(parsed: Any) -> dict[str, Any]:
    directory = parsed.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]
    rva, size = int(directory.VirtualAddress), int(directory.Size)
    if rva == 0:
        return {
            "dll_name": None,
            "metadata": None,
            "ordinal_base": 0,
            "slot_count": 0,
            "holes": [],
            "slots": [],
            "name_table": [],
        }
    raw = parsed.pe.get_data(rva, 40)
    if len(raw) != 40:
        raise ToolkitInputError("strict export directory became unavailable")
    (
        characteristics, timestamp, major, minor, dll_name_rva, ordinal_base,
        slot_count, name_count, eat_rva, names_rva, ordinals_rva,
    ) = struct.unpack("<IIHHIIIIIII", raw)
    dll_name_raw = parsed.pe.get_string_at_rva(dll_name_rva)
    try:
        dll_name = bytes(dll_name_raw).decode("ascii")
    except (TypeError, UnicodeDecodeError) as exc:
        raise ToolkitInputError("strict export DLL name is unavailable") from exc
    eat = parsed.pe.get_data(eat_rva, slot_count * 4)
    if len(eat) != slot_count * 4:
        raise ToolkitInputError("strict export address table became unavailable")
    target_rvas = [row[0] for row in struct.iter_unpack("<I", eat)]
    grouped: dict[tuple[int, int], list[Any]] = {}
    for exported in parsed.exports or ():
        grouped.setdefault((exported.ordinal, exported.rva), []).append(exported)
    name_table: list[dict[str, Any]] = []
    if name_count:
        name_words = parsed.pe.get_data(names_rva, name_count * 4)
        ordinal_words = parsed.pe.get_data(ordinals_rva, name_count * 2)
        if len(name_words) != name_count * 4 or len(ordinal_words) != name_count * 2:
            raise ToolkitInputError("strict export name table became unavailable")
        for index, ((name_rva,), (slot_index,)) in enumerate(zip(
            struct.iter_unpack("<I", name_words),
            struct.iter_unpack("<H", ordinal_words),
        )):
            encoded = parsed.pe.get_string_at_rva(name_rva)
            try:
                name = bytes(encoded).decode("ascii")
            except (TypeError, UnicodeDecodeError) as exc:
                raise ToolkitInputError("strict export name became unavailable") from exc
            name_table.append({
                "index": index,
                "name": name,
                "slot_index": slot_index,
                "ordinal": ordinal_base + slot_index,
            })
        names = [row["name"] for row in name_table]
        if names != sorted(names):
            raise ToolkitInputError("PE export name pointer table is not lexical")
    slots: list[dict[str, Any]] = []
    holes: list[dict[str, int]] = []
    for slot_index, target_rva in enumerate(target_rvas):
        ordinal = ordinal_base + slot_index
        if target_rva == 0:
            holes.append({"slot_index": slot_index, "ordinal": ordinal})
            slots.append({
                "slot_index": slot_index, "ordinal": ordinal, "rva": 0,
                "kind": "hole", "forwarder": None, "names": [],
            })
            continue
        exports = grouped.get((ordinal, target_rva), [])
        if not exports:
            raise ToolkitInputError("strict export inventory omitted a live EAT slot")
        kinds = {row.kind for row in exports}
        forwarders = {row.forwarder for row in exports}
        if len(kinds) != 1 or len(forwarders) != 1:
            raise ToolkitInputError("EAT aliases have conflicting classifications")
        names = sorted(row.name for row in exports if row.name is not None)
        slots.append({
            "slot_index": slot_index,
            "ordinal": ordinal,
            "rva": target_rva,
            "kind": next(iter(kinds)),
            "forwarder": next(iter(forwarders)),
            "names": names,
        })
    return {
        "dll_name": dll_name,
        "metadata": {
            "directory_rva": rva,
            "directory_size": size,
            "characteristics": characteristics,
            "timestamp": timestamp,
            "major_version": major,
            "minor_version": minor,
            "eat_rva": eat_rva,
            "name_pointer_table_rva": names_rva,
            "name_ordinal_table_rva": ordinals_rva,
        },
        "ordinal_base": ordinal_base,
        "slot_count": slot_count,
        "holes": holes,
        "slots": slots,
        "name_table": name_table,
    }


def _delay_import_surface_v2(
    parsed: Any, image_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Decode every PE32 delay descriptor and physical delay-IAT cell."""

    directory = parsed.pe.OPTIONAL_HEADER.DATA_DIRECTORY[13]
    directory_rva, directory_size = int(directory.VirtualAddress), int(directory.Size)
    if directory_rva == 0 and directory_size == 0:
        return [], []
    if directory_rva == 0 or directory_size < 32 or directory_size % 32:
        return [], [{"category": "delay_import_directory_malformed"}]
    raw = parsed.pe.get_data(directory_rva, directory_size)
    if len(raw) != directory_size:
        return [], [{"category": "delay_import_directory_not_fully_mapped"}]

    descriptors: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    terminated = False
    for descriptor_index, values in enumerate(struct.iter_unpack("<IIIIIIII", raw)):
        if not any(values):
            terminated = True
            if any(raw[(descriptor_index + 1) * 32 :]):
                blockers.append({
                    "category": "delay_import_data_after_terminator",
                    "descriptor_index": descriptor_index,
                })
            break
        (
            attributes, dll_pointer, module_handle_pointer, iat_pointer,
            int_pointer, bound_iat_pointer, unload_iat_pointer, timestamp,
        ) = values
        if attributes & ~1:
            blockers.append({
                "category": "delay_import_attributes_unsupported",
                "descriptor_index": descriptor_index,
                "attributes": attributes,
            })
            continue
        pointers_are_rvas = bool(attributes & 1)
        try:
            dll_rva = _delay_pointer_rva(parsed, dll_pointer, pointers_are_rvas)
            module_handle_rva = _delay_optional_pointer_rva(
                parsed, module_handle_pointer, pointers_are_rvas
            )
            iat_rva = _delay_pointer_rva(parsed, iat_pointer, pointers_are_rvas)
            int_rva = _delay_optional_pointer_rva(
                parsed, int_pointer, pointers_are_rvas
            ) or iat_rva
            bound_iat_rva = _delay_optional_pointer_rva(
                parsed, bound_iat_pointer, pointers_are_rvas
            )
            unload_iat_rva = _delay_optional_pointer_rva(
                parsed, unload_iat_pointer, pointers_are_rvas
            )
            dll_raw = parsed.pe.get_string_at_rva(dll_rva)
            dll = bytes(dll_raw).decode("ascii").lower()
            if not dll:
                raise ValueError("empty DLL name")
            cells: list[dict[str, Any]] = []
            for cell_index in range(parsed.size_of_image // 4):
                thunk_raw = parsed.pe.get_data(int_rva + cell_index * 4, 4)
                if len(thunk_raw) != 4:
                    raise ValueError("lookup table is not fully mapped")
                thunk = struct.unpack("<I", thunk_raw)[0]
                if thunk == 0:
                    break
                symbol: str | None
                ordinal: int | None
                hint: int | None
                if thunk & 0x80000000:
                    symbol, ordinal, hint = None, thunk & 0xFFFF, None
                else:
                    name_rva = _delay_pointer_rva(parsed, thunk, pointers_are_rvas)
                    hint_raw = parsed.pe.get_data(name_rva, 2)
                    if len(hint_raw) != 2:
                        raise ValueError("hint/name entry is not fully mapped")
                    hint = struct.unpack("<H", hint_raw)[0]
                    symbol_raw = parsed.pe.get_string_at_rva(name_rva + 2)
                    symbol = bytes(symbol_raw).decode("ascii")
                    if not symbol:
                        raise ValueError("empty import name")
                    ordinal = None
                cell_rva = iat_rva + cell_index * 4
                cells.append({
                    "slot_id": f"{image_id}:delay-iat:{cell_rva:08x}",
                    "descriptor_index": descriptor_index,
                    "cell_index": cell_index,
                    "iat_rva": cell_rva,
                    "dll": dll,
                    "symbol": symbol,
                    "ordinal": ordinal,
                    "hint": hint,
                })
            else:
                raise ValueError("lookup table is not null terminated")
        except (TypeError, UnicodeDecodeError, ValueError) as exc:
            blockers.append({
                "category": "delay_import_descriptor_malformed",
                "descriptor_index": descriptor_index,
                "detail": str(exc),
            })
            continue
        descriptors.append({
            "descriptor_index": descriptor_index,
            "attributes": attributes,
            "pointers_are_rvas": pointers_are_rvas,
            "dll": dll,
            "dll_name_rva": dll_rva,
            "module_handle_rva": module_handle_rva,
            "iat_rva": iat_rva,
            "int_rva": int_rva,
            "bound_iat_rva": bound_iat_rva,
            "unload_iat_rva": unload_iat_rva,
            "timestamp": timestamp,
            "cells": cells,
        })
    if not terminated:
        blockers.append({"category": "delay_import_directory_not_terminated"})
    return descriptors, blockers


def _delay_pointer_rva(parsed: Any, value: int, pointers_are_rvas: bool) -> int:
    rva = value if pointers_are_rvas else value - parsed.image_base
    if value == 0 or not 0 <= rva < parsed.size_of_image:
        raise ValueError("delay import pointer is outside the image")
    return rva


def _delay_optional_pointer_rva(
    parsed: Any, value: int, pointers_are_rvas: bool
) -> int | None:
    return None if value == 0 else _delay_pointer_rva(parsed, value, pointers_are_rvas)


def _load_config_surface_v2(parsed: Any) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    directory = parsed.pe.OPTIONAL_HEADER.DATA_DIRECTORY[10]
    rva, declared_size = int(directory.VirtualAddress), int(directory.Size)
    if rva == 0 and declared_size == 0:
        return None, []
    blockers: list[dict[str, Any]] = []
    if rva == 0 or declared_size < 4:
        return None, [{"category": "load_config_span_malformed"}]
    header = parsed.pe.get_data(rva, declared_size)
    if len(header) != declared_size:
        return None, [{"category": "load_config_not_fully_mapped"}]
    structure_size = struct.unpack_from("<I", header)[0]
    # Successive IMAGE_LOAD_CONFIG_DIRECTORY32 revisions end at these field
    # boundaries.  A size from the 64-bit layout must never be accepted here.
    known_sizes = {
        64, 72, 92, 104, 120, 124, 128, 132, 136, 144, 148, 152,
        156, 160, 164, 172, 176, 180, 184, 188, 192, 196,
    }
    if structure_size > declared_size or structure_size < 64:
        blockers.append({
            "category": "load_config_size_malformed",
            "structure_size": structure_size,
            "directory_size": declared_size,
        })
        return {
            "directory_rva": rva, "directory_size": declared_size,
            "structure_size": structure_size, "fields": {},
            "safe_seh": None, "cfg": None,
        }, blockers
    if structure_size not in known_sizes:
        blockers.append({
            "category": "load_config_version_unsupported",
            "structure_size": structure_size,
        })
    data = header[:structure_size]
    fields: dict[str, Any] = {
        "timestamp": struct.unpack_from("<I", data, 4)[0],
        "major_version": struct.unpack_from("<H", data, 8)[0],
        "minor_version": struct.unpack_from("<H", data, 10)[0],
        "global_flags_clear": struct.unpack_from("<I", data, 12)[0],
        "global_flags_set": struct.unpack_from("<I", data, 16)[0],
        "security_cookie_va": struct.unpack_from("<I", data, 60)[0],
    }
    safe_seh = None
    if structure_size >= 72:
        table_va, count = struct.unpack_from("<II", data, 64)
        entries, error = _rva_table_from_va(parsed, table_va, count, stride=4)
        if error is not None:
            blockers.append({"category": "safe_seh_table_unsupported", "detail": error})
        elif entries != sorted(set(entries)):
            blockers.append({"category": "safe_seh_table_not_sorted_unique"})
        elif any(not _rva_is_executable(parsed, entry) for entry in entries):
            blockers.append({"category": "safe_seh_handler_not_executable"})
        safe_seh = {"table_va": table_va, "count": count, "handler_rvas": entries}
    cfg = None
    if structure_size >= 92:
        check_va, dispatch_va, table_va, count, flags = struct.unpack_from("<IIIII", data, 72)
        stride = 4 + ((flags & 0xF0000000) >> 28)
        entries, error = _rva_table_from_va(parsed, table_va, count, stride=stride)
        if error is not None:
            blockers.append({"category": "cfg_table_unsupported", "detail": error})
        elif entries != sorted(set(entries)):
            blockers.append({"category": "cfg_table_not_sorted_unique"})
        cfg = {
            "check_function_pointer_va": check_va,
            "dispatch_function_pointer_va": dispatch_va,
            "function_table_va": table_va,
            "function_count": count,
            "guard_flags": flags,
            "entry_stride": stride,
            "function_rvas": entries,
        }
    pointer_fields: list[dict[str, Any]] = []
    for offset, minimum_size, name, pointer_kind in (
        (32, 36, "lock_prefix_table", "va_table"),
        (56, 60, "edit_list", "va"),
        (60, 64, "security_cookie", "va_data"),
        (72, 76, "guard_cf_check_function_pointer", "va_data"),
        (76, 80, "guard_cf_dispatch_function_pointer", "va_data"),
        (120, 124, "dynamic_value_reloc_table", "va_table"),
        (124, 128, "chpe_metadata_pointer", "va_metadata"),
        (128, 132, "guard_rf_failure_routine", "va_code"),
        (132, 136, "guard_rf_failure_routine_function_pointer", "va_data"),
        (144, 148, "guard_rf_verify_stack_pointer_function_pointer", "va_data"),
        (156, 160, "enclave_configuration_pointer", "va_metadata"),
        (160, 164, "volatile_metadata_pointer", "va_metadata"),
        (172, 176, "guard_xfg_check_function_pointer", "va_data"),
        (176, 180, "guard_xfg_dispatch_function_pointer", "va_data"),
        (180, 184, "guard_xfg_table_dispatch_function_pointer", "va_data"),
        (184, 188, "cast_guard_failure_mode", "va_data"),
        (188, 192, "guard_memcpy_function_pointer", "va_data"),
        (192, 196, "uma_function_pointers", "va_table"),
    ):
        if structure_size < minimum_size:
            continue
        value = struct.unpack_from("<I", data, offset)[0]
        locator = _typed_load_config_va(parsed, value)
        pointer_fields.append({
            "name": name,
            "field_offset": offset,
            "value_va": value,
            "pointer_kind": pointer_kind,
            "target": locator,
            "realization_policy": (
                "preserve_null" if value == 0
                else "regenerate_code_target" if pointer_kind == "va_code"
                else "relocate_typed_target"
            ),
        })
        if value and locator["kind"] == "external":
            blockers.append({
                "category": "load_config_pointer_outside_image",
                "field": name,
            })

    typed_tables: list[dict[str, Any]] = []
    for pointer_offset, count_offset, minimum_size, name in (
        (104, 108, 112, "guard_address_taken_iat_entries"),
        (112, 116, 120, "guard_long_jump_targets"),
        (164, 168, 172, "guard_eh_continuation_targets"),
    ):
        if structure_size < minimum_size:
            continue
        table_va, count = struct.unpack_from("<II", data, pointer_offset)
        entries, error = _rva_table_from_va(parsed, table_va, count, stride=4)
        if error is not None:
            blockers.append({
                "category": "load_config_typed_table_unsupported",
                "table": name,
                "detail": error,
            })
        elif entries != sorted(set(entries)):
            blockers.append({
                "category": "load_config_typed_table_not_sorted_unique",
                "table": name,
            })
        typed_tables.append({
            "name": name,
            "table_va": table_va,
            "count": count,
            "entry_stride": 4,
            "entries": entries,
        })
    return {
        "directory_rva": rva,
        "directory_size": declared_size,
        "structure_size": structure_size,
        "fields": fields,
        "safe_seh": safe_seh,
        "cfg": cfg,
        "pointer_fields": pointer_fields,
        "typed_tables": typed_tables,
    }, blockers


def _rva_table_from_va(parsed: Any, table_va: int, count: int, *, stride: int) -> tuple[list[int], str | None]:
    if table_va == 0 and count == 0:
        return [], None
    if table_va == 0 or count > parsed.size_of_image // max(stride, 1):
        return [], "table pointer/count is incoherent"
    if not parsed.image_base <= table_va < parsed.image_base + parsed.size_of_image:
        return [], "table VA is outside the image"
    table_rva = table_va - parsed.image_base
    raw = parsed.pe.get_data(table_rva, count * stride)
    if len(raw) != count * stride:
        return [], "table is not fully mapped"
    return [struct.unpack_from("<I", raw, index * stride)[0] for index in range(count)], None


def _typed_load_config_va(parsed: Any, value: int) -> dict[str, Any]:
    if value == 0:
        return {"kind": "null", "rva": None, "section_index": None}
    rva = value - parsed.image_base
    matches = [
        (index, section) for index, section in enumerate(parsed.sections)
        if section.rva_start <= rva < section.rva_end
    ]
    if len(matches) != 1:
        return {"kind": "external", "rva": None, "section_index": None}
    section_index, section = matches[0]
    return {
        "kind": "image_rva",
        "rva": rva,
        "section_index": section_index,
        "executable": section.executable,
    }


def _rva_is_executable(parsed: Any, rva: int) -> bool:
    return sum(
        section.executable
        and section.rva_start <= rva < section.rva_end
        for section in parsed.sections
    ) == 1


def _directory_surface_v2(parsed: Any, load_config: Mapping[str, Any] | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    policies = {
        0: "regenerate_export", 1: "rebuild_imports", 2: "preserve_resource",
        3: "unsupported_exception_directory", 4: "drop_security_overlay",
        5: "regenerate_relocations", 6: "unsupported_debug_directory",
        7: "unsupported_architecture_directory", 8: "unsupported_global_pointer",
        9: "regenerate_tls", 10: "regenerate_load_config",
        11: "clear_bound_import", 12: "rebuild_iat", 13: "rebuild_delay_imports",
        14: "unsupported_clr_runtime", 15: "unsupported_reserved_directory",
    }
    names = (
        "export", "import", "resource", "exception", "security", "base_relocation",
        "debug", "architecture", "global_pointer", "tls", "load_config",
        "bound_import", "iat", "delay_import", "clr_runtime", "reserved",
    )
    unsupported = {3, 6, 7, 8, 14, 15}
    rows: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for index, directory in enumerate(parsed.pe.OPTIONAL_HEADER.DATA_DIRECTORY[:16]):
        rva, size = int(directory.VirtualAddress), int(directory.Size)
        rows.append({
            "index": index, "name": names[index], "rva": rva, "size": size,
            "realization_policy": policies[index],
        })
        if (rva or size) and index in unsupported:
            blockers.append({
                "category": "pointer_bearing_directory_unsupported",
                "directory": names[index],
            })
    if any(row["name"] == "load_config" and (row["rva"] or row["size"]) for row in rows) and load_config is None:
        blockers.append({"category": "load_config_typed_codec_missing"})
    return rows, blockers


def write_pe32_project_load_plan(
    *,
    intent: Path,
    module_interfaces: Mapping[str, Path],
    native_ingress_plans: Mapping[str, Path] | None = None,
    edge_authorities: Mapping[str, Mapping[str, Any]] | None = None,
    out: Path,
) -> dict[str, Any]:
    """Resolve declared target edges and leave environment edges to the host."""

    raw_intent = _object(Path(intent), "project intent")
    project = _parse_project_intent(raw_intent)
    modules = {
        image_id: _module_interface(path, expected_image_id=image_id)
        for image_id, path in module_interfaces.items()
    }
    ingress_paths = {} if native_ingress_plans is None else dict(native_ingress_plans)
    ingress_plans = {
        image_id: _load_format(path, NATIVE_INGRESS_PLAN_FORMAT, f"{image_id} native ingress plan")
        for image_id, path in ingress_paths.items()
    }
    if ingress_plans and set(ingress_plans) != set(modules):
        raise ToolkitInputError("native ingress plan IDs differ from module-interface IDs")
    for image_id, ingress in ingress_plans.items():
        if (
            ingress.get("status") != "complete"
            or ingress.get("module", {}).get("image_id") != image_id
            or ingress.get("module", {}).get("module_interface_sha256")
            != sha256_file(module_interfaces[image_id])
        ):
            raise ToolkitInputError(f"native ingress plan {image_id!r} is stale or incomplete")
    edge_authority = {} if edge_authorities is None else dict(edge_authorities)
    declared_ids = {
        row["image_id"]
        for row in project["images"]
        if row["ownership"] == "target"
    }
    if set(modules) != declared_ids:
        raise ToolkitInputError(
            "module-interface IDs differ from target-owned project images: "
            f"missing={sorted(declared_ids - set(modules))!r}, "
            f"extra={sorted(set(modules) - declared_ids)!r}"
        )
    aliases: dict[str, str] = {}
    specifications = {row["image_id"]: row for row in project["images"]}
    blockers: list[dict[str, Any]] = []
    for row in project["images"]:
        for alias in (row["filename"], *row["aliases"]):
            normalized = alias.lower()
            prior = aliases.get(normalized)
            if prior is not None and prior != row["image_id"]:
                blockers.append({
                    "category": "module_alias_ambiguous",
                    "alias": normalized,
                    "images": sorted({prior, row["image_id"]}),
                })
            else:
                aliases[normalized] = row["image_id"]

    edges: list[dict[str, Any]] = []
    for importer_id in sorted(modules):
        interface = modules[importer_id]
        for slot in interface["imports"]:
            request = {
                "dll": str(slot["dll"]).lower(),
                "symbol": slot["symbol"],
                "ordinal": slot["ordinal"],
            }
            provider_id = aliases.get(request["dll"])
            if provider_id is None:
                resolution = {
                    "kind": "host_loader",
                    "requested_dll": request["dll"],
                }
            elif specifications[provider_id]["ownership"] == "runtime":
                resolution = {
                    "kind": "host_loader",
                    "requested_dll": request["dll"],
                    "declared_runtime_image_id": provider_id,
                }
            else:
                exported = _resolve_export(modules[provider_id], request)
                if exported is None:
                    blockers.append({
                        "category": "target_export_missing",
                        "slot_id": slot["slot_id"],
                        "provider_image_id": provider_id,
                        "request": request,
                    })
                    resolution = {"kind": "unresolved"}
                elif exported["kind"] == "forwarder":
                    resolution = {
                        "kind": "target_forwarder",
                        "provider_image_id": provider_id,
                        "export": exported,
                    }
                else:
                    compatibility = None
                    if ingress_plans:
                        authority = edge_authority.get(slot["slot_id"])
                        if authority is None:
                            blockers.append({
                                "category": "cross_image_edge_authority_missing",
                                "slot_id": slot["slot_id"],
                            })
                        elif exported["kind"] == "code":
                            providers = [
                                row for row in ingress_plans[provider_id].get("ingresses", [])
                                if row.get("role") == "export"
                                and any(
                                    alias.get("ordinal") == exported["ordinal"]
                                    and (
                                        request["symbol"] is None
                                        or alias.get("name") == request["symbol"]
                                    )
                                    for alias in row.get("exports", [])
                                )
                            ]
                            expected_fields = {
                                "slot_id", "kind", "importer_use",
                                "importer_physical_frame_id",
                            }
                            if (
                                set(authority) != expected_fields
                                or authority.get("kind") != "code"
                                or authority.get("importer_use") != "code"
                                or len(providers) != 1
                            ):
                                blockers.append({
                                    "category": (
                                        "cross_image_iat_use_ambiguous"
                                        if authority.get("importer_use") == "ambiguous"
                                        else "cross_image_code_authority_invalid"
                                    ),
                                    "slot_id": slot["slot_id"],
                                })
                            else:
                                provider_frame = providers[0]["physical_frame_id"]
                                importer_frame = authority["importer_physical_frame_id"]
                                compatibility = {
                                    "kind": "code",
                                    "importer_physical_frame_id": importer_frame,
                                    "provider_physical_frame_id": provider_frame,
                                    "compatible": importer_frame == provider_frame,
                                }
                                if not compatibility["compatible"]:
                                    blockers.append({"category": "cross_image_code_protocol_mismatch", "slot_id": slot["slot_id"]})
                        elif exported["kind"] == "data":
                            anchors = [
                                row for row in ingress_plans[provider_id].get("data_export_anchors", [])
                                if any(
                                    alias.get("ordinal") == exported["ordinal"]
                                    and (request["symbol"] is None or alias.get("name") == request["symbol"])
                                    for alias in row.get("aliases", [])
                                )
                            ]
                            expected_fields = {
                                "slot_id", "kind", "importer_use",
                                "required_permissions", "minimum_extent",
                            }
                            if (
                                set(authority) != expected_fields
                                or authority.get("kind") != "data"
                                or authority.get("importer_use") != "data"
                                or len(anchors) != 1
                            ):
                                blockers.append({
                                    "category": (
                                        "cross_image_iat_use_ambiguous"
                                        if authority.get("importer_use") == "ambiguous"
                                        else "cross_image_data_authority_invalid"
                                    ),
                                    "slot_id": slot["slot_id"],
                                })
                            else:
                                required = authority["required_permissions"]
                                minimum = authority["minimum_extent"]
                                anchor = anchors[0]
                                compatible = (
                                    isinstance(required, int) and not isinstance(required, bool) and required > 0
                                    and isinstance(minimum, int) and not isinstance(minimum, bool) and minimum > 0
                                    and anchor["object_permissions"] & required == required
                                    and anchor["available_extent"] >= minimum
                                )
                                compatibility = {
                                    "kind": "data", "required_permissions": required,
                                    "minimum_extent": minimum, "provider_anchor_id": anchor["id"],
                                    "compatible": compatible,
                                }
                                if not compatible:
                                    blockers.append({"category": "cross_image_data_protocol_mismatch", "slot_id": slot["slot_id"]})
                    resolution = {
                        "kind": "target_image",
                        "provider_image_id": provider_id,
                        "export": exported,
                        "compatibility": compatibility,
                    }
            edges.append({
                "slot_id": slot["slot_id"],
                "importer_image_id": importer_id,
                "iat_rva": slot["iat_rva"],
                "request": request,
                "resolution": resolution,
            })

    known_slots = {row["slot_id"] for row in edges}
    extra_edge_authorities = sorted(set(edge_authority) - known_slots)
    if extra_edge_authorities:
        blockers.append({
            "category": "cross_image_edge_authority_unreachable",
            "slot_ids": extra_edge_authorities,
        })

    payload = {
        "format": PE32_PROJECT_LOAD_PLAN_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "project_id": project["project_id"],
        "root_image_id": project["root_image_id"],
        "intent": {
            "path": Path(intent).name,
            "sha256": sha256_file(intent),
        },
        "images": [
            {
                **specifications[image_id],
                "interface_sha256": (
                    sha256_file(module_interfaces[image_id])
                    if image_id in module_interfaces else None
                ),
                "native_ingress_plan_sha256": (
                    sha256_file(ingress_paths[image_id])
                    if image_id in ingress_paths else None
                ),
                "pe_sha256": (
                    modules[image_id]["identity"]["pe_sha256"]
                    if image_id in modules else None
                ),
            }
            for image_id in sorted(specifications)
        ],
        "target_distribution_roots": project["target_distribution_roots"],
        "host_environment": project["host_environment"],
        "edges": edges,
        "blockers": blockers,
        "counts": {
            "images": len(specifications),
            "target_images": sum(
                row["ownership"] == "target" for row in project["images"]
            ),
            "import_slots": len(edges),
            "target_edges": sum(
                row["resolution"]["kind"].startswith("target_") for row in edges
            ),
            "host_edges": sum(
                row["resolution"]["kind"] == "host_loader" for row in edges
            ),
            "blockers": len(blockers),
        },
        "policy": {
            "host_loader_resolution": True,
            "duplicate_logical_import_slots": "preserved",
            "unknown_target_local_module": "fail_until_classified",
            "layout_compatibility": "not_promised",
        },
    }
    payload["plan_sha256"] = canonical_sha256_v3(payload)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "project-load-plan.json", payload)
    return payload


def write_pe32_project_completion(
    *,
    load_plan: Path,
    module_deployments: Mapping[str, Path],
    observed_load_graph: Path | None,
    out: Path,
) -> dict[str, Any]:
    plan = _load_closed_payload(
        load_plan, PE32_PROJECT_LOAD_PLAN_FORMAT, "project load plan", "plan_sha256"
    )
    declared = {row["image_id"]: row for row in plan["images"]}
    blockers = list(plan.get("blockers") or [])
    completion_rows: list[dict[str, Any]] = []
    deployments_by_image: dict[str, dict[str, Any]] = {}
    for image_id, specification in sorted(declared.items()):
        if specification["ownership"] != "target":
            completion_rows.append({
                "image_id": image_id,
                "ownership": "runtime",
                "implementation": specification["implementation"],
                "status": "qualified_environment_dependency",
            })
            continue
        path = module_deployments.get(image_id)
        if specification["implementation"] != "behavioral_c":
            blockers.append({
                "category": "target_image_not_lifted",
                "image_id": image_id,
            })
            completion_rows.append({
                "image_id": image_id,
                "ownership": "target",
                "implementation": specification["implementation"],
                "status": "incomplete",
            })
            continue
        if path is None:
            blockers.append({
                "category": "target_module_deployment_missing",
                "image_id": image_id,
            })
            status = "incomplete"
            digest = None
            candidate_sha256 = None
        else:
            deployment = _load_format(
                path, PE32_MODULE_DEPLOYMENT_FORMAT,
                f"{image_id} module deployment",
            )
            _validate_closed_payload(
                deployment, f"{image_id} module deployment", "deployment_sha256"
            )
            _validate_module_deployment(
                deployment, f"{image_id} module deployment"
            )
            if deployment.get("image_id") != image_id:
                raise ToolkitInputError(
                    f"module deployment {image_id!r} binds another image"
                )
            status = str(deployment.get("status"))
            digest = sha256_file(path)
            candidate = deployment.get("candidate")
            candidate_sha256 = (
                candidate.get("sha256") if isinstance(candidate, Mapping) else None
            )
            deployments_by_image[image_id] = deployment
            if status != "complete":
                blockers.append({
                    "category": "target_module_deployment_incomplete",
                    "image_id": image_id,
                    "observed": status,
                })
        completion_rows.append({
            "image_id": image_id,
            "ownership": "target",
            "implementation": "behavioral_c",
            "status": status,
            "deployment_sha256": digest,
            "candidate_sha256": candidate_sha256,
        })

    observed_binding: dict[str, Any] | None = None
    if observed_load_graph is None:
        blockers.append({"category": "observed_load_graph_missing"})
    else:
        observed = _load_format(
            observed_load_graph,
            PE32_OBSERVED_LOAD_GRAPH_FORMAT,
            "observed load graph",
        )
        _validate_closed_payload(
            observed, "observed load graph", "graph_sha256"
        )
        if observed.get("project_id") != plan.get("project_id"):
            blockers.append({"category": "observed_load_graph_project_mismatch"})
        if observed.get("environment_sha256") != plan["host_environment"]["sha256"]:
            blockers.append({"category": "observed_load_graph_environment_mismatch"})
        if observed.get("status") != "qualified":
            blockers.append({
                "category": "observed_load_graph_incomplete",
                "observed": observed.get("status"),
            })
        if observed.get("unknown_target_local_modules"):
            blockers.append({
                "category": "unknown_target_local_module",
                "modules": observed["unknown_target_local_modules"],
            })
        observed_modules = observed.get("modules")
        if not isinstance(observed_modules, list):
            blockers.append({"category": "observed_module_inventory_missing"})
        else:
            observed_target = {
                row.get("image_id"): row
                for row in observed_modules
                if isinstance(row, Mapping)
                and row.get("origin") == "target_distribution"
                and isinstance(row.get("image_id"), str)
            }
            for image_id, deployment in sorted(deployments_by_image.items()):
                observed_row = observed_target.get(image_id)
                expected_hash = deployment.get("candidate", {}).get("sha256")
                if observed_row is None:
                    blockers.append({
                        "category": "deployed_candidate_not_observed",
                        "image_id": image_id,
                    })
                elif observed_row.get("sha256") != expected_hash:
                    blockers.append({
                        "category": "observed_candidate_hash_mismatch",
                        "image_id": image_id,
                        "expected": expected_hash,
                        "observed": observed_row.get("sha256"),
                    })
        observed_slots = observed.get("slots")
        if not isinstance(observed_slots, list):
            blockers.append({"category": "observed_import_slots_missing"})
        else:
            by_slot = {
                row.get("slot_id"): row
                for row in observed_slots
                if isinstance(row, Mapping) and isinstance(row.get("slot_id"), str)
            }
            planned_ids = {row["slot_id"] for row in plan["edges"]}
            if set(by_slot) != planned_ids:
                blockers.append({
                    "category": "observed_import_slot_inventory_mismatch",
                    "missing": sorted(planned_ids - set(by_slot)),
                    "extra": sorted(set(by_slot) - planned_ids),
                })
            for edge in plan["edges"]:
                observed_slot = by_slot.get(edge["slot_id"])
                if observed_slot is None:
                    continue
                resolution = observed_slot.get("resolution")
                if not isinstance(resolution, Mapping):
                    blockers.append({
                        "category": "observed_import_resolution_missing",
                        "slot_id": edge["slot_id"],
                    })
                    continue
                planned_resolution = edge["resolution"]
                if planned_resolution["kind"] == "target_forwarder":
                    if (
                        resolution.get("kind") != "target_forwarder"
                        or resolution.get("forwarding_image_id")
                        != planned_resolution.get("provider_image_id")
                    ):
                        blockers.append({
                            "category": "target_forwarder_resolution_mismatch",
                            "slot_id": edge["slot_id"],
                            "expected": planned_resolution,
                            "observed": dict(resolution),
                        })
                elif planned_resolution["kind"].startswith("target_"):
                    if (
                        resolution.get("kind") != "target_image"
                        or resolution.get("provider_image_id")
                        != planned_resolution.get("provider_image_id")
                    ):
                        blockers.append({
                            "category": "target_import_resolution_mismatch",
                            "slot_id": edge["slot_id"],
                            "expected": planned_resolution,
                            "observed": dict(resolution),
                        })
                elif (
                    resolution.get("kind") != "host_loader"
                    or resolution.get("environment_sha256")
                    != plan["host_environment"]["sha256"]
                ):
                    blockers.append({
                        "category": "host_import_resolution_unqualified",
                        "slot_id": edge["slot_id"],
                        "observed": dict(resolution),
                    })
        observed_binding = {
            "path": Path(observed_load_graph).name,
            "sha256": sha256_file(observed_load_graph),
            "environment_sha256": observed.get("environment_sha256"),
        }

    payload = {
        "format": PE32_PROJECT_COMPLETION_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "project_id": plan["project_id"],
        "load_plan": {
            "path": Path(load_plan).name,
            "sha256": sha256_file(load_plan),
        },
        "observed_load_graph": observed_binding,
        "images": completion_rows,
        "blockers": blockers,
        "counts": {
            "images": len(declared),
            "complete_target_images": sum(
                row["ownership"] == "target" and row["status"] == "complete"
                for row in completion_rows
            ),
            "blockers": len(blockers),
        },
        "definition_of_complete": (
            "all target-owned candidate module deployments close and their exact "
            "hashes appear in a qualified candidate-observed load graph"
        ),
    }
    payload["completion_sha256"] = canonical_sha256_v3(payload)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "project-completion.json", payload)
    return payload


def write_pe32_observed_load_graph(
    *,
    load_plan: Path,
    observation: Path,
    out: Path,
) -> dict[str, Any]:
    """Check a loader-harness observation against one static load plan.

    The observation is deliberately a lower-authority input: it contains the
    runner and trace hashes plus what the harness saw.  This function checks
    its complete physical-slot inventory and module classifications before it
    can become the receipt consumed by project completion.
    """

    plan = _load_closed_payload(
        load_plan, PE32_PROJECT_LOAD_PLAN_FORMAT, "project load plan", "plan_sha256"
    )
    observed = _load_format(
        observation, PE32_LOAD_OBSERVATION_FORMAT, "PE32 load observation"
    )
    expected_observation_fields = {
        "format", "project_id", "environment_sha256", "runner_sha256",
        "trace_sha256", "process_exit_code", "modules", "slots",
    }
    if set(observed) != expected_observation_fields:
        raise ToolkitInputError("PE32 load observation has unsupported fields")
    _sha256(observed.get("environment_sha256"), "observation environment SHA-256")
    _sha256(observed.get("runner_sha256"), "observation runner SHA-256")
    _sha256(observed.get("trace_sha256"), "observation trace SHA-256")
    if observed.get("project_id") != plan.get("project_id"):
        raise ToolkitInputError("PE32 load observation belongs to another project")
    if isinstance(observed.get("process_exit_code"), bool) or not isinstance(
        observed.get("process_exit_code"), int
    ):
        raise ToolkitInputError("PE32 load observation exit code must be an integer")

    declared = {row["image_id"]: row for row in plan["images"]}
    raw_modules = observed.get("modules")
    if not isinstance(raw_modules, list):
        raise ToolkitInputError("PE32 load observation modules must be a list")
    modules: list[dict[str, Any]] = []
    target_modules: dict[str, dict[str, Any]] = {}
    unknown_local: list[str] = []
    for index, raw in enumerate(raw_modules):
        if not isinstance(raw, Mapping) or set(raw) != {
            "loader_name", "resolved_path", "sha256", "origin", "image_id"
        }:
            raise ToolkitInputError(f"observed module {index} has invalid fields")
        loader_name = _basename(raw.get("loader_name"), "observed module loader name")
        resolved_path = _text(raw.get("resolved_path"), "observed module path")
        digest = _sha256(raw.get("sha256"), "observed module SHA-256")
        origin = raw.get("origin")
        image_id = raw.get("image_id")
        if origin not in {"target_distribution", "host_environment"}:
            raise ToolkitInputError(f"observed module {index} has invalid origin")
        if image_id is not None and not isinstance(image_id, str):
            raise ToolkitInputError(f"observed module {index} image ID is invalid")
        if origin == "host_environment" and image_id is not None:
            raise ToolkitInputError("host modules cannot claim a project image ID")
        if origin == "target_distribution":
            if image_id is None:
                unknown_local.append(loader_name)
            elif image_id not in declared:
                unknown_local.append(loader_name)
            elif image_id in target_modules:
                raise ToolkitInputError(f"project image {image_id!r} was loaded twice")
            else:
                aliases = {
                    declared[image_id]["filename"], *declared[image_id]["aliases"]
                }
                if loader_name not in aliases:
                    raise ToolkitInputError(
                        f"observed module {loader_name!r} is not an alias of {image_id!r}"
                    )
                target_modules[image_id] = dict(raw)
        modules.append({
            "loader_name": loader_name,
            "resolved_path": resolved_path,
            "sha256": digest,
            "origin": origin,
            "image_id": image_id,
        })

    raw_slots = observed.get("slots")
    if not isinstance(raw_slots, list):
        raise ToolkitInputError("PE32 load observation slots must be a list")
    slot_rows: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_slots):
        if not isinstance(raw, Mapping) or set(raw) != {"slot_id", "resolution"}:
            raise ToolkitInputError(f"observed import slot {index} has invalid fields")
        slot_id = _text(raw.get("slot_id"), "observed import slot ID")
        if slot_id in slot_rows:
            raise ToolkitInputError(f"duplicate observed import slot {slot_id!r}")
        resolution = raw.get("resolution")
        if not isinstance(resolution, Mapping):
            raise ToolkitInputError(f"observed import slot {slot_id!r} has no resolution")
        kind = resolution.get("kind")
        if kind == "target_image":
            if set(resolution) != {"kind", "provider_image_id"}:
                raise ToolkitInputError(f"target resolution for {slot_id!r} is malformed")
            provider = _text(
                resolution.get("provider_image_id"), "target provider image ID"
            )
            if provider not in target_modules:
                raise ToolkitInputError(
                    f"target provider {provider!r} for {slot_id!r} was not observed loaded"
                )
            normalized_resolution = {
                "kind": "target_image", "provider_image_id": provider,
            }
        elif kind == "target_forwarder":
            fields = {
                "kind", "forwarding_image_id", "final_kind",
                "final_provider_image_id", "environment_sha256",
            }
            if set(resolution) != fields:
                raise ToolkitInputError(
                    f"forwarded resolution for {slot_id!r} is malformed"
                )
            forwarding = _text(
                resolution.get("forwarding_image_id"),
                "forwarding provider image ID",
            )
            if forwarding not in target_modules:
                raise ToolkitInputError(
                    f"forwarding provider {forwarding!r} was not observed loaded"
                )
            final_kind = resolution.get("final_kind")
            final_provider = resolution.get("final_provider_image_id")
            final_environment = resolution.get("environment_sha256")
            if final_kind == "target_image":
                final_provider = _text(
                    final_provider, "final forwarded provider image ID"
                )
                if final_provider not in target_modules or final_environment is not None:
                    raise ToolkitInputError(
                        f"final target provider for {slot_id!r} is invalid"
                    )
            elif final_kind == "host_loader":
                if final_provider is not None:
                    raise ToolkitInputError(
                        f"final host provider for {slot_id!r} claims a project image"
                    )
                final_environment = _sha256(
                    final_environment,
                    "final forwarded host environment SHA-256",
                )
            else:
                raise ToolkitInputError(
                    f"final forwarded provider for {slot_id!r} has invalid kind"
                )
            normalized_resolution = {
                "kind": "target_forwarder",
                "forwarding_image_id": forwarding,
                "final_kind": final_kind,
                "final_provider_image_id": final_provider,
                "environment_sha256": final_environment,
            }
        elif kind == "host_loader":
            if set(resolution) != {"kind", "environment_sha256"}:
                raise ToolkitInputError(f"host resolution for {slot_id!r} is malformed")
            normalized_resolution = {
                "kind": "host_loader",
                "environment_sha256": _sha256(
                    resolution.get("environment_sha256"),
                    "host resolution environment SHA-256",
                ),
            }
        else:
            raise ToolkitInputError(f"observed import slot {slot_id!r} has invalid kind")
        slot_rows[slot_id] = {
            "slot_id": slot_id, "resolution": normalized_resolution,
        }

    blockers: list[dict[str, Any]] = []
    if plan.get("status") != "complete":
        blockers.append({"category": "project_load_plan_incomplete"})
    if observed["environment_sha256"] != plan["host_environment"]["sha256"]:
        blockers.append({"category": "host_environment_mismatch"})
    if observed["process_exit_code"] != 0:
        blockers.append({
            "category": "validation_process_failed",
            "exit_code": observed["process_exit_code"],
        })
    if unknown_local:
        blockers.append({
            "category": "unknown_target_local_module",
            "modules": sorted(set(unknown_local)),
        })
    planned_by_slot = {row["slot_id"]: row for row in plan["edges"]}
    if set(slot_rows) != set(planned_by_slot):
        blockers.append({
            "category": "observed_import_slot_inventory_mismatch",
            "missing": sorted(set(planned_by_slot) - set(slot_rows)),
            "extra": sorted(set(slot_rows) - set(planned_by_slot)),
        })
    for slot_id in sorted(set(slot_rows) & set(planned_by_slot)):
        planned_resolution = planned_by_slot[slot_id]["resolution"]
        actual_resolution = slot_rows[slot_id]["resolution"]
        if planned_resolution["kind"] == "target_forwarder":
            matches = (
                actual_resolution["kind"] == "target_forwarder"
                and actual_resolution.get("forwarding_image_id")
                == planned_resolution.get("provider_image_id")
                and (
                    actual_resolution.get("final_kind") == "target_image"
                    or actual_resolution.get("environment_sha256")
                    == plan["host_environment"]["sha256"]
                )
            )
        elif planned_resolution["kind"].startswith("target_"):
            matches = (
                actual_resolution["kind"] == "target_image"
                and actual_resolution.get("provider_image_id")
                == planned_resolution.get("provider_image_id")
            )
        else:
            matches = (
                planned_resolution["kind"] == "host_loader"
                and actual_resolution["kind"] == "host_loader"
                and actual_resolution.get("environment_sha256")
                == plan["host_environment"]["sha256"]
            )
        if not matches:
            blockers.append({
                "category": "observed_import_resolution_mismatch",
                "slot_id": slot_id,
                "expected": planned_resolution,
                "observed": actual_resolution,
            })

    payload = {
        "format": PE32_OBSERVED_LOAD_GRAPH_FORMAT,
        "status": "qualified" if not blockers else "incomplete",
        "project_id": plan["project_id"],
        "environment_sha256": observed["environment_sha256"],
        "evidence": {
            "observation_sha256": sha256_file(observation),
            "runner_sha256": observed["runner_sha256"],
            "trace_sha256": observed["trace_sha256"],
            "process_exit_code": observed["process_exit_code"],
        },
        "modules": modules,
        "slots": [slot_rows[key] for key in sorted(slot_rows)],
        "unknown_target_local_modules": sorted(set(unknown_local)),
        "blockers": blockers,
        "policy": {
            "host_resolution_bound_to_environment": True,
            "target_local_modules_require_declaration": True,
            "physical_import_slots_preserved": True,
            "forwarder_final_provider_observed": True,
        },
    }
    payload["graph_sha256"] = canonical_sha256_v3(payload)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "observed-load-graph.json", payload)
    return payload


def _parse_project_intent(raw: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "format", "project_id", "root_image_id", "images",
        "target_distribution_roots", "host_environment",
    }
    if set(raw) != expected or raw.get("format") != PE32_PROJECT_INTENT_FORMAT:
        raise ToolkitInputError("project intent has unsupported format or fields")
    project_id = _text(raw.get("project_id"), "project ID")
    root = _text(raw.get("root_image_id"), "root image ID")
    images_raw = raw.get("images")
    if not isinstance(images_raw, list) or not images_raw:
        raise ToolkitInputError("project intent images must be a nonempty list")
    images: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(images_raw):
        if not isinstance(value, Mapping) or set(value) != {
            "image_id", "filename", "aliases", "ownership", "implementation"
        }:
            raise ToolkitInputError(f"project image {index} has invalid fields")
        image_id = _text(value.get("image_id"), f"project image {index} ID")
        if image_id in seen:
            raise ToolkitInputError(f"duplicate project image ID {image_id!r}")
        seen.add(image_id)
        filename = _basename(value.get("filename"), f"project image {index} filename")
        raw_aliases = value.get("aliases")
        if not isinstance(raw_aliases, list):
            raise ToolkitInputError(f"project image {index} aliases must be a list")
        aliases = sorted({_basename(item, "module alias") for item in raw_aliases})
        ownership = value.get("ownership")
        implementation = value.get("implementation")
        if ownership not in _OWNERSHIP or implementation not in _IMPLEMENTATIONS:
            raise ToolkitInputError(f"project image {index} policy is invalid")
        if ownership == "runtime" and implementation != "native_host":
            raise ToolkitInputError("runtime-owned images must use native_host")
        images.append({
            "image_id": image_id,
            "filename": filename,
            "aliases": aliases,
            "ownership": ownership,
            "implementation": implementation,
        })
    if root not in seen:
        raise ToolkitInputError("project root image is not declared")
    roots = raw.get("target_distribution_roots")
    if not isinstance(roots, list) or any(not isinstance(item, str) for item in roots):
        raise ToolkitInputError("target distribution roots must be strings")
    environment = raw.get("host_environment")
    if not isinstance(environment, Mapping) or set(environment) != {"id", "sha256"}:
        raise ToolkitInputError("host environment binding is malformed")
    return {
        "format": PE32_PROJECT_INTENT_FORMAT,
        "project_id": project_id,
        "root_image_id": root,
        "images": images,
        "target_distribution_roots": list(roots),
        "host_environment": {
            "id": _text(environment.get("id"), "host environment ID"),
            "sha256": _sha256(environment.get("sha256"), "host environment SHA-256"),
        },
    }


def _resolve_export(interface: Mapping[str, Any], request: Mapping[str, Any]) -> Mapping[str, Any] | None:
    export_directory = interface.get("export_directory")
    if not isinstance(export_directory, Mapping) or not isinstance(export_directory.get("slots"), list):
        raise ToolkitInputError("module interface has no exact EAT geometry")
    matches = []
    for row in export_directory["slots"]:
        if not isinstance(row, Mapping) or row.get("kind") == "hole":
            continue
        if request["symbol"] is not None and request["symbol"] in row.get("names", []):
            matches.append(row)
        elif request["ordinal"] is not None and row.get("ordinal") == request["ordinal"]:
            matches.append(row)
    if len(matches) > 1:
        raise ToolkitInputError("module export identity is ambiguous")
    return matches[0] if matches else None


def _module_interface(path: Path, *, expected_image_id: str) -> dict[str, Any]:
    payload = _load_format(path, PE32_MODULE_INTERFACE_FORMAT, "module interface")
    declared_hash = payload.get("interface_sha256")
    core = {key: value for key, value in payload.items() if key != "interface_sha256"}
    if declared_hash != canonical_sha256_v3(core):
        raise ToolkitInputError("module interface self hash is stale")
    if payload.get("status") != "complete" or payload.get("image_id") != expected_image_id:
        raise ToolkitInputError("module interface identity or status is invalid")
    return payload


def _load_format(path: Path, expected: str, label: str) -> dict[str, Any]:
    payload = _object(Path(path), label)
    if payload.get("format") != expected:
        raise ToolkitInputError(f"{label} has unsupported format")
    return dict(payload)


def _load_closed_payload(
    path: Path, expected: str, label: str, digest_field: str
) -> dict[str, Any]:
    payload = _load_format(path, expected, label)
    _validate_closed_payload(payload, label, digest_field)
    return payload


def _validate_closed_payload(
    payload: Mapping[str, Any], label: str, digest_field: str
) -> None:
    observed = payload.get(digest_field)
    core = {key: value for key, value in payload.items() if key != digest_field}
    if observed != canonical_sha256_v3(core):
        raise ToolkitInputError(f"{label} self hash is stale")


def _validate_module_deployment(
    payload: Mapping[str, Any], label: str
) -> None:
    expected_fields = {
        "format", "status", "image_id", "module_kind", "candidate",
        "bindings", "original_identity", "decoded_loader_surface",
        "blockers", "definition_of_complete", "deployment_sha256",
    }
    if set(payload) != expected_fields:
        raise ToolkitInputError(f"{label} has an incomplete deployment surface")
    if payload.get("status") not in {"complete", "incomplete"}:
        raise ToolkitInputError(f"{label} status is invalid")
    if payload.get("module_kind") not in {"exe", "dll"}:
        raise ToolkitInputError(f"{label} module kind is invalid")
    candidate = payload.get("candidate")
    if not isinstance(candidate, Mapping) or set(candidate) != {
        "filename", "sha256", "decoded_loader_surface_sha256"
    }:
        raise ToolkitInputError(f"{label} candidate binding is malformed")
    _basename(candidate.get("filename"), f"{label} candidate filename")
    _sha256(candidate.get("sha256"), f"{label} candidate SHA-256")
    _sha256(
        candidate.get("decoded_loader_surface_sha256"),
        f"{label} decoded loader surface SHA-256",
    )
    bindings = payload.get("bindings")
    required_bindings = {
        "original_interface", "behavioral_c_completion", "ingress_plan",
        "link_receipt", "exact_runtime_qualification", "loader_surface",
        "static_assurance", "candidate_interface",
    }
    if not isinstance(bindings, Mapping) or set(bindings) != required_bindings:
        raise ToolkitInputError(f"{label} dependency bindings are incomplete")
    for identity, binding in bindings.items():
        if not isinstance(binding, Mapping) or set(binding) != {"filename", "sha256"}:
            raise ToolkitInputError(
                f"{label} dependency binding {identity!r} is malformed"
            )
        _text(binding.get("filename"), f"{label} dependency filename")
        _sha256(binding.get("sha256"), f"{label} dependency SHA-256")
    if not isinstance(payload.get("original_identity"), Mapping):
        raise ToolkitInputError(f"{label} original identity is malformed")
    surface = payload.get("decoded_loader_surface")
    if not isinstance(surface, Mapping) or set(surface) != {
        "kind", "loader", "export_directory", "tls", "imports", "load_config"
    }:
        raise ToolkitInputError(f"{label} decoded loader surface is malformed")
    blockers = payload.get("blockers")
    if not isinstance(blockers, list) or (
        payload.get("status") == "complete" and blockers
    ):
        raise ToolkitInputError(f"{label} blocker inventory contradicts status")
    _text(
        payload.get("definition_of_complete"),
        f"{label} definition of complete",
    )


def _object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{label} must be an object")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolkitInputError(f"{label} must be a nonempty string")
    return value


def _basename(value: Any, label: str) -> str:
    text = _text(value, label).lower()
    if "/" in text or "\\" in text or text in {".", ".."}:
        raise ToolkitInputError(f"{label} must be a loader basename")
    return text


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ToolkitInputError(f"{label} must be lowercase SHA-256")
    return value


__all__ = [
    "write_pe32_module_interface",
    "write_pe32_observed_load_graph",
    "write_pe32_project_load_plan",
    "write_pe32_project_completion",
]
