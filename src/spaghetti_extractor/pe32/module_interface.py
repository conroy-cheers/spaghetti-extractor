"""Strict codec for the complete PE32 module-interface-v2 contract."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..roundtrip_fuzz.image_model import (
    ImportDescriptor,
    RelocationBlock,
    RuntimePEHeaders,
    TLSInitialization,
)
from .formats import PE32_MODULE_INTERFACE_FORMAT
from .resources import validate_resource_surface_v1


_FIELDS = {
    "format",
    "status",
    "image_id",
    "kind",
    "identity",
    "loader",
    "imports",
    "import_descriptors",
    "delay_imports",
    "export_directory",
    "tls",
    "runtime_headers",
    "sections",
    "resources",
    "base_relocations",
    "load_config",
    "directories",
    "blockers",
    "counts",
    "policy",
    "interface_sha256",
}
_EXPORT_KINDS = frozenset({"hole", "code", "data", "forwarder"})
_DIRECTORY_NAMES = (
    "export", "import", "resource", "exception", "security",
    "base_relocation", "debug", "architecture", "global_pointer", "tls",
    "load_config", "bound_import", "iat", "delay_import", "clr_runtime",
    "reserved",
)
_DIRECTORY_CODECS = (
    "pe32-export-directory-v2", "pe32-import-directory-v1",
    "pe32-resource-directory-v1", "unsupported-fail-closed",
    "pe32-security-overlay-v1", "pe32-base-relocation-directory-v1",
    "unsupported-fail-closed", "unsupported-fail-closed",
    "unsupported-fail-closed", "pe32-tls-directory-v1",
    "pe32-load-config-directory-v2", "pe32-bound-import-directory-v1",
    "pe32-iat-directory-v1", "pe32-delay-import-directory-v2",
    "unsupported-fail-closed", "unsupported-fail-closed",
)
_DIRECTORY_POLICIES = (
    "regenerate_export", "rebuild_imports", "preserve_resource",
    "unsupported_exception_directory", "drop_security_overlay",
    "regenerate_relocations", "unsupported_debug_directory",
    "unsupported_architecture_directory", "unsupported_global_pointer",
    "regenerate_tls", "regenerate_load_config", "clear_bound_import",
    "rebuild_iat", "rebuild_delay_imports", "unsupported_clr_runtime",
    "unsupported_reserved_directory",
)
_POINTER_BEARING_DIRECTORIES = frozenset(
    {0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
)
_LOAD_CONFIG_POINTER_FIELDS = (
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
)
_LOAD_CONFIG_TYPED_TABLES = (
    (104, 108, 112, "guard_address_taken_iat_entries"),
    (112, 116, 120, "guard_long_jump_targets"),
    (164, 168, 172, "guard_eh_continuation_targets"),
)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    return value


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ToolkitInputError(f"{context} must be an array")
    return value


def _integer(value: object, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ToolkitInputError(f"{context} must be an integer >= {minimum}")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolkitInputError(f"{context} must be nonempty text")
    return value


def _optional_integer(value: object, context: str) -> int | None:
    return None if value is None else _integer(value, context)


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    if set(value) != expected:
        raise ToolkitInputError(f"{context} fields are incomplete")


def _sha256(value: object, context: str) -> str:
    text = _text(value, context)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ToolkitInputError(f"{context} must be lowercase SHA-256")
    return text


def _validate_eat(value: object) -> None:
    eat = _mapping(value, "module export directory")
    slots = _list(eat.get("slots"), "module EAT slots")
    count = _integer(eat.get("slot_count"), "module EAT slot count")
    base = _integer(eat.get("ordinal_base"), "module EAT ordinal base")
    if len(slots) != count:
        raise ToolkitInputError("module EAT slot count disagrees with its inventory")
    holes: list[dict[str, int]] = []
    names_by_slot: dict[int, list[str]] = {}
    all_names: set[str] = set()
    for index, raw in enumerate(slots):
        row = _mapping(raw, f"module EAT slot {index}")
        if row.get("slot_index") != index or row.get("ordinal") != base + index:
            raise ToolkitInputError("module EAT slot identity is not contiguous")
        kind = row.get("kind")
        if kind not in _EXPORT_KINDS:
            raise ToolkitInputError("module EAT slot classification is unsupported")
        rva = _integer(row.get("rva"), f"module EAT slot {index} RVA")
        names = _list(row.get("names"), f"module EAT slot {index} names")
        if names != sorted(names) or any(
            not isinstance(name, str) or not name or name in all_names
            for name in names
        ):
            raise ToolkitInputError("module EAT aliases are duplicate or noncanonical")
        all_names.update(names)
        names_by_slot[index] = names
        forwarder = row.get("forwarder")
        if kind == "hole":
            if rva != 0 or forwarder is not None or names:
                raise ToolkitInputError("module EAT hole carries a live target")
            holes.append({"slot_index": index, "ordinal": base + index})
        elif kind == "forwarder":
            _text(forwarder, f"module EAT slot {index} forwarder")
            if rva == 0:
                raise ToolkitInputError("module EAT forwarder has no target RVA")
        elif rva == 0 or forwarder is not None:
            raise ToolkitInputError("module EAT code/data target is malformed")
    if eat.get("holes") != holes:
        raise ToolkitInputError("module EAT hole inventory is stale")
    table = _list(eat.get("name_table"), "module EAT lexical name table")
    lexical: list[str] = []
    for index, raw in enumerate(table):
        row = _mapping(raw, f"module EAT name {index}")
        if row.get("index") != index:
            raise ToolkitInputError("module EAT name indexes are not contiguous")
        name = _text(row.get("name"), f"module EAT name {index}")
        slot = _integer(row.get("slot_index"), f"module EAT name {index} slot")
        if slot >= count or name not in names_by_slot[slot]:
            raise ToolkitInputError("module EAT name table disagrees with its slot")
        if row.get("ordinal") != base + slot:
            raise ToolkitInputError("module EAT name ordinal is stale")
        lexical.append(name)
    if lexical != sorted(lexical) or set(lexical) != all_names:
        raise ToolkitInputError("module EAT lexical name table is incomplete")


def _validate_imports(payload: Mapping[str, Any]) -> None:
    slots = _list(payload.get("imports"), "module imports")
    identities: set[tuple[int, int, int]] = set()
    iat_rvas: set[int] = set()
    for index, raw in enumerate(slots):
        row = _mapping(raw, f"module import {index}")
        _exact_fields(row, {
            "slot_id", "image_id", "descriptor_index", "cell_index",
            "iat_rva", "iat_va", "dll", "symbol", "ordinal",
        }, f"module import {index}")
        descriptor = _integer(
            row.get("descriptor_index"), f"module import {index} descriptor"
        )
        cell = _integer(row.get("cell_index"), f"module import {index} cell")
        iat_rva = _integer(row.get("iat_rva"), f"module import {index} IAT RVA")
        dll = _text(row.get("dll"), f"module import {index} DLL")
        if dll != dll.lower():
            raise ToolkitInputError("module import DLL identity is not canonical")
        has_symbol = isinstance(row.get("symbol"), str) and bool(row.get("symbol"))
        has_ordinal = (
            isinstance(row.get("ordinal"), int)
            and not isinstance(row.get("ordinal"), bool)
            and row.get("ordinal") >= 0
        )
        if has_symbol == has_ordinal:
            raise ToolkitInputError("module import lacks one exact symbol or ordinal")
        identity = (descriptor, cell, iat_rva)
        if identity in identities or iat_rva in iat_rvas:
            raise ToolkitInputError("module import slot identity is duplicated")
        identities.add(identity)
        iat_rvas.add(iat_rva)
        if row.get("image_id") != payload.get("image_id"):
            raise ToolkitInputError("module import image identity is stale")
        if row.get("slot_id") != (
            f"{payload['image_id']}:iat:{iat_rva:08x}"
        ):
            raise ToolkitInputError("module import stable slot identity is stale")
        preferred_base = _mapping(
            payload.get("loader"), "module loader contract"
        ).get("preferred_base")
        if row.get("iat_va") != preferred_base + iat_rva:
            raise ToolkitInputError("module import IAT VA is stale")
    descriptors = _list(
        payload.get("import_descriptors"), "module import descriptors"
    )
    parsed_descriptors = []
    for index, raw in enumerate(descriptors):
        descriptor = ImportDescriptor.parse(
            _mapping(raw, f"module import descriptor {index}"),
            context=f"module import descriptor {index}",
        )
        if descriptor.index != index or descriptor.dll != descriptor.dll.lower():
            raise ToolkitInputError(
                "module import descriptor identities are not canonical"
            )
        parsed_descriptors.append(descriptor)
    expected_slots = sorted(
        (
            descriptor.index,
            cell.index,
            descriptor.dll,
            cell.symbol,
            cell.ordinal,
            cell.iat_rva,
        )
        for descriptor in parsed_descriptors
        for cell in descriptor.cells
    )
    observed_slots = sorted(
        (
            row["descriptor_index"], row["cell_index"], row["dll"],
            row["symbol"], row["ordinal"], row["iat_rva"],
        )
        for row in slots
    )
    if expected_slots != observed_slots:
        raise ToolkitInputError(
            "module import slots disagree with descriptor geometry"
        )


def _validate_delay_imports(payload: Mapping[str, Any]) -> None:
    descriptors = _list(payload.get("delay_imports"), "module delay imports")
    iat_rvas: set[int] = set()
    for index, raw in enumerate(descriptors):
        row = _mapping(raw, f"module delay import descriptor {index}")
        _exact_fields(row, {
            "descriptor_index", "attributes", "pointers_are_rvas", "dll",
            "dll_name_rva", "module_handle_rva", "iat_rva", "int_rva",
            "bound_iat_rva", "unload_iat_rva", "timestamp", "cells",
        }, f"module delay import descriptor {index}")
        if row.get("descriptor_index") != index:
            raise ToolkitInputError(
                "module delay-import descriptors are not contiguous"
            )
        _integer(row.get("attributes"), f"module delay import {index} attributes")
        if not isinstance(row.get("pointers_are_rvas"), bool):
            raise ToolkitInputError("module delay-import pointer mode is malformed")
        dll = _text(row.get("dll"), f"module delay import {index} DLL")
        if dll != dll.lower():
            raise ToolkitInputError("module delay-import DLL is not canonical")
        for field in (
            "dll_name_rva", "iat_rva", "int_rva", "timestamp"
        ):
            _integer(row.get(field), f"module delay import {index} {field}")
        for field in (
            "module_handle_rva", "bound_iat_rva", "unload_iat_rva"
        ):
            _optional_integer(
                row.get(field), f"module delay import {index} {field}"
            )
        cells = _list(row.get("cells"), f"module delay import {index} cells")
        for cell_index, raw_cell in enumerate(cells):
            cell = _mapping(
                raw_cell, f"module delay import {index} cell {cell_index}"
            )
            _exact_fields(cell, {
                "slot_id", "descriptor_index", "cell_index", "iat_rva",
                "dll", "symbol", "ordinal", "hint",
            }, f"module delay import {index} cell {cell_index}")
            iat_rva = _integer(
                cell.get("iat_rva"),
                f"module delay import {index} cell {cell_index} IAT RVA",
            )
            if (
                cell.get("descriptor_index") != index
                or cell.get("cell_index") != cell_index
                or cell.get("dll") != dll
                or cell.get("slot_id")
                != f"{payload['image_id']}:delay-iat:{iat_rva:08x}"
                or iat_rva != row["iat_rva"] + cell_index * 4
                or iat_rva in iat_rvas
            ):
                raise ToolkitInputError(
                    "module delay-import slot identity is stale or duplicated"
                )
            iat_rvas.add(iat_rva)
            symbol = cell.get("symbol")
            ordinal = cell.get("ordinal")
            if (isinstance(symbol, str) and bool(symbol)) == (
                isinstance(ordinal, int) and not isinstance(ordinal, bool)
            ):
                raise ToolkitInputError(
                    "module delay import lacks one exact symbol or ordinal"
                )
            _optional_integer(cell.get("hint"), "module delay-import hint")


def _validate_loader(payload: Mapping[str, Any]) -> None:
    loader = _mapping(payload.get("loader"), "module loader contract")
    _exact_fields(loader, {
        "preferred_base", "image_size", "entry_rva", "entry_kind",
        "subsystem", "coff_characteristics", "dll_characteristics", "stack",
    }, "module loader contract")
    kind = payload.get("kind")
    if kind not in {"dll", "executable"}:
        raise ToolkitInputError("module kind is unsupported")
    entry_rva = _integer(loader.get("entry_rva"), "module entry RVA")
    entry_kind = loader.get("entry_kind")
    expected_entry = None if entry_rva == 0 else (
        "dll_entry" if kind == "dll" else "process_entry"
    )
    if entry_kind != expected_entry:
        raise ToolkitInputError("module entry kind disagrees with its PE role")
    _integer(loader.get("preferred_base"), "module preferred base")
    _integer(loader.get("image_size"), "module image size", minimum=1)
    _integer(loader.get("dll_characteristics"), "module DLL characteristics")
    _integer(loader.get("coff_characteristics"), "module COFF characteristics")
    _text(loader.get("subsystem"), "module subsystem")
    stack = _mapping(loader.get("stack"), "module stack geometry")
    _exact_fields(stack, {"reserve", "commit"}, "module stack geometry")
    reserve = _integer(stack.get("reserve"), "module stack reserve")
    commit = _integer(stack.get("commit"), "module stack commit")
    if commit > reserve:
        raise ToolkitInputError("module stack commit exceeds its reserve")


def _validate_sections(payload: Mapping[str, Any]) -> None:
    sections = _list(payload.get("sections"), "module sections")
    spans: list[tuple[int, int]] = []
    for index, raw in enumerate(sections):
        row = _mapping(raw, f"module section {index}")
        _exact_fields(row, {
            "index", "name", "rva", "mapped_size", "raw_size",
            "characteristics", "executable", "permissions",
            "default_object_origin",
        }, f"module section {index}")
        if row.get("index") != index:
            raise ToolkitInputError("module section indexes are not contiguous")
        start = _integer(row.get("rva"), f"module section {index} RVA")
        size = _integer(
            row.get("mapped_size"), f"module section {index} mapped size"
        )
        end = start + size
        if any(start < previous_end and previous_start < end for previous_start, previous_end in spans):
            raise ToolkitInputError("module section geometry overlaps")
        spans.append((start, end))
        executable = row.get("executable")
        if not isinstance(executable, bool):
            raise ToolkitInputError("module section executable bit is malformed")
        permissions = _mapping(
            row.get("permissions"), f"module section {index} permissions"
        )
        _exact_fields(
            permissions, {"read", "write", "execute"},
            f"module section {index} permissions",
        )
        if any(not isinstance(value, bool) for value in permissions.values()):
            raise ToolkitInputError("module section permissions are malformed")
        if permissions["execute"] != executable:
            raise ToolkitInputError("module section execution flags disagree")
        origin = row.get("default_object_origin")
        if executable is True and origin is not None:
            raise ToolkitInputError("executable section has a data-object origin")
        if executable is False:
            _text(origin, f"module section {index} object origin")


def _validate_runtime_headers(payload: Mapping[str, Any]) -> None:
    headers = RuntimePEHeaders.parse(
        _mapping(payload.get("runtime_headers"), "module runtime PE headers")
    )
    if headers.rva != 0:
        raise ToolkitInputError("module runtime PE headers must begin at RVA zero")
    if hashlib.sha256(headers.data).hexdigest() != headers.data_sha256:
        raise ToolkitInputError("module runtime PE-header hash is stale")
    if len(headers.data) > int(payload["loader"]["image_size"]):
        raise ToolkitInputError("module runtime PE headers exceed the image")


def _validate_directories(payload: Mapping[str, Any]) -> None:
    directories = _list(payload.get("directories"), "module directories")
    if len(directories) != 16:
        raise ToolkitInputError("PE32 module interface requires 16 directories")
    for index, raw in enumerate(directories):
        row = _mapping(raw, f"module directory {index}")
        _exact_fields(row, {
            "index", "name", "rva", "size", "pointer_bearing", "codec",
            "realization_policy",
        }, f"module directory {index}")
        if row.get("index") != index:
            raise ToolkitInputError("module directory indexes are not canonical")
        if row.get("name") != _DIRECTORY_NAMES[index]:
            raise ToolkitInputError("module directory name is not canonical")
        rva = _integer(row.get("rva"), f"module directory {index} RVA")
        size = _integer(row.get("size"), f"module directory {index} size")
        if (rva == 0) != (size == 0):
            raise ToolkitInputError("module directory span is incoherent")
        if not isinstance(row.get("pointer_bearing"), bool):
            raise ToolkitInputError(
                f"module directory {index} pointer classification is malformed"
            )
        if row["pointer_bearing"] != (index in _POINTER_BEARING_DIRECTORIES):
            raise ToolkitInputError("module directory pointer classification is stale")
        if row.get("codec") != _DIRECTORY_CODECS[index]:
            raise ToolkitInputError("module directory codec is not canonical")
        if row.get("realization_policy") != _DIRECTORY_POLICIES[index]:
            raise ToolkitInputError("module directory realization policy is stale")


def _validate_tls(payload: Mapping[str, Any]) -> None:
    raw = payload.get("tls")
    directory = _list(payload.get("directories"), "module directories")[9]
    if raw is None:
        if directory["rva"] or directory["size"]:
            raise ToolkitInputError("module TLS directory lacks typed geometry")
        return
    tls = _mapping(raw, "module TLS initialization")
    parsed = TLSInitialization.parse(tls)
    if hashlib.sha256(parsed.template_data).hexdigest() != parsed.template_sha256:
        raise ToolkitInputError("module TLS template hash is stale")
    if (
        parsed.directory_rva != directory["rva"]
        or parsed.directory_size != directory["size"]
        or [callback.order for callback in parsed.callbacks]
        != list(range(len(parsed.callbacks)))
    ):
        raise ToolkitInputError("module TLS directory or callback order is stale")


def _validate_base_relocations(payload: Mapping[str, Any]) -> None:
    rows = _list(
        payload.get("base_relocations"), "module base-relocation blocks"
    )
    directory = _list(payload.get("directories"), "module directories")[5]
    if bool(rows) != bool(directory["rva"]):
        raise ToolkitInputError(
            "module base-relocation inventory disagrees with its directory"
        )
    blocks = [
        RelocationBlock.parse(
            _mapping(row, f"module base-relocation block {index}"),
            context=f"module base-relocation block {index}",
        )
        for index, row in enumerate(rows)
    ]
    if sum(block.size for block in blocks) != directory["size"]:
        raise ToolkitInputError(
            "module base-relocation blocks do not cover their directory"
        )
    image_size = int(payload["loader"]["image_size"])
    seen_targets: set[tuple[int, int]] = set()
    for index, block in enumerate(blocks):
        if block.index != index or block.page_rva % 0x1000:
            raise ToolkitInputError(
                "module base-relocation blocks are malformed or unordered"
            )
        if block.size != 8 + 2 * block.slot_count:
            raise ToolkitInputError(
                "module base-relocation block size is stale"
            )
        cursor = 0
        for relocation in block.relocations:
            if relocation.slot_index != cursor:
                raise ToolkitInputError(
                    "module base relocations do not cover every block slot"
                )
            cursor += relocation.consumed_slots
            if relocation.type == 0:
                if (
                    relocation.kind != "absolute_padding"
                    or relocation.consumed_slots != 1
                    or relocation.target_rva is not None
                    or relocation.width != 0
                    or relocation.preferred_value is not None
                    or relocation.adjustment is not None
                ):
                    raise ToolkitInputError(
                        "module ABSOLUTE relocation padding is malformed"
                    )
                continue
            expected = {
                1: ("high", 2, 1),
                2: ("low", 2, 1),
                3: ("highlow", 4, 1),
                4: ("highadj", 2, 2),
            }.get(relocation.type)
            if expected != (
                relocation.kind,
                relocation.width,
                relocation.consumed_slots,
            ):
                raise ToolkitInputError(
                    "module base-relocation kind is unsupported for PE32"
                )
            if (
                relocation.target_rva is None
                or relocation.preferred_value is None
                or relocation.target_rva + relocation.width > image_size
                or not block.page_rva
                <= relocation.target_rva
                < block.page_rva + 0x1000
            ):
                raise ToolkitInputError(
                    "module base-relocation target is malformed"
                )
            if (relocation.adjustment is None) != (relocation.type != 4):
                raise ToolkitInputError(
                    "module HIGHADJ relocation adjustment is incoherent"
                )
            target = (relocation.target_rva, relocation.width)
            if target in seen_targets:
                raise ToolkitInputError(
                    "module base-relocation target is duplicated"
                )
            seen_targets.add(target)
        if cursor != block.slot_count:
            raise ToolkitInputError(
                "module base relocations do not close their block slots"
            )


def _validate_load_config(payload: Mapping[str, Any]) -> None:
    raw = payload.get("load_config")
    directory = _list(payload.get("directories"), "module directories")[10]
    if raw is None:
        if directory["rva"] or directory["size"]:
            raise ToolkitInputError(
                "module load-config directory lacks a typed codec"
            )
        return
    config = _mapping(raw, "module load config")
    _exact_fields(config, {
        "directory_rva", "directory_size", "structure_size", "fields",
        "safe_seh", "cfg", "pointer_fields", "typed_tables",
    }, "module load config")
    if (
        config.get("directory_rva") != directory["rva"]
        or config.get("directory_size") != directory["size"]
    ):
        raise ToolkitInputError("module load-config directory binding is stale")
    structure_size = _integer(
        config.get("structure_size"), "module load-config structure size"
    )
    _mapping(config.get("fields"), "module load-config fields")
    safe_seh = config.get("safe_seh")
    if (safe_seh is not None) != (structure_size >= 72):
        raise ToolkitInputError("module SafeSEH revision projection is stale")
    if safe_seh is not None:
        seh = _mapping(safe_seh, "module SafeSEH metadata")
        _exact_fields(
            seh, {"table_va", "count", "handler_rvas"},
            "module SafeSEH metadata",
        )
        count = _integer(seh.get("count"), "module SafeSEH count")
        handlers = _list(seh.get("handler_rvas"), "module SafeSEH handlers")
        if len(handlers) != count or handlers != sorted(set(handlers)):
            raise ToolkitInputError("module SafeSEH table is not canonical")
        for index, handler in enumerate(handlers):
            _integer(handler, f"module SafeSEH handler {index}")
    cfg = config.get("cfg")
    if (cfg is not None) != (structure_size >= 92):
        raise ToolkitInputError("module CFG revision projection is stale")
    if cfg is not None:
        guard = _mapping(cfg, "module CFG metadata")
        _exact_fields(guard, {
            "check_function_pointer_va", "dispatch_function_pointer_va",
            "function_table_va", "function_count", "guard_flags",
            "entry_stride", "function_rvas",
        }, "module CFG metadata")
        count = _integer(guard.get("function_count"), "module CFG function count")
        functions = _list(guard.get("function_rvas"), "module CFG functions")
        if len(functions) != count or functions != sorted(set(functions)):
            raise ToolkitInputError("module CFG function table is not canonical")
        _integer(guard.get("entry_stride"), "module CFG entry stride", minimum=4)
    pointer_rows = _list(
        config.get("pointer_fields"), "module load-config pointer fields"
    )
    expected_pointers = [
        (offset, name, pointer_kind)
        for offset, minimum_size, name, pointer_kind
        in _LOAD_CONFIG_POINTER_FIELDS
        if structure_size >= minimum_size
    ]
    if len(pointer_rows) != len(expected_pointers):
        raise ToolkitInputError("module load-config pointer inventory is stale")
    preferred_base = _integer(
        _mapping(payload.get("loader"), "module loader contract").get(
            "preferred_base"
        ),
        "module preferred base",
    )
    sections = _list(payload.get("sections"), "module sections")
    for index, (raw_pointer, expected) in enumerate(
        zip(pointer_rows, expected_pointers, strict=True)
    ):
        pointer = _mapping(raw_pointer, f"module load-config pointer {index}")
        _exact_fields(pointer, {
            "name", "field_offset", "value_va", "pointer_kind", "target",
            "realization_policy",
        }, f"module load-config pointer {index}")
        expected_offset, expected_name, expected_kind = expected
        if (
            pointer.get("name") != expected_name
            or pointer.get("field_offset") != expected_offset
            or pointer.get("pointer_kind") != expected_kind
        ):
            raise ToolkitInputError(
                "module load-config pointer field classification is stale"
            )
        value_va = _integer(
            pointer.get("value_va"), "module load-config pointer VA"
        )
        target = _mapping(pointer.get("target"), "module load-config pointer target")
        target_kind = target.get("kind")
        if target_kind not in {"null", "image_rva", "external"}:
            raise ToolkitInputError("module load-config pointer target is unsupported")
        expected_target_fields = {"kind", "rva", "section_index"}
        if target_kind == "image_rva":
            expected_target_fields.add("executable")
        _exact_fields(
            target, expected_target_fields,
            f"module load-config pointer {index} target",
        )
        expected_policy = (
            "preserve_null" if value_va == 0 else
            "regenerate_code_target" if expected_kind == "va_code" else
            "relocate_typed_target"
        )
        if pointer.get("realization_policy") != expected_policy:
            raise ToolkitInputError(
                "module load-config pointer realization policy is stale"
            )
        if target_kind == "null":
            if value_va != 0 or target.get("rva") is not None or target.get("section_index") is not None:
                raise ToolkitInputError("module load-config null pointer is incoherent")
            continue
        if value_va == 0:
            raise ToolkitInputError("module load-config nonnull target has a null VA")
        if target_kind == "external":
            if target.get("rva") is not None or target.get("section_index") is not None:
                raise ToolkitInputError("module load-config external pointer is incoherent")
            continue
        rva = _integer(target.get("rva"), "module load-config pointer target RVA")
        section_index = _integer(
            target.get("section_index"),
            "module load-config pointer target section",
        )
        if value_va != preferred_base + rva or section_index >= len(sections):
            raise ToolkitInputError("module load-config image pointer is stale")
        section = _mapping(
            sections[section_index], "module load-config target section"
        )
        if not (
            int(section["rva"]) <= rva
            < int(section["rva"]) + int(section["mapped_size"])
            and target.get("executable") is section["executable"]
        ):
            raise ToolkitInputError(
                "module load-config pointer section projection is stale"
            )
        if expected_kind == "va_code" and target.get("executable") is not True:
            raise ToolkitInputError("module load-config code pointer is not executable")
    table_rows = _list(
        config.get("typed_tables"), "module load-config typed tables"
    )
    expected_tables = [
        name for _, _, minimum_size, name in _LOAD_CONFIG_TYPED_TABLES
        if structure_size >= minimum_size
    ]
    if len(table_rows) != len(expected_tables):
        raise ToolkitInputError("module load-config typed-table inventory is stale")
    for index, (raw_table, expected_name) in enumerate(
        zip(table_rows, expected_tables, strict=True)
    ):
        table = _mapping(raw_table, f"module load-config table {index}")
        _exact_fields(table, {
            "name", "table_va", "count", "entry_stride", "entries",
        }, f"module load-config table {index}")
        name = _text(table.get("name"), f"module load-config table {index} name")
        if name != expected_name:
            raise ToolkitInputError("module load-config table identity is stale")
        count = _integer(table.get("count"), "module load-config table count")
        if table.get("entry_stride") != 4:
            raise ToolkitInputError("module load-config table stride is unsupported")
        entries = _list(table.get("entries"), "module load-config table entries")
        if len(entries) != count or entries != sorted(set(entries)):
            raise ToolkitInputError("module load-config typed table is not canonical")


def _validate_counts(payload: Mapping[str, Any]) -> None:
    counts = _mapping(payload.get("counts"), "module-interface counts")
    _exact_fields(counts, {
        "import_slots", "import_descriptors", "delay_import_slots",
        "export_slots", "export_names", "data_exports", "tls_callbacks",
        "relocation_blocks", "relocation_slots", "base_relocations",
        "runtime_header_bytes", "resource_directories", "resource_entries",
        "resource_data_entries", "resource_bytes", "blockers",
    }, "module-interface counts")
    expected = {
        "import_slots": len(payload["imports"]),
        "import_descriptors": len(payload["import_descriptors"]),
        "delay_import_slots": sum(
            len(row["cells"]) for row in payload["delay_imports"]
        ),
        "export_slots": payload["export_directory"]["slot_count"],
        "export_names": len(payload["export_directory"]["name_table"]),
        "data_exports": sum(
            row["kind"] == "data" for row in payload["export_directory"]["slots"]
        ),
        "tls_callbacks": 0 if payload["tls"] is None else len(payload["tls"]["callbacks"]),
        "relocation_blocks": len(payload["base_relocations"]),
        "relocation_slots": sum(
            row["slot_count"] for row in payload["base_relocations"]
        ),
        "base_relocations": sum(
            relocation["type"] != 0
            for block in payload["base_relocations"]
            for relocation in block["relocations"]
        ),
        "runtime_header_bytes": payload["runtime_headers"]["size"],
        "resource_directories": (
            0 if payload["resources"] is None
            else len(payload["resources"]["directories"])
        ),
        "resource_entries": (
            0 if payload["resources"] is None
            else sum(
                len(row["entries"])
                for row in payload["resources"]["directories"]
            )
        ),
        "resource_data_entries": (
            0 if payload["resources"] is None
            else len(payload["resources"]["data_entries"])
        ),
        "resource_bytes": (
            0 if payload["resources"] is None
            else sum(row["size"] for row in payload["resources"]["data_entries"])
        ),
        "blockers": len(payload["blockers"]),
    }
    if dict(counts) != expected:
        raise ToolkitInputError("module-interface counts are stale")


@dataclass(frozen=True)
class Pe32ModuleInterfaceV2:
    payload: Mapping[str, Any]

    @property
    def image_id(self) -> str:
        return str(self.payload["image_id"])

    @property
    def interface_sha256(self) -> str:
        return str(self.payload["interface_sha256"])

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        expected_image_id: str | None = None,
        require_complete: bool = False,
    ) -> "Pe32ModuleInterfaceV2":
        payload = _mapping(value, "PE32 module interface")
        if set(payload) != _FIELDS:
            raise ToolkitInputError("PE32 module-interface fields are incomplete")
        if payload.get("format") != PE32_MODULE_INTERFACE_FORMAT:
            raise ToolkitInputError("PE32 module-interface format is unsupported")
        declared_sha = _sha256(
            payload.get("interface_sha256"), "module-interface SHA-256"
        )
        core = {
            key: item for key, item in payload.items() if key != "interface_sha256"
        }
        if declared_sha != canonical_sha256_v3(core):
            raise ToolkitInputError("module interface self hash is stale")
        image_id = _text(payload.get("image_id"), "module image ID")
        if expected_image_id is not None and image_id != expected_image_id:
            raise ToolkitInputError("module interface image identity is stale")
        blockers = _list(payload.get("blockers"), "module-interface blockers")
        status = payload.get("status")
        if status not in {"complete", "incomplete"} or (
            (status == "complete") != (not blockers)
        ):
            raise ToolkitInputError("module-interface status contradicts blockers")
        if require_complete and status != "complete":
            raise ToolkitInputError("module interface remains incomplete")
        identity = _mapping(payload.get("identity"), "module identity")
        _exact_fields(identity, {
            "pe_sha256", "file_size", "load_image_contract_sha256",
            "load_image_contract_id",
        }, "module identity")
        _sha256(identity.get("pe_sha256"), "original PE SHA-256")
        _integer(identity.get("file_size"), "original PE file size", minimum=1)
        _sha256(
            identity.get("load_image_contract_sha256"),
            "load-image-contract file SHA-256",
        )
        _sha256(
            identity.get("load_image_contract_id"),
            "load-image-contract identity",
        )
        _validate_loader(payload)
        _validate_eat(payload.get("export_directory"))
        _validate_imports(payload)
        _validate_delay_imports(payload)
        _validate_runtime_headers(payload)
        _validate_sections(payload)
        _validate_directories(payload)
        validate_resource_surface_v1(
            payload.get("resources"),
            directory=payload["directories"][2],
            sections=payload["sections"],
            runtime_headers=payload["runtime_headers"],
            allow_missing=any(
                str(row.get("category", "")).startswith("resource_")
                for row in payload["blockers"]
                if isinstance(row, Mapping)
            ),
        )
        _validate_tls(payload)
        _validate_base_relocations(payload)
        _validate_load_config(payload)
        _validate_counts(payload)
        policy = _mapping(payload.get("policy"), "module-interface policy")
        if dict(policy) != {
            "layout_compatibility": "not_promised",
            "cross_image_addresses": "loader_abi_only",
            "pointer_bearing_directories": "typed_or_fail_closed",
            "bound_import_metadata": "clear_on_composition",
        }:
            raise ToolkitInputError("module-interface policy is unsupported")
        return cls(dict(payload))

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        expected_image_id: str | None = None,
        require_complete: bool = False,
    ) -> "Pe32ModuleInterfaceV2":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ToolkitInputError(
                f"cannot read PE32 module interface: {exc}"
            ) from exc
        return cls.parse(
            value,
            expected_image_id=expected_image_id,
            require_complete=require_complete,
        )


__all__ = ["Pe32ModuleInterfaceV2"]
