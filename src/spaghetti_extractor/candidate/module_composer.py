"""Direct PE32 loader-surface composition from a checked native-ingress plan."""

from __future__ import annotations

import json
import os
import struct
import tempfile
from pathlib import Path
from typing import Any, Mapping

import pefile

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import PE_COMPOSITION_MANIFEST_FORMAT
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..pe32.formats import PE32_MODULE_INTERFACE_FORMAT
from .formats import (
    NATIVE_INGRESS_PLAN_FORMAT,
    NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT,
)
from .build_objects import _payload_symbol_rvas
from .linked_skeleton_merge import merge_linked_skeleton
from .outcomes import pinned_continuation_portal_for_protocol_v1
from ..errors import ToolkitInputError
from ..util import sha256_bytes, sha256_file, write_json


_SECTION_CHARACTERISTICS = 0xC0000040
_HIGHLOW = 3


class PE32ModuleCompositionError(ToolkitInputError):
    """A checked module surface cannot be realized in one PE32 image."""


class _Surface:
    def __init__(self, base_rva: int, image_base: int) -> None:
        self.base_rva = base_rva
        self.image_base = image_base
        self.data = bytearray()

    def align(self, alignment: int) -> None:
        self.data.extend(b"\0" * (-len(self.data) % alignment))

    def reserve(self, size: int, *, alignment: int = 1) -> int:
        self.align(alignment)
        offset = len(self.data)
        self.data.extend(b"\0" * size)
        return offset

    def append(self, value: bytes, *, alignment: int = 1) -> int:
        offset = self.reserve(len(value), alignment=alignment)
        self.data[offset : offset + len(value)] = value
        return offset

    def c_string(self, value: str) -> int:
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise PE32ModuleCompositionError(
                "loader surface strings must be ASCII"
            ) from exc
        if not encoded or b"\0" in encoded:
            raise PE32ModuleCompositionError("loader surface string is malformed")
        return self.append(encoded + b"\0")

    def rva(self, offset: int) -> int:
        return self.base_rva + offset

    def va(self, offset: int) -> int:
        return self.image_base + self.rva(offset)

    def pack_into(self, fmt: str, offset: int, *values: object) -> None:
        struct.pack_into(fmt, self.data, offset, *values)


def compose_pe32_native_module(
    *,
    linked_skeleton: Path,
    linked_relocation_inventory: Path,
    load_image_contract: Path,
    recovered_executable_data: Path | None,
    original_module_interface: Path,
    native_ingress_plan: Path,
    native_build_manifest: Path,
    resolved_external_environment: Path,
    object_authority: Path,
    out: Path,
    candidate_filename: str,
) -> dict[str, Any]:
    """Regenerate loader-consumed surfaces and emit the declared module basename."""

    if (
        not isinstance(candidate_filename, str)
        or not candidate_filename
        or Path(candidate_filename).name != candidate_filename
    ):
        raise PE32ModuleCompositionError(
            "candidate filename must be a loader basename"
        )
    skeleton_path = Path(linked_skeleton)
    relocation_path = Path(linked_relocation_inventory)
    load_contract_path = Path(load_image_contract)
    interface_path = Path(original_module_interface)
    plan_path = Path(native_ingress_plan)
    build_manifest_path = Path(native_build_manifest)
    environment_path = Path(resolved_external_environment)
    authority_path = Path(object_authority)
    interface = _closed(
        interface_path, PE32_MODULE_INTERFACE_FORMAT, "interface_sha256"
    )
    plan = _closed(plan_path, NATIVE_INGRESS_PLAN_FORMAT, "plan_sha256")
    environment = _object(environment_path, "resolved external environment")
    authority_payload = _object(authority_path, "machine object authority")
    authority = MachineObjectAuthorityV2.parse(authority_payload)
    if interface.get("status") != "complete" or plan.get("status") != "complete":
        raise PE32ModuleCompositionError("module interface or ingress plan is incomplete")
    if plan.get("module", {}).get("module_interface_sha256") != sha256_file(
        interface_path
    ):
        raise PE32ModuleCompositionError("ingress plan binds another interface")
    if (
        environment.get("format") != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
        or environment.get("status") != "complete"
        or environment.get("blockers") != []
    ):
        raise PE32ModuleCompositionError("resolved external environment is incomplete")
    if authority.bindings.get("module_interface_sha256") != sha256_file(
        interface_path
    ):
        raise PE32ModuleCompositionError("object authority binds another interface")
    relocation_payload = _object(
        relocation_path, "linked relocation inventory"
    )
    build_manifest = _object(
        build_manifest_path, "native realization build manifest"
    )
    manifest_hashes = build_manifest.get("hashes")
    manifest_core = {
        key: value for key, value in build_manifest.items() if key != "hashes"
    }
    if (
        build_manifest.get("format") != NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT
        or build_manifest.get("status") != "linked"
        or build_manifest.get("acceptance_authority") != "none"
        or not isinstance(manifest_hashes, Mapping)
        or manifest_hashes.get("manifest_core_sha256")
        != canonical_sha256_v3(manifest_core)
    ):
        raise PE32ModuleCompositionError(
            "native realization build manifest is stale or incomplete"
        )
    manifest_inputs = build_manifest.get("inputs")
    linked_binding = (
        manifest_inputs.get("linked_semantic_module", {})
        if isinstance(manifest_inputs, Mapping)
        else {}
    )
    ingress_binding = (
        manifest_inputs.get("native_ingress_plan", {})
        if isinstance(manifest_inputs, Mapping)
        else {}
    )
    load_binding = (
        manifest_inputs.get("load_image_contract", {})
        if isinstance(manifest_inputs, Mapping)
        else {}
    )
    if (
        ingress_binding.get("artifact_sha256") != sha256_file(plan_path)
        or load_binding.get("artifact_sha256") != sha256_file(load_contract_path)
        or linked_binding.get("resolved_external_environment_sha256")
        != sha256_file(environment_path)
        or linked_binding.get("machine_object_authority_sha256")
        != sha256_file(authority_path)
    ):
        raise PE32ModuleCompositionError(
            "native realization build bindings are stale"
        )
    outputs = build_manifest.get("outputs")
    payload_binding = outputs.get("payload", {}) if isinstance(outputs, Mapping) else {}
    map_binding = outputs.get("linker_map", {}) if isinstance(outputs, Mapping) else {}
    relocation_binding = (
        outputs.get("payload_relocation_inventory", {})
        if isinstance(outputs, Mapping)
        else {}
    )
    linker_map_path = build_manifest_path.parent / "payload.map"
    if (
        payload_binding.get("sha256") != sha256_file(skeleton_path)
        or map_binding.get("sha256") != sha256_file(linker_map_path)
        or relocation_binding.get("complete") is not True
        or relocation_binding.get("sha256") != sha256_file(relocation_path)
        or relocation_payload.get("complete") is not True
    ):
        raise PE32ModuleCompositionError(
            "native realization outputs are stale or incomplete"
        )
    linked = _payload_symbol_rvas(
        linker_map_path,
        image_base=int(build_manifest["policy"]["image_base"]),
    )
    if sha256_file(skeleton_path) == interface.get("identity", {}).get("pe_sha256"):
        # A checked fixture or internal linker may provide an already merged
        # skeleton.  Its hash must be the exact original image identity.
        image = bytearray(skeleton_path.read_bytes())
    else:
        with tempfile.TemporaryDirectory(prefix="spx-linked-skeleton-") as temporary:
            temporary_root = Path(temporary)
            merge_linked_skeleton(
                load_image_contract=load_contract_path,
                payload_pe=skeleton_path,
                entry_rva=_module_entry_rva(plan, linked),
                payload_relocation_inventory=relocation_path,
                recovered_executable_data=recovered_executable_data,
                out_dir=temporary_root,
                candidate_filename=candidate_filename,
            )
            image = bytearray((temporary_root / candidate_filename).read_bytes())
    pe = pefile.PE(data=bytes(image), fast_load=False)
    try:
        _require_pe32(pe)
        if _ensure_section_header_capacity(image, pe):
            pe.close()
            pe = pefile.PE(data=bytes(image), fast_load=False)
            _require_pe32(pe)
        section_alignment = int(pe.OPTIONAL_HEADER.SectionAlignment)
        file_alignment = int(pe.OPTIONAL_HEADER.FileAlignment)
        section_rva = _align_up(int(pe.OPTIONAL_HEADER.SizeOfImage), section_alignment)
        surface = _Surface(section_rva, int(pe.OPTIONAL_HEADER.ImageBase))
        directories: dict[int, tuple[int, int]] = {}
        export_geometry = _compose_exports(surface, interface, plan, linked)
        if export_geometry is not None:
            directories[0] = export_geometry
        import_geometry, support_slots, iat_geometry = _compose_imports(
            surface, pe, interface, plan
        )
        directories[1] = import_geometry
        if iat_geometry != (0, 0):
            directories[12] = iat_geometry
        directories[13] = _compose_delay_imports(surface, pe, interface)
        tls_geometry, tls_relocations, tls_index_rva = _compose_tls(
            surface, interface, plan, linked
        )
        directories[9] = tls_geometry
        support_relocations, support_realizations = _realize_support_symbols(
            image, pe, plan, linked, tls_index_rva=tls_index_rva,
            support_import_slots=support_slots,
        )
        load_config_geometry, load_config_relocations = _compose_load_config(
            surface, pe, plan, linked
        )
        if load_config_geometry is not None:
            directories[10] = load_config_geometry
        relocations = (
            _original_relocations(pe)
            | tls_relocations
            | load_config_relocations
            | support_relocations
        )
        relocation_geometry = _compose_relocations(surface, relocations)
        directories[5] = relocation_geometry

        raw_pointer = _align_up(len(image), file_alignment)
        raw_size = _align_up(len(surface.data), file_alignment)
        image.extend(b"\0" * (raw_pointer - len(image)))
        image.extend(surface.data)
        image.extend(b"\0" * (raw_size - len(surface.data)))
        _append_section_header(
            image, pe, rva=section_rva, virtual_size=len(surface.data),
            raw_pointer=raw_pointer, raw_size=raw_size,
        )
        _update_optional_header(
            image, pe, section_rva=section_rva,
            virtual_size=len(surface.data), raw_size=raw_size,
            entry_rva=_module_entry_rva(plan, linked), directories=directories,
        )
        final_pe = pefile.PE(data=bytes(image), fast_load=False)
        try:
            checksum_offset = final_pe.OPTIONAL_HEADER.get_field_absolute_offset(
                "CheckSum"
            )
            struct.pack_into("<I", image, checksum_offset, 0)
            checksum_pe = pefile.PE(data=bytes(image), fast_load=True)
            try:
                checksum = checksum_pe.generate_checksum()
            finally:
                checksum_pe.close()
            struct.pack_into("<I", image, checksum_offset, checksum)
        finally:
            final_pe.close()
    finally:
        pe.close()

    candidate = bytes(image)
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    candidate_path = output / candidate_filename
    temporary = output / f".{candidate_filename}.tmp"
    try:
        temporary.write_bytes(candidate)
        os.replace(temporary, candidate_path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    core = {
        "format": PE_COMPOSITION_MANIFEST_FORMAT,
        "status": "composed",
        "acceptance_authority": "none",
        "inputs": {
            "linked_skeleton_sha256": sha256_file(skeleton_path),
            "linked_relocation_inventory_sha256": sha256_file(relocation_path),
            "load_image_contract_sha256": sha256_file(load_contract_path),
            "recovered_executable_data_sha256": (
                None
                if recovered_executable_data is None
                else sha256_file(Path(recovered_executable_data))
            ),
            "original_module_interface_sha256": sha256_file(interface_path),
            "native_ingress_plan_sha256": sha256_file(plan_path),
            "native_build_manifest_sha256": sha256_file(build_manifest_path),
            "resolved_external_environment_sha256": sha256_file(environment_path),
            "object_authority_sha256": sha256_file(authority_path),
        },
        "candidate": {
            "path": candidate_filename,
            "sha256": sha256_bytes(candidate),
            "file_size": len(candidate),
            "entry_rva": _module_entry_rva(plan, linked),
        },
        "loader_surface": {
            "section_name": ".spxldr",
            "section_rva": section_rva,
            "virtual_size": len(surface.data),
            "raw_size": raw_size,
            "directories": {
                str(index): {"rva": value[0], "size": value[1]}
                for index, value in sorted(directories.items())
            },
            "runtime_support_import_slots": support_slots,
            "runtime_support_symbol_realizations": support_realizations,
        },
        "policy": {
            "entrypoint": "direct_linked_ingress_bridge",
            "exports": "deterministic_regenerated_eat",
            "tls": "combined_target_runtime_template",
            "imports": "original_slots_plus_tagged_runtime_support",
            "bound_import_metadata": "cleared",
            "relocations": "canonical_pe32_highlow_regenerated",
            "linked_relocations": "explicit_native_module_inventory",
        },
    }
    manifest = {
        **core,
        "hashes": {
            "algorithm": "sha256",
            "manifest_core_sha256": canonical_sha256_v3(core),
        },
    }
    write_json(output / "pe-composition-manifest.json", manifest)
    return manifest


def _compose_exports(
    surface: _Surface,
    interface: Mapping[str, Any],
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
) -> tuple[int, int] | None:
    source = interface["export_directory"]
    if source["slot_count"] == 0:
        return None
    start = surface.reserve(40, alignment=4)
    dll_offset = surface.c_string(source["dll_name"])
    eat_offset = surface.reserve(source["slot_count"] * 4, alignment=4)
    name_table = source["name_table"]
    names_offset = surface.reserve(len(name_table) * 4, alignment=4)
    ordinals_offset = surface.reserve(len(name_table) * 2, alignment=2)
    name_offsets = [surface.c_string(row["name"]) for row in name_table]
    forwarder_offsets: dict[int, int] = {}
    for row in source["slots"]:
        if row["kind"] == "forwarder":
            forwarder_offsets[row["slot_index"]] = surface.c_string(
                row["forwarder"]
            )
    for row in source["slots"]:
        target = _export_target_rva(row, plan, linked, surface, forwarder_offsets)
        surface.pack_into("<I", eat_offset + row["slot_index"] * 4, target)
    for index, row in enumerate(name_table):
        surface.pack_into("<I", names_offset + index * 4, surface.rva(name_offsets[index]))
        surface.pack_into("<H", ordinals_offset + index * 2, row["slot_index"])
    metadata = source["metadata"]
    surface.pack_into(
        "<IIHHIIIIIII", start,
        metadata["characteristics"], metadata["timestamp"],
        metadata["major_version"], metadata["minor_version"],
        surface.rva(dll_offset), source["ordinal_base"], source["slot_count"],
        len(name_table), surface.rva(eat_offset), surface.rva(names_offset),
        surface.rva(ordinals_offset),
    )
    return surface.rva(start), len(surface.data) - start


def _export_target_rva(
    row: Mapping[str, Any],
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
    surface: _Surface,
    forwarders: Mapping[int, int],
) -> int:
    kind = row["kind"]
    if kind == "hole":
        return 0
    if kind == "data":
        aliases = {(name, row["ordinal"]) for name in row.get("names", [])} or {
            (None, row["ordinal"])
        }
        anchors = [
            anchor for anchor in plan.get("data_export_anchors", [])
            if aliases <= {
                (alias.get("name"), alias.get("ordinal"))
                for alias in anchor.get("aliases", [])
            }
        ]
        if len(anchors) != 1:
            raise PE32ModuleCompositionError(
                f"data export ordinal {row['ordinal']} has no unique address anchor"
            )
        locator = anchors[0].get("locator")
        if (
            not isinstance(locator, Mapping)
            or locator.get("kind") != "image_rva"
            or not isinstance(locator.get("rva"), int)
        ):
            raise PE32ModuleCompositionError(
                f"data export ordinal {row['ordinal']} is not image-backed"
            )
        target = int(locator["rva"]) + int(anchors[0]["byte_offset"])
        if target != int(row["rva"]):
            raise PE32ModuleCompositionError(
                f"data export ordinal {row['ordinal']} address anchor is stale"
            )
        return target
    if kind == "forwarder":
        return surface.rva(forwarders[row["slot_index"]])
    matches = [
        ingress for ingress in plan["ingresses"]
        if ingress["role"] == "export"
        and any(alias["ordinal"] == row["ordinal"] for alias in ingress["exports"])
    ]
    if len(matches) != 1 or matches[0]["bridge_symbol"] not in linked:
        raise PE32ModuleCompositionError(
            f"code export ordinal {row['ordinal']} has no unique linked ingress"
        )
    return linked[matches[0]["bridge_symbol"]]


def _compose_imports(
    surface: _Surface,
    pe: pefile.PE,
    interface: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> tuple[tuple[int, int], list[dict[str, Any]], tuple[int, int]]:
    originals: list[tuple[int, int, int, int, int]] = []
    descriptors = interface.get("import_descriptors")
    if not isinstance(descriptors, list):
        raise PE32ModuleCompositionError(
            "module interface lacks exact import descriptor geometry"
        )
    for expected_index, descriptor in enumerate(descriptors):
        if (
            not isinstance(descriptor, Mapping)
            or int(descriptor.get("index", -1)) != expected_index
            or not isinstance(descriptor.get("dll"), str)
            or not descriptor["dll"]
        ):
            raise PE32ModuleCompositionError("original import descriptor is malformed")
        cells = descriptor.get("cells")
        if not isinstance(cells, list) or not cells:
            raise PE32ModuleCompositionError("original import descriptor has no cells")
        thunk_values: list[int] = []
        expected_iat = int(descriptor["iat_rva"])
        for cell_index, cell in enumerate(cells):
            if (
                not isinstance(cell, Mapping)
                or int(cell.get("index", -1)) != cell_index
                or int(cell.get("iat_rva", -1)) != expected_iat + cell_index * 4
                or int(cell.get("pointer_width", 0)) != 4
            ):
                raise PE32ModuleCompositionError(
                    "original import cells are not a contiguous PE32 IAT"
                )
            try:
                iat_offset = pe.get_offset_from_rva(int(cell["iat_rva"]))
            except Exception as exc:
                raise PE32ModuleCompositionError(
                    "original IAT slot is absent from the base candidate"
                ) from exc
            if iat_offset < 0 or iat_offset + 4 > len(pe.__data__):
                raise PE32ModuleCompositionError(
                    "original IAT slot is not fully file-backed"
                )
            symbol, ordinal = cell.get("symbol"), cell.get("ordinal")
            if symbol is not None:
                if not isinstance(symbol, str) or not symbol:
                    raise PE32ModuleCompositionError("original import name is malformed")
                name_offset = surface.append(
                    struct.pack("<H", int(cell.get("hint") or 0))
                    + symbol.encode("ascii") + b"\0",
                    alignment=2,
                )
                thunk_values.append(surface.rva(name_offset))
            elif isinstance(ordinal, int) and not isinstance(ordinal, bool):
                thunk_values.append(0x80000000 | ordinal)
            else:
                raise PE32ModuleCompositionError("original import identity is malformed")
        int_offset = surface.append(
            struct.pack(
                "<" + "I" * (len(thunk_values) + 1), *thunk_values, 0
            ),
            alignment=4,
        )
        dll_offset = surface.c_string(str(descriptor["dll"]))
        originals.append((
            surface.rva(int_offset), 0, 0, surface.rva(dll_offset), expected_iat,
        ))
    support = plan.get("required_support_imports", [])
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in support:
        grouped.setdefault(str(row["dll"]).lower(), []).append(row)
    generated: list[tuple[int, int, int, int, int]] = []
    support_slots: list[dict[str, Any]] = []
    for dll in sorted(grouped):
        rows = sorted(grouped[dll], key=lambda row: (str(row.get("symbol")), row.get("ordinal") or -1))
        dll_offset = surface.c_string(dll)
        thunk_values: list[int] = []
        for row in rows:
            if row.get("symbol") is not None:
                name_offset = surface.append(
                    struct.pack("<H", 0) + str(row["symbol"]).encode("ascii") + b"\0",
                    alignment=2,
                )
                thunk_values.append(surface.rva(name_offset))
            else:
                thunk_values.append(0x80000000 | int(row["ordinal"]))
        thunk_bytes = struct.pack(
            "<" + "I" * (len(thunk_values) + 1), *thunk_values, 0
        )
        int_offset = surface.append(thunk_bytes, alignment=4)
        iat_offset = surface.append(thunk_bytes, alignment=4)
        generated.append((
            surface.rva(int_offset), 0, 0, surface.rva(dll_offset),
            surface.rva(iat_offset),
        ))
        for index, row in enumerate(rows):
            support_slots.append({
                "ownership": "runtime_support",
                "dll": dll,
                "symbol": row.get("symbol"),
                "ordinal": row.get("ordinal"),
                "iat_rva": surface.rva(iat_offset) + index * 4,
                "purpose": row.get("purpose"),
            })
    if not originals and not generated:
        return (0, 0), support_slots, (0, 0)
    descriptor_offset = surface.reserve(
        (len(originals) + len(generated) + 1) * 20, alignment=4
    )
    for index, row in enumerate((*originals, *generated)):
        surface.pack_into("<IIIII", descriptor_offset + index * 20, *row)
    iat_rvas = [int(row["iat_rva"]) for row in interface.get("imports", [])]
    iat_rvas.extend(int(row["iat_rva"]) for row in support_slots)
    iat_geometry = (
        (min(iat_rvas), max(iat_rvas) + 4 - min(iat_rvas))
        if iat_rvas else (0, 0)
    )
    return (
        surface.rva(descriptor_offset),
        (len(originals) + len(generated) + 1) * 20,
    ), support_slots, iat_geometry


def _compose_tls(
    surface: _Surface,
    interface: Mapping[str, Any],
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
) -> tuple[tuple[int, int], set[int], int]:
    source = interface.get("tls")
    layout = plan["tls_layout"]
    template = b"" if source is None else bytes.fromhex(source["template_data_hex"])
    template_offset = surface.append(template or b"\0", alignment=16)
    raw_template_size = len(template)
    if raw_template_size == 0:
        raw_template_size = 0
    index_rva = None if source is None else source.get("index_rva")
    if index_rva is None:
        index_offset = surface.reserve(4, alignment=4)
        index_rva = surface.rva(index_offset)
    callbacks = sorted(
        (row for row in plan["ingresses"] if row["role"] == "tls_callback"),
        key=lambda row: row["tls_order"],
    )
    callback_values = [
        surface.image_base + linked[row["bridge_symbol"]] for row in callbacks
    ]
    callback_offset = surface.append(
        struct.pack("<" + "I" * (len(callback_values) + 1), *callback_values, 0),
        alignment=4,
    )
    directory_offset = surface.reserve(24, alignment=4)
    start_va = surface.va(template_offset)
    end_va = start_va + raw_template_size
    surface.pack_into(
        "<IIIIII", directory_offset, start_va, end_va,
        surface.image_base + int(index_rva), surface.va(callback_offset),
        int(layout["runtime_offset"] + layout["runtime_bytes"] - raw_template_size),
        0 if source is None else int(source["characteristics"]),
    )
    relocations = {
        surface.rva(directory_offset + offset) for offset in (0, 4, 8, 12)
    }
    relocations.update(
        surface.rva(callback_offset + index * 4)
        for index in range(len(callback_values))
    )
    return (surface.rva(directory_offset), 24), relocations, int(index_rva)


def _compose_delay_imports(
    surface: _Surface, pe: pefile.PE, interface: Mapping[str, Any]
) -> tuple[int, int]:
    descriptors = interface.get("delay_imports")
    if not isinstance(descriptors, list):
        raise PE32ModuleCompositionError(
            "module interface lacks typed delay-import geometry"
        )
    if not descriptors:
        return 0, 0

    def require_storage(rva: int, label: str) -> None:
        if rva == 0:
            return
        try:
            offset = pe.get_offset_from_rva(rva)
        except Exception as exc:
            raise PE32ModuleCompositionError(
                f"{label} is absent from the base candidate"
            ) from exc
        if offset < 0 or offset + 4 > len(pe.__data__):
            raise PE32ModuleCompositionError(
                f"{label} is not fully file-backed"
            )

    rows: list[tuple[int, int, int, int, int, int, int, int]] = []
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    for expected_index, descriptor in enumerate(descriptors):
        if (
            not isinstance(descriptor, Mapping)
            or int(descriptor.get("descriptor_index", -1)) != expected_index
            or not isinstance(descriptor.get("dll"), str)
            or not descriptor["dll"]
        ):
            raise PE32ModuleCompositionError("delay-import descriptor is malformed")
        cells = descriptor.get("cells")
        if not isinstance(cells, list) or not cells:
            raise PE32ModuleCompositionError("delay-import descriptor has no cells")
        pointers_are_rvas = bool(descriptor.get("pointers_are_rvas"))
        attributes = int(descriptor.get("attributes", -1))
        if attributes not in {0, 1} or pointers_are_rvas != bool(attributes & 1):
            raise PE32ModuleCompositionError(
                "delay-import pointer attributes are inconsistent"
            )
        iat_rva = int(descriptor["iat_rva"])
        module_handle_rva = int(descriptor.get("module_handle_rva") or 0)
        unload_iat_rva = int(descriptor.get("unload_iat_rva") or 0)
        require_storage(iat_rva, "delay IAT")
        require_storage(module_handle_rva, "delay module-handle slot")
        require_storage(unload_iat_rva, "delay unload IAT")
        thunk_values: list[int] = []
        for cell_index, cell in enumerate(cells):
            if (
                not isinstance(cell, Mapping)
                or int(cell.get("cell_index", -1)) != cell_index
                or int(cell.get("iat_rva", -1)) != iat_rva + cell_index * 4
            ):
                raise PE32ModuleCompositionError(
                    "delay-import cells are not a contiguous PE32 IAT"
                )
            require_storage(int(cell["iat_rva"]), "delay IAT cell")
            symbol, ordinal = cell.get("symbol"), cell.get("ordinal")
            if symbol is not None:
                if not isinstance(symbol, str) or not symbol:
                    raise PE32ModuleCompositionError(
                        "delay-import name is malformed"
                    )
                name_offset = surface.append(
                    struct.pack("<H", int(cell.get("hint") or 0))
                    + symbol.encode("ascii") + b"\0",
                    alignment=2,
                )
                name_pointer = surface.rva(name_offset)
                thunk_values.append(
                    name_pointer if pointers_are_rvas else image_base + name_pointer
                )
            elif isinstance(ordinal, int) and not isinstance(ordinal, bool):
                thunk_values.append(0x80000000 | ordinal)
            else:
                raise PE32ModuleCompositionError(
                    "delay-import identity is malformed"
                )
        int_offset = surface.append(
            struct.pack(
                "<" + "I" * (len(thunk_values) + 1), *thunk_values, 0
            ),
            alignment=4,
        )
        dll_offset = surface.c_string(str(descriptor["dll"]))

        def pointer(rva: int) -> int:
            return rva if pointers_are_rvas or rva == 0 else image_base + rva

        rows.append((
            attributes,
            pointer(surface.rva(dll_offset)),
            pointer(module_handle_rva),
            pointer(iat_rva),
            pointer(surface.rva(int_offset)),
            0,
            pointer(unload_iat_rva),
            0,
        ))
    descriptor_offset = surface.reserve((len(rows) + 1) * 32, alignment=4)
    for index, row in enumerate(rows):
        surface.pack_into("<IIIIIIII", descriptor_offset + index * 32, *row)
    return surface.rva(descriptor_offset), (len(rows) + 1) * 32


def _realize_support_symbols(
    image: bytearray,
    pe: pefile.PE,
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
    *,
    tls_index_rva: int,
    support_import_slots: list[dict[str, Any]],
) -> tuple[set[int], list[dict[str, Any]]]:
    relocations: set[int] = set()
    realizations: list[dict[str, Any]] = []
    for support in plan.get("support_symbols", []):
        if not isinstance(support, Mapping):
            raise PE32ModuleCompositionError("runtime support symbol is malformed")
        symbol = support.get("symbol")
        if symbol not in linked:
            raise PE32ModuleCompositionError(
                f"runtime support symbol {symbol!r} is not linked"
            )
        target_kind = support.get("target")
        if (
            support.get("kind") != "loader_realized_data_pointer"
            or support.get("width_bytes") != 4
            or support.get("relocation_kind") != "pe32_highlow"
        ):
            raise PE32ModuleCompositionError(
                f"runtime support symbol {symbol!r} has no realization codec"
            )
        rva = int(linked[str(symbol)])
        try:
            offset = pe.get_offset_from_rva(rva)
        except Exception as exc:
            raise PE32ModuleCompositionError(
                f"runtime support symbol {symbol!r} is not file-backed"
            ) from exc
        if offset < 0 or offset + 4 > len(image):
            raise PE32ModuleCompositionError(
                f"runtime support symbol {symbol!r} is not fully file-backed"
            )
        if target_kind == "tls_index_cell_va":
            target_rva = tls_index_rva
        elif target_kind == "module_base_va":
            target_rva = 0
        elif isinstance(target_kind, str) and target_kind.startswith(
            "runtime_support_iat_va:"
        ):
            purpose = target_kind.split(":", 1)[1]
            matches = [
                row for row in support_import_slots
                if row.get("purpose") == purpose
            ]
            if len(matches) != 1:
                raise PE32ModuleCompositionError(
                    f"runtime support symbol {symbol!r} has no unique support IAT slot"
                )
            target_rva = int(matches[0]["iat_rva"])
        else:
            raise PE32ModuleCompositionError(
                f"runtime support symbol {symbol!r} has no realization codec"
            )
        struct.pack_into(
            "<I", image, offset,
            int(pe.OPTIONAL_HEADER.ImageBase) + target_rva,
        )
        relocations.add(rva)
        realizations.append({
            "symbol": symbol,
            "symbol_rva": rva,
            "value_kind": "va",
            "value": int(pe.OPTIONAL_HEADER.ImageBase) + target_rva,
            "target_rva": target_rva,
            "relocation_rva": rva,
            "relocation_kind": "pe32_highlow",
        })
    return relocations, realizations


def _original_relocations(pe: pefile.PE) -> set[int]:
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
    )
    result: set[int] = set()
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for entry in block.entries:
            if entry.type == 0:
                continue
            if entry.type != _HIGHLOW:
                raise PE32ModuleCompositionError(
                    "base candidate contains a non-HIGHLOW PE32 relocation"
                )
            result.add(int(entry.rva))
    return result


def _compose_load_config(
    surface: _Surface,
    pe: pefile.PE,
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
) -> tuple[tuple[int, int] | None, set[int]]:
    requirements = plan.get("load_config_requirements")
    if requirements is None and not plan.get("seh_protocols"):
        return None, set()
    if requirements is None:
        directory_size = structure_size = 72
        raw = bytearray(directory_size)
        struct.pack_into("<I", raw, 0, structure_size)
        requirements = {
            "pointer_fields": [],
            "safe_seh": {"handler_rvas": []},
            "cfg": None,
            "typed_tables": [],
        }
    else:
        directory_rva = int(requirements["directory_rva"])
        directory_size = int(requirements["directory_size"])
        structure_size = int(requirements["structure_size"])
        raw = pe.get_data(directory_rva, directory_size)
        if len(raw) != directory_size or structure_size > directory_size:
            raise PE32ModuleCompositionError("load-config bytes are not fully mapped")
        if plan.get("seh_protocols") and structure_size < 72:
            raw = raw[:structure_size] + b"\0" * (72 - structure_size)
            directory_size = structure_size = 72
            raw = bytearray(raw)
            struct.pack_into("<I", raw, 0, structure_size)
            requirements = {
                **requirements,
                "safe_seh": {"handler_rvas": []},
            }
    header_offset = surface.append(raw, alignment=4)
    relocations: set[int] = set()
    portals = {
        int(portal["source_rva"]): linked[portal["candidate_symbol"]]
        for protocol in plan.get("seh_protocols", [])
        for portal in protocol.get("portals", [])
        if portal.get("candidate_symbol") in linked
    }
    portals.update({
        int(protocol["resumption_rva"]): linked[symbol]
        for protocol in plan.get("seh_protocols", [])
        if isinstance(protocol, Mapping)
        and (symbol := pinned_continuation_portal_for_protocol_v1(protocol))
        is not None and symbol in linked
    })
    for pointer in requirements.get("pointer_fields", []):
        value = int(pointer["value_va"])
        if value == 0:
            continue
        if pointer["pointer_kind"] == "va_code":
            source_rva = value - int(pe.OPTIONAL_HEADER.ImageBase)
            if source_rva not in portals:
                raise PE32ModuleCompositionError(
                    f"load-config code pointer {pointer['name']} lacks a portal mapping"
                )
            surface.pack_into(
                "<I", header_offset + int(pointer["field_offset"]),
                surface.image_base + portals[source_rva],
            )
        relocations.add(surface.rva(header_offset + int(pointer["field_offset"])))
    safe = requirements.get("safe_seh")
    if isinstance(safe, Mapping):
        handlers = sorted({
            linked[protocol["gateway_handler_symbol"]]
            for protocol in plan.get("seh_protocols", [])
        })
        if handlers:
            table_offset = surface.append(
                struct.pack("<" + "I" * len(handlers), *handlers), alignment=4
            )
            surface.pack_into(
                "<II", header_offset + 64, surface.va(table_offset), len(handlers)
            )
            relocations.add(surface.rva(header_offset + 64))
        else:
            surface.pack_into("<II", header_offset + 64, 0, 0)

    cfg = requirements.get("cfg")
    if isinstance(cfg, Mapping):
        targets = sorted({
            linked[row["symbol"]] for row in plan.get("bridges", [])
            if row.get("symbol") in linked
        })
        stride = int(cfg["entry_stride"])
        table = bytearray()
        for target in targets:
            table.extend(struct.pack("<I", target))
            table.extend(b"\0" * (stride - 4))
        if table:
            table_offset = surface.append(bytes(table), alignment=4)
            surface.pack_into(
                "<II", header_offset + 80, surface.va(table_offset), len(targets)
            )
            relocations.add(surface.rva(header_offset + 80))
        else:
            surface.pack_into("<II", header_offset + 80, 0, 0)

    for table in requirements.get("typed_tables", []):
        name = table["name"]
        entries = [int(value) for value in table["entries"]]
        pointer_offset = {
            "guard_address_taken_iat_entries": 104,
            "guard_long_jump_targets": 112,
            "guard_eh_continuation_targets": 164,
        }[name]
        if name == "guard_long_jump_targets" and entries:
            raise PE32ModuleCompositionError(
                "load-config long-jump targets require a checked nonlocal protocol"
            )
        if name == "guard_eh_continuation_targets":
            try:
                entries = [portals[value] for value in entries]
            except KeyError as exc:
                raise PE32ModuleCompositionError(
                    "EH continuation target lacks an exception portal mapping"
                ) from exc
        if entries:
            table_offset = surface.append(
                struct.pack("<" + "I" * len(entries), *sorted(set(entries))),
                alignment=4,
            )
            surface.pack_into(
                "<II", header_offset + pointer_offset,
                surface.va(table_offset), len(set(entries)),
            )
            relocations.add(surface.rva(header_offset + pointer_offset))
        else:
            surface.pack_into("<II", header_offset + pointer_offset, 0, 0)
    return (surface.rva(header_offset), directory_size), relocations


def _compose_relocations(
    surface: _Surface, relocations: set[int]
) -> tuple[int, int]:
    encoded = bytearray()
    pages: dict[int, list[int]] = {}
    for rva in sorted(relocations):
        pages.setdefault(rva & ~0xFFF, []).append((_HIGHLOW << 12) | (rva & 0xFFF))
    for page, entries in sorted(pages.items()):
        values = sorted(set(entries))
        if len(values) % 2:
            values.append(0)
        encoded.extend(struct.pack("<II", page, 8 + len(values) * 2))
        encoded.extend(struct.pack("<" + "H" * len(values), *values))
    offset = surface.append(bytes(encoded), alignment=4)
    return surface.rva(offset), len(encoded)


def _append_section_header(
    image: bytearray,
    pe: pefile.PE,
    *,
    rva: int,
    virtual_size: int,
    raw_pointer: int,
    raw_size: int,
) -> None:
    section_table = pe.sections[0].get_file_offset()
    count = int(pe.FILE_HEADER.NumberOfSections)
    header_offset = section_table + count * 40
    if header_offset + 40 > int(pe.OPTIONAL_HEADER.SizeOfHeaders):
        raise PE32ModuleCompositionError(
            "PE headers have no room for the loader-surface section"
        )
    if any(image[header_offset : header_offset + 40]):
        raise PE32ModuleCompositionError("loader-surface section header overlaps data")
    struct.pack_into(
        "<8sIIIIIIHHI", image, header_offset, b".spxldr\0",
        virtual_size, rva, raw_size, raw_pointer, 0, 0, 0, 0,
        _SECTION_CHARACTERISTICS,
    )
    struct.pack_into(
        "<H", image, pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
        count + 1,
    )


def _ensure_section_header_capacity(image: bytearray, pe: pefile.PE) -> bool:
    """Grow packed PE headers without changing any RVA or loader-visible bytes."""

    section_table = pe.sections[0].get_file_offset()
    required_end = section_table + (int(pe.FILE_HEADER.NumberOfSections) + 1) * 40
    old_headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
    if required_end <= old_headers:
        return False
    file_alignment = int(pe.OPTIONAL_HEADER.FileAlignment)
    new_headers = _align_up(required_end, file_alignment)
    first_raw = min(
        int(section.PointerToRawData)
        for section in pe.sections
        if int(section.SizeOfRawData) != 0
    )
    if first_raw < old_headers:
        raise PE32ModuleCompositionError(
            "section raw data begins inside the declared PE headers"
        )
    insertion = first_raw
    growth = new_headers - old_headers
    if growth <= 0:
        raise PE32ModuleCompositionError("PE header growth is not positive")
    image[insertion:insertion] = b"\0" * growth
    for section in pe.sections:
        for field in (
            "PointerToRawData",
            "PointerToRelocations",
            "PointerToLinenumbers",
        ):
            value = int(getattr(section, field))
            if value >= insertion and value != 0:
                struct.pack_into(
                    "<I", image, section.get_field_absolute_offset(field),
                    value + growth,
                )
    symbol_table = int(pe.FILE_HEADER.PointerToSymbolTable)
    if symbol_table >= insertion and symbol_table != 0:
        struct.pack_into(
            "<I", image,
            pe.FILE_HEADER.get_field_absolute_offset("PointerToSymbolTable"),
            symbol_table + growth,
        )
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    security_offset = int(security.VirtualAddress)
    if security_offset >= insertion and security_offset != 0:
        struct.pack_into(
            "<I", image, security.get_field_absolute_offset("VirtualAddress"),
            security_offset + growth,
        )
    struct.pack_into(
        "<I", image,
        pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfHeaders"),
        new_headers,
    )
    return True


def _update_optional_header(
    image: bytearray,
    pe: pefile.PE,
    *,
    section_rva: int,
    virtual_size: int,
    raw_size: int,
    entry_rva: int,
    directories: Mapping[int, tuple[int, int]],
) -> None:
    optional = pe.OPTIONAL_HEADER
    struct.pack_into(
        "<I", image, optional.get_field_absolute_offset("AddressOfEntryPoint"),
        entry_rva,
    )
    struct.pack_into(
        "<I", image, optional.get_field_absolute_offset("SizeOfImage"),
        _align_up(section_rva + virtual_size, int(optional.SectionAlignment)),
    )
    struct.pack_into(
        "<I", image, optional.get_field_absolute_offset("SizeOfInitializedData"),
        int(optional.SizeOfInitializedData) + raw_size,
    )
    for index, value in directories.items():
        offset = optional.DATA_DIRECTORY[index].get_file_offset()
        struct.pack_into("<II", image, offset, *value)
    for index in (4, 10, 11, 12):
        if index not in directories:
            offset = optional.DATA_DIRECTORY[index].get_file_offset()
            struct.pack_into("<II", image, offset, 0, 0)


def _module_entry_rva(
    plan: Mapping[str, Any], linked: Mapping[str, int]
) -> int:
    entries = [
        row for row in plan["ingresses"]
        if row["role"] in {"process_entry", "dll_entry"}
    ]
    if not entries:
        return 0
    if len(entries) != 1 or entries[0]["bridge_symbol"] not in linked:
        raise PE32ModuleCompositionError("module entry ingress is ambiguous or unlinked")
    return linked[entries[0]["bridge_symbol"]]


def _require_pe32(pe: pefile.PE) -> None:
    if int(pe.FILE_HEADER.Machine) != 0x14C or int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
        raise PE32ModuleCompositionError("module composer requires IA-32 PE32")
    if len(pe.sections) >= 96:
        raise PE32ModuleCompositionError("candidate already has the PE loader section limit")


def _closed(path: Path, expected: str, digest_field: str) -> dict[str, Any]:
    payload = _object(path, expected)
    if payload.get("format") != expected:
        raise PE32ModuleCompositionError(f"unsupported {expected} artifact")
    core = {key: value for key, value in payload.items() if key != digest_field}
    if payload.get(digest_field) != canonical_sha256_v3(core):
        raise PE32ModuleCompositionError(f"stale {expected} artifact")
    return dict(payload)


def _object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PE32ModuleCompositionError(f"cannot read {label}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise PE32ModuleCompositionError(f"{label} must be an object")
    return payload


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


__all__ = ["PE32ModuleCompositionError", "compose_pe32_native_module"]
