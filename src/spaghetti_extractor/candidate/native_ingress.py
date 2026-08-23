"""Derived native-ingress planning, link receipts, and module deployment receipts."""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    BEHAVIORAL_C_COMPLETION_FORMAT,
    BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT,
    BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
    CHECKED_CALL_PROTOCOL_V2_FORMAT,
    NATIVE_INGRESS_LINK_RECEIPT_FORMAT,
    NATIVE_INGRESS_PLAN_FORMAT,
    PE32_LOADER_SURFACE_RECEIPT_FORMAT,
    PE32_MODULE_DEPLOYMENT_FORMAT,
    PE32_MODULE_INTERFACE_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
    PHYSICAL_CALL_FRAME_V3_FORMAT,
    RELEASE_ACCEPTANCE_FORMAT,
)
from ..components.object_authority import (
    MachineObjectAuthorityV2,
    derive_pe32_machine_object_authority_v2,
)
from ..calls._canonical import CallProtocolError
from ..calls.frame import PhysicalCallFrameV2
from ..pe32.behavioral_roots import BEHAVIORAL_ROOTS_FORMAT
from ..pe32.image import parse_pe_image
from ..util import sha256_file, write_json
from .outcomes import CheckedBoundaryOutcomeProtocolV1, CheckedSEHProtocolV1
from .native_ingress_runtime import (
    ENGINE_STACK_FRAME_BYTES,
    MINIMUM_RUNTIME_CONTROL_BYTES,
    exact_tls_regions,
)
from .native_ingress_errors import NativeIngressError
from .native_ingress_derivation import (
    _derive_ingress_authorities,
    _root_specs,
)


_ROLES = frozenset({"process_entry", "dll_entry", "tls_callback", "export", "callback"})
_BASE_RUNTIME_FEATURES = (
    "code_capability_registry_v1",
    "host_thread_concurrency_v1",
    "loader_lock_safe_bootstrap_v1",
    "outgoing_bridge_pe_tls_state_v1",
    "per_thread_ingress_frame_chain_v1",
    "same_thread_reentrancy_v1",
    "tls_private_engine_stack_v1",
    "transactional_boundary_writeback_v1",
)


def write_pe32_machine_object_authority_v2(
    *,
    module_interface: Path,
    out: Path,
    refinements: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    interface_path = Path(module_interface)
    interface = _load_format(interface_path, PE32_MODULE_INTERFACE_FORMAT, "module interface")
    _validate_module_interface_hash(interface)
    authority = derive_pe32_machine_object_authority_v2(
        module_interface=interface,
        module_interface_sha256=sha256_file(interface_path),
        refinements=refinements,
    )
    payload = authority.to_payload()
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "machine-object-authority.json", payload)
    return payload


def write_native_ingress_plan(
    *,
    module_interface: Path,
    behavioral_roots: Path,
    object_authority: Path,
    machine_ir: Path,
    root_closure: Path,
    call_protocol_packages: Sequence[Path] = (),
    callback_authority: Path | None = None,
    outcome_protocols: Sequence[Mapping[str, Any]] = (),
    seh_protocols: Sequence[Mapping[str, Any]] = (),
    runtime_tls_bytes: int = 0,
    private_stack_size: int | None = None,
    out: Path,
) -> dict[str, Any]:
    """Derive every loader/native entry from exact module and checked ABI authority."""

    interface_path = Path(module_interface)
    roots_path = Path(behavioral_roots)
    object_path = Path(object_authority)
    interface = _load_format(interface_path, PE32_MODULE_INTERFACE_FORMAT, "module interface")
    _validate_module_interface_hash(interface)
    roots = _load_format(roots_path, BEHAVIORAL_ROOTS_FORMAT, "behavioral roots")
    authority = MachineObjectAuthorityV2.parse(_object(object_path, "machine object authority V2"))
    if roots.get("status") != "complete":
        raise NativeIngressError("behavioral roots are not complete")
    pe_binding = roots.get("pe")
    if not isinstance(pe_binding, Mapping) or pe_binding.get("sha256") != interface.get("identity", {}).get("pe_sha256"):
        raise NativeIngressError("behavioral roots and module interface bind different images")
    interface_sha256 = sha256_file(interface_path)
    object_bindings = authority.bindings
    if object_bindings.get("module_interface_sha256") != interface_sha256:
        raise NativeIngressError("machine object authority does not bind the exact module interface")

    derived_authorities, derived_outcomes, derivation_blockers = (
        _derive_ingress_authorities(
            interface=interface,
            roots=roots,
            machine_ir=Path(machine_ir),
            root_closure=Path(root_closure),
            call_protocol_packages=tuple(Path(item) for item in call_protocol_packages),
            callback_authority=(
                None if callback_authority is None else Path(callback_authority)
            ),
            outcome_protocols=outcome_protocols,
        )
    )
    all_outcomes = (*outcome_protocols, *derived_outcomes)
    parsed_outcomes = {
        row.protocol_id: row
        for row in (CheckedBoundaryOutcomeProtocolV1.parse(item) for item in all_outcomes)
    }
    if len(parsed_outcomes) != len(all_outcomes):
        raise NativeIngressError("outcome protocol IDs are duplicated")
    parsed_seh = {
        row.protocol_id: row
        for row in (CheckedSEHProtocolV1.parse(item) for item in seh_protocols)
    }
    if len(parsed_seh) != len(seh_protocols):
        raise NativeIngressError("SEH protocol IDs are duplicated")
    for protocol in parsed_outcomes.values():
        missing = set(protocol.seh_protocol_ids) - set(parsed_seh)
        if missing:
            raise NativeIngressError(f"outcome protocol names unknown SEH protocols: {sorted(missing)!r}")

    root_specs = _root_specs(interface, roots)
    provided = [
        _parse_ingress_authority(item, index=index)
        for index, item in enumerate(derived_authorities)
    ]
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in provided:
        key = (row["role"], row["target_rva"], row["capability_id"] or "")
        if key in by_key:
            raise NativeIngressError(f"duplicate native ingress authority {key!r}")
        by_key[key] = row

    blockers: list[dict[str, Any]] = [
        *(dict(item) for item in interface.get("blockers", [])),
        *derivation_blockers,
    ]
    descriptors: list[dict[str, Any]] = []
    expected_keys: set[tuple[str, int, str]] = set()
    for spec in root_specs:
        key = (spec["role"], spec["target_rva"], "")
        expected_keys.add(key)
        authority_row = by_key.get(key)
        if authority_row is None:
            blockers.append({
                "category": "ingress_authority_missing",
                "role": spec["role"],
                "target_rva": spec["target_rva"],
            })
            continue
        descriptors.append(_checked_descriptor(spec, authority_row, parsed_outcomes, blockers))
    for row in provided:
        if row["role"] != "callback":
            continue
        if row["capability_id"] is None:
            blockers.append({"category": "callback_capability_identity_missing", "target_rva": row["target_rva"]})
            continue
        key = ("callback", row["target_rva"], row["capability_id"])
        expected_keys.add(key)
        descriptors.append(_checked_descriptor({
            "role": "callback",
            "target_rva": row["target_rva"],
            "root_ids": row["root_ids"],
            "exports": [],
            "capability_id": row["capability_id"],
            "capability_lifetime": row["capability_lifetime"],
            "tls_order": None,
        }, row, parsed_outcomes, blockers))
    extras = sorted(set(by_key) - expected_keys)
    if extras:
        blockers.append({"category": "ingress_authority_not_reachable", "identities": [list(row) for row in extras]})

    target_frames: dict[int, set[str]] = {}
    for descriptor in descriptors:
        target_frames.setdefault(descriptor["target_rva"], set()).add(descriptor["bridge_equivalence_class"])
    for target_rva, frames in sorted(target_frames.items()):
        if len(frames) > 1:
            blockers.append({
                "category": "incompatible_ingress_physical_abi",
                "target_rva": target_rva,
                "bridge_equivalence_classes": sorted(frames),
            })
        units = {
            row["target_unit_id"] for row in descriptors
            if row["target_rva"] == target_rva
        }
        if len(units) > 1:
            blockers.append({
                "category": "ingress_target_unit_ambiguous",
                "target_rva": target_rva,
                "target_unit_ids": sorted(units),
            })
    bridge_keys = sorted({
        (row["target_rva"], row["target_unit_id"], row["bridge_equivalence_class"])
        for row in descriptors
    })
    bridge_by_key = {
        key: f"spx_ingress_{index:04d}" for index, key in enumerate(bridge_keys)
    }
    for descriptor in descriptors:
        descriptor["logical_image_id"] = interface["image_id"]
        descriptor["bridge_symbol"] = bridge_by_key[
            (
                descriptor["target_rva"], descriptor["target_unit_id"],
                descriptor["bridge_equivalence_class"],
            )
        ]
        descriptor["id"] = "native-ingress:" + canonical_sha256_v3({
            key: value for key, value in descriptor.items() if key != "id"
        })
    descriptors.sort(key=lambda row: (row["target_rva"], row["role"], row["capability_id"] or ""))

    export_directory = interface["export_directory"]
    data_slots = [dict(row) for row in export_directory["slots"] if row["kind"] == "data"]
    forwarders = [dict(row) for row in export_directory["slots"] if row["kind"] == "forwarder"]
    anchors_by_alias = {
        (alias["name"], alias["ordinal"]): anchor
        for anchor in authority.data_export_anchors
        for alias in anchor.aliases
    }
    data_anchors: dict[str, dict[str, Any]] = {}
    for slot in data_slots:
        aliases = [{"name": name, "ordinal": slot["ordinal"]} for name in slot["names"]] or [
            {"name": None, "ordinal": slot["ordinal"]}
        ]
        matched_rows = [
            anchors_by_alias.get((alias["name"], alias["ordinal"]))
            for alias in aliases
        ]
        matches = {
            anchor.identity: anchor for anchor in matched_rows if anchor is not None
        }
        if len(matches) != 1:
            blockers.append({
                "category": "data_export_anchor_missing_or_ambiguous",
                "ordinal": slot["ordinal"],
                "rva": slot["rva"],
            })
            continue
        anchor = next(iter(matches.values()))
        if any(anchors_by_alias.get((alias["name"], alias["ordinal"])) != anchor for alias in aliases):
            blockers.append({"category": "data_export_alias_anchor_conflict", "ordinal": slot["ordinal"]})
            continue
        rule = next(row for row in authority.rules if row.identity == anchor.rule_id)
        data_anchors[anchor.identity] = {
            **anchor.to_payload(),
            "locator": rule.locator.to_payload(),
            "object_extent": rule.extent,
            "object_permissions": rule.permissions,
            "available_extent": rule.extent - anchor.byte_offset,
        }

    stack_reserve = int(interface["loader"]["stack"]["reserve"])
    selected_stack = (
        max(stack_reserve, ENGINE_STACK_FRAME_BYTES)
        if private_stack_size is None else private_stack_size
    )
    if (
        not isinstance(selected_stack, int)
        or isinstance(selected_stack, bool)
        or selected_stack <= 0
    ):
        raise NativeIngressError("private engine stack size is invalid")
    if selected_stack < stack_reserve:
        blockers.append({
            "category": "private_engine_stack_below_original_reserve",
            "required": stack_reserve,
            "selected": selected_stack,
        })
    if selected_stack < ENGINE_STACK_FRAME_BYTES:
        blockers.append({
            "category": "private_engine_stack_below_ingress_frame_slice",
            "required": ENGINE_STACK_FRAME_BYTES,
            "selected": selected_stack,
        })
    if not isinstance(runtime_tls_bytes, int) or isinstance(runtime_tls_bytes, bool) or runtime_tls_bytes < 0:
        raise NativeIngressError("runtime TLS byte count is invalid")
    target_tls_size = 0 if interface["tls"] is None else int(interface["tls"]["template_size"]) + int(interface["tls"]["zero_fill_size"])
    alignment = 16
    runtime_offset = (target_tls_size + alignment - 1) // alignment * alignment
    runtime_control_bytes = max(runtime_tls_bytes, MINIMUM_RUNTIME_CONTROL_BYTES)
    engine_stack_offset = (
        runtime_control_bytes + alignment - 1
    ) // alignment * alignment
    combined_runtime_bytes = engine_stack_offset + selected_stack
    code_registry = []
    for target_rva in sorted(target_frames):
        rows = [row for row in descriptors if row["target_rva"] == target_rva]
        code_registry.append({
            "id": "native-code-target:" + canonical_sha256_v3({
                "module": interface["image_id"],
                "rva": target_rva,
                "unit": rows[0]["target_unit_id"],
            }),
            "logical_image_id": interface["image_id"],
            "rva": target_rva,
            "target_unit_id": rows[0]["target_unit_id"],
            "bridge_symbol": rows[0]["bridge_symbol"] if len(target_frames[target_rva]) == 1 else None,
        })
    support_imports = []
    if any("exceptional" in parsed_outcomes[row["outcome_protocol_id"]].outcomes for row in descriptors):
        support_imports.append({
            "dll": "kernel32.dll", "symbol": "RaiseException", "ordinal": None,
            "purpose": "checked_exception_escape", "ownership": "runtime_support",
        })
    support_symbols = [{
        "symbol": "spx_native_tls_index_cell_pointer",
        "kind": "loader_realized_data_pointer",
        "target": "tls_index_cell_va",
        "width_bytes": 4,
        "relocation_kind": "pe32_highlow",
    }]
    if support_imports:
        support_symbols.append({
            "symbol": "spx_native_raise_exception_iat_pointer",
            "kind": "loader_realized_data_pointer",
            "target": "runtime_support_iat_va:checked_exception_escape",
            "width_bytes": 4,
            "relocation_kind": "pe32_highlow",
        })
    runtime_features = list(_BASE_RUNTIME_FEATURES)
    if parsed_seh:
        runtime_features.extend((
            "checked_seh_gateway_v1",
            "exceptional_outcome_dispatch_v1",
            "seh_unwind_frame_cleanup_v1",
        ))
    core = {
        "format": NATIVE_INGRESS_PLAN_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "module": {
            "image_id": interface["image_id"],
            "kind": interface["kind"],
            "module_interface_sha256": interface_sha256,
            "behavioral_roots_sha256": sha256_file(roots_path),
            "object_authority_sha256": authority.authority_sha256,
        },
        "ingresses": descriptors,
        "bridges": [
            {
                "symbol": bridge_by_key[key],
                "target_rva": key[0],
                "target_unit_id": key[1],
                "equivalence_class": key[2],
            }
            for key in bridge_keys
        ],
        "support_symbols": support_symbols,
        "code_target_registry": code_registry,
        "data_export_anchors": [data_anchors[key] for key in sorted(data_anchors)],
        "forwarders": forwarders,
        "tls_layout": {
            "target_template_bytes": 0 if interface["tls"] is None else interface["tls"]["template_size"],
            "target_zero_fill_bytes": 0 if interface["tls"] is None else interface["tls"]["zero_fill_size"],
            "runtime_offset": runtime_offset,
            "runtime_bytes": combined_runtime_bytes,
            "runtime_control_bytes": runtime_control_bytes,
            "runtime_regions": exact_tls_regions(
                control_bytes=runtime_control_bytes,
                stack_bytes=selected_stack,
            ),
            "alignment": alignment,
            "private_stack_bytes": selected_stack,
            "index_policy": "reuse_target_or_generate",
            "callback_policy": "replace_with_ingress_bridges_in_original_order",
        },
        "required_support_imports": support_imports,
        "runtime_requirements": {
            "features": sorted(runtime_features),
            "private_stack_bytes": selected_stack,
            "runtime_tls_bytes": combined_runtime_bytes,
            "state_model": "immutable_tables_shared_state_pe_tls_thread_state_v1",
        },
        "load_config_requirements": interface["load_config"],
        "outcome_protocols": [
            parsed_outcomes[key].to_payload() for key in sorted(parsed_outcomes)
        ],
        "seh_protocols": [parsed_seh[key].to_payload() for key in sorted(parsed_seh)],
        "blockers": blockers,
        "policy": {
            "host_threads_are_concurrency_model": True,
            "same_thread_reentrancy": "per_thread_frame_chain",
            "native_function_pointer_equality": "shared_equivalent_bridge",
            "unknown_nonlocal_transfer": "fail_closed",
            "original_numeric_code_addresses": "not_promised",
        },
    }
    payload = {**core, "plan_sha256": canonical_sha256_v3(core)}
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "native-ingress-plan.json", payload)
    return payload


def write_native_ingress_link_receipt(
    *,
    native_ingress_plan: Path,
    linked_module: Path,
    linker_map: Path | None = None,
    out: Path,
) -> dict[str, Any]:
    """Bind every generated bridge, exception portal, and support symbol to one RVA."""

    plan_path = Path(native_ingress_plan)
    plan = _load_closed(plan_path, NATIVE_INGRESS_PLAN_FORMAT, "native ingress plan", "plan_sha256")
    if plan.get("status") != "complete":
        raise NativeIngressError("cannot link an incomplete native ingress plan")
    required = {row["symbol"] for row in plan["bridges"]}
    gateway_symbols = {
        protocol["gateway_handler_symbol"]
        for protocol in plan.get("seh_protocols", [])
    }
    required.update(gateway_symbols)
    for protocol in plan.get("seh_protocols", []):
        symbols_for_protocol = {
            row["candidate_symbol"] for row in protocol["portals"]
        }
        required.update(symbols_for_protocol)
    support_symbols = {
        row["symbol"]: row for row in plan.get("support_symbols", [])
    }
    required.update(support_symbols)
    symbols = _linked_symbol_rvas(
        linked_module=Path(linked_module),
        required=required,
        linker_map=None if linker_map is None else Path(linker_map),
    )
    if set(symbols) != required:
        raise NativeIngressError(
            f"linked symbol inventory differs: missing={sorted(required - set(symbols))!r}, extra={sorted(set(symbols) - required)!r}"
        )
    normalized: list[dict[str, Any]] = []
    seen_rvas: dict[int, str] = {}
    frame_by_symbol = {
        row["bridge_symbol"]: row["physical_frame_id"] for row in plan["ingresses"]
    }
    linked_path = Path(linked_module)
    parsed = parse_pe_image(linked_path)
    try:
        if parsed.machine != "i386" or parsed.bitness != 32:
            raise NativeIngressError("native ingress link receipt requires IA-32 PE32")
        for symbol in sorted(symbols):
            rva = symbols[symbol]
            if not isinstance(rva, int) or isinstance(rva, bool) or not 0 <= rva <= 0xFFFFFFFF:
                raise NativeIngressError(f"linked symbol {symbol!r} has an invalid RVA")
            if rva in seen_rvas:
                raise NativeIngressError(
                    f"linked symbols {seen_rvas[rva]!r} and {symbol!r} alias one RVA"
                )
            is_support = symbol in support_symbols
            containing = [
                (index, section) for index, section in enumerate(parsed.sections)
                if ((not section.executable) if is_support else section.executable)
                and section.rva_start <= rva < section.rva_end
            ]
            if len(containing) != 1:
                raise NativeIngressError(
                    f"linked symbol {symbol!r} is not in exactly one "
                    f"{'non-executable mapped' if is_support else 'executable'} section"
                )
            seen_rvas[rva] = symbol
            normalized.append({
                "symbol": symbol,
                "rva": rva,
                "section_index": containing[0][0],
                "physical_frame_id": frame_by_symbol.get(symbol),
                "kind": (
                    "ingress_bridge" if symbol in frame_by_symbol
                    else "seh_gateway" if symbol in gateway_symbols
                    else "runtime_support_data" if is_support
                    else "exception_portal"
                ),
            })
    finally:
        parsed.pe.close()
    core = {
        "format": NATIVE_INGRESS_LINK_RECEIPT_FORMAT,
        "status": "complete",
        "native_ingress_plan_sha256": sha256_file(plan_path),
        "native_ingress_plan_id": plan["plan_sha256"],
        "linked_module_sha256": sha256_file(linked_path),
        "symbols": normalized,
    }
    payload = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "native-ingress-link-receipt.json", payload)
    return payload


def _linked_symbol_rvas(
    *, linked_module: Path, required: set[str], linker_map: Path | None
) -> dict[str, int]:
    """Read symbol RVAs from the actual linked image or its emitted map."""

    values: dict[str, set[int]] = {name: set() for name in required}

    def record(raw_name: str, value: int) -> None:
        candidates = (raw_name, raw_name[1:] if raw_name.startswith("_") else "")
        for name in candidates:
            if name in values:
                values[name].add(value)

    pe = pefile.PE(str(linked_module), fast_load=True)
    try:
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        pointer = int(pe.FILE_HEADER.PointerToSymbolTable)
        count = int(pe.FILE_HEADER.NumberOfSymbols)
        data = pe.__data__
        string_base = pointer + count * 18
        index = 0
        while pointer and index < count:
            offset = pointer + index * 18
            if offset + 18 > len(data):
                raise NativeIngressError("linked COFF symbol table is truncated")
            name_bytes = bytes(data[offset : offset + 8])
            if name_bytes[:4] == b"\0\0\0\0":
                string_offset = struct.unpack_from("<I", name_bytes, 4)[0]
                start = string_base + string_offset
                end = data.find(b"\0", start)
                if start < string_base + 4 or end < start:
                    raise NativeIngressError("linked COFF string table is malformed")
                name = bytes(data[start:end]).decode("ascii", errors="strict")
            else:
                name = name_bytes.split(b"\0", 1)[0].decode("ascii", errors="strict")
            value, section_number = struct.unpack_from("<Ih", data, offset + 8)
            auxiliary = int(data[offset + 17])
            if 1 <= section_number <= len(pe.sections):
                record(name, int(pe.sections[section_number - 1].VirtualAddress) + value)
            index += 1 + auxiliary
    finally:
        pe.close()

    if linker_map is not None:
        try:
            lines = linker_map.read_text(encoding="utf-8", errors="strict").splitlines()
        except (OSError, UnicodeError) as exc:
            raise NativeIngressError(f"cannot read linked module map: {exc}") from exc
        pattern = re.compile(
            r"^\s*(?:0x)?([0-9A-Fa-f]{8,16})\s+(_?[A-Za-z][A-Za-z0-9_@$?]*)\b"
        )
        for line in lines:
            match = pattern.match(line)
            if match is None:
                continue
            address = int(match.group(1), 16)
            rva = address - image_base if address >= image_base else address
            if 0 <= rva <= 0xFFFFFFFF:
                record(match.group(2), rva)

    ambiguous = {name: sorted(rows) for name, rows in values.items() if len(rows) > 1}
    missing = sorted(name for name, rows in values.items() if not rows)
    if missing or ambiguous:
        raise NativeIngressError(
            f"linked symbol evidence is incomplete: missing={missing!r}, "
            f"ambiguous={ambiguous!r}"
        )
    return {name: next(iter(values[name])) for name in sorted(values)}


def write_pe32_loader_surface_receipt(
    *,
    original_module_interface: Path,
    native_ingress_plan: Path,
    native_ingress_link_receipt: Path,
    composition_manifest: Path,
    candidate_module: Path,
    candidate_module_interface: Path,
    out: Path,
) -> dict[str, Any]:
    """Check the composed binary's loader surface against exact ingress authority."""

    original_path = Path(original_module_interface)
    plan_path = Path(native_ingress_plan)
    link_path = Path(native_ingress_link_receipt)
    candidate_path = Path(candidate_module)
    candidate_interface_path = Path(candidate_module_interface)
    composition_path = Path(composition_manifest)
    original = _load_format(
        original_path, PE32_MODULE_INTERFACE_FORMAT, "original module interface"
    )
    _validate_module_interface_hash(original)
    plan = _load_closed(
        plan_path, NATIVE_INGRESS_PLAN_FORMAT, "native ingress plan", "plan_sha256"
    )
    link = _load_closed(
        link_path, NATIVE_INGRESS_LINK_RECEIPT_FORMAT,
        "native ingress link receipt", "receipt_sha256",
    )
    candidate = _load_format(
        candidate_interface_path, PE32_MODULE_INTERFACE_FORMAT,
        "candidate module interface",
    )
    _validate_module_interface_hash(candidate)
    composition = _object(composition_path, "PE composition manifest")
    blockers: list[dict[str, Any]] = []
    if (
        composition.get("format") != PE_COMPOSITION_MANIFEST_FORMAT
        or composition.get("status") != "composed"
    ):
        blockers.append({"category": "loader_surface_composition_manifest_invalid"})
    hashes = composition.get("hashes")
    if composition.get("format") == PE_COMPOSITION_MANIFEST_FORMAT and (
        not isinstance(hashes, Mapping)
        or hashes.get("algorithm") != "sha256"
        or hashes.get("manifest_core_sha256")
        != canonical_sha256_v3({
            key: value for key, value in composition.items() if key != "hashes"
        })
    ):
        blockers.append({"category": "loader_surface_composition_manifest_stale"})
    if plan.get("module", {}).get("module_interface_sha256") != sha256_file(
        original_path
    ):
        blockers.append({"category": "loader_surface_ingress_interface_mismatch"})
    if link.get("native_ingress_plan_sha256") != sha256_file(plan_path):
        blockers.append({"category": "loader_surface_link_receipt_stale"})
    if candidate.get("image_id") != original.get("image_id"):
        blockers.append({"category": "loader_surface_image_identity_mismatch"})
    if candidate.get("kind") != original.get("kind"):
        blockers.append({"category": "loader_surface_module_kind_mismatch"})
    candidate_sha256 = sha256_file(candidate_path)
    composed = composition.get("candidate")
    if (
        not isinstance(composed, Mapping)
        or composed.get("sha256") != candidate_sha256
        or composed.get("path") != candidate_path.name
    ):
        blockers.append({"category": "loader_surface_composition_hash_mismatch"})
    composition_inputs = composition.get("inputs")
    if (
        "anchors" in composition
        or isinstance(composition_inputs, Mapping)
        and composition_inputs.get("executable_anchor_manifest") is not None
    ):
        blockers.append({"category": "legacy_executable_anchor_composition"})

    linked = {
        row["symbol"]: row["rva"] for row in link.get("symbols", [])
        if isinstance(row, Mapping)
        and isinstance(row.get("symbol"), str)
        and isinstance(row.get("rva"), int)
    }
    module_entries = [
        row for row in plan.get("ingresses", [])
        if row.get("role") in {"process_entry", "dll_entry"}
    ]
    expected_entry = 0
    if module_entries:
        if len(module_entries) != 1:
            blockers.append({"category": "loader_surface_module_entry_ambiguous"})
        else:
            expected_entry = linked.get(module_entries[0]["bridge_symbol"], -1)
    observed_entry = candidate.get("loader", {}).get("entry_rva")
    if observed_entry != expected_entry:
        blockers.append({
            "category": "loader_surface_entrypoint_mismatch",
            "expected": expected_entry,
            "observed": observed_entry,
        })

    _check_export_surface(original, candidate, plan, linked, blockers)
    _check_tls_surface(original, candidate, plan, linked, blockers)
    _check_import_surface(original, candidate, plan, blockers)
    _check_load_config_surface(candidate, plan, linked, blockers)
    _check_runtime_support_symbols(
        candidate, composition, plan, linked, blockers
    )
    for row in candidate.get("directories", []):
        if (
            isinstance(row, Mapping)
            and row.get("name") == "bound_import"
            and (row.get("rva") or row.get("size"))
        ):
            blockers.append({"category": "stale_bound_import_metadata"})

    core = {
        "format": PE32_LOADER_SURFACE_RECEIPT_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "image_id": original["image_id"],
        "candidate": {
            "filename": candidate_path.name,
            "sha256": candidate_sha256,
            "module_interface_sha256": sha256_file(candidate_interface_path),
        },
        "bindings": {
            "original_module_interface_sha256": sha256_file(original_path),
            "native_ingress_plan_sha256": sha256_file(plan_path),
            "native_ingress_link_receipt_sha256": sha256_file(link_path),
            "composition_manifest_sha256": sha256_file(composition_path),
        },
        "blockers": blockers,
        "counts": {
            "export_slots": original["export_directory"]["slot_count"],
            "tls_callbacks": sum(
                row.get("role") == "tls_callback"
                for row in plan.get("ingresses", [])
            ),
            "original_import_slots": len(original.get("imports", [])),
            "runtime_support_imports": len(plan.get("required_support_imports", [])),
            "blockers": len(blockers),
        },
    }
    payload = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "loader-surface-receipt.json", payload)
    return payload


def write_pe32_module_deployment(
    *,
    original_module_interface: Path,
    behavioral_c_completion: Path,
    native_ingress_plan: Path,
    native_ingress_link_receipt: Path,
    exact_runtime_qualification: Path,
    loader_surface_receipt: Path,
    candidate_static_assurance: Path,
    candidate_module: Path,
    candidate_module_interface: Path,
    out: Path,
) -> dict[str, Any]:
    """Close one candidate module only after every implementation and loader receipt agrees."""

    paths = {
        "original_interface": Path(original_module_interface),
        "behavioral_c_completion": Path(behavioral_c_completion),
        "ingress_plan": Path(native_ingress_plan),
        "link_receipt": Path(native_ingress_link_receipt),
        "exact_runtime_qualification": Path(exact_runtime_qualification),
        "loader_surface": Path(loader_surface_receipt),
        "static_assurance": Path(candidate_static_assurance),
        "candidate_interface": Path(candidate_module_interface),
    }
    original = _load_format(paths["original_interface"], PE32_MODULE_INTERFACE_FORMAT, "original module interface")
    _validate_module_interface_hash(original)
    behavioral = _load_format(paths["behavioral_c_completion"], BEHAVIORAL_C_COMPLETION_FORMAT, "behavioral-C completion")
    plan = _load_closed(paths["ingress_plan"], NATIVE_INGRESS_PLAN_FORMAT, "native ingress plan", "plan_sha256")
    link = _load_closed(paths["link_receipt"], NATIVE_INGRESS_LINK_RECEIPT_FORMAT, "native ingress link receipt", "receipt_sha256")
    runtime = _load_format(paths["exact_runtime_qualification"], BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT, "exact runtime qualification")
    loader_surface = _load_closed(
        paths["loader_surface"], PE32_LOADER_SURFACE_RECEIPT_FORMAT,
        "PE32 loader surface receipt", "receipt_sha256",
    )
    assurance = _object(paths["static_assurance"], "candidate static assurance")
    candidate_interface = _load_format(paths["candidate_interface"], PE32_MODULE_INTERFACE_FORMAT, "candidate module interface")
    _validate_module_interface_hash(candidate_interface)
    blockers: list[dict[str, Any]] = []
    if (
        assurance.get("format") != RELEASE_ACCEPTANCE_FORMAT
        or assurance.get("status") != "complete"
        or assurance.get("executable") is not True
        or assurance.get("release_accepted") is not True
    ):
        blockers.append({
            "category": "deployment_candidate_static_assurance_invalid"
        })
    for label, artifact in (
        ("original_module_interface", original), ("behavioral_c_completion", behavioral),
        ("native_ingress_plan", plan), ("native_ingress_link_receipt", link),
        ("exact_runtime_qualification", runtime),
        ("loader_surface", loader_surface),
        ("candidate_static_assurance", assurance), ("candidate_module_interface", candidate_interface),
    ):
        if artifact.get("status") not in {
            "complete", "qualified", "ready", "accepted", "composed",
            "candidate-generated",
        }:
            blockers.append({"category": "deployment_dependency_incomplete", "dependency": label, "observed": artifact.get("status")})
    if plan.get("module", {}).get("module_interface_sha256") != sha256_file(paths["original_interface"]):
        blockers.append({"category": "deployment_ingress_interface_mismatch"})
    if link.get("native_ingress_plan_sha256") != sha256_file(paths["ingress_plan"]):
        blockers.append({"category": "deployment_link_receipt_stale"})
    if behavioral.get("runtime_qualification_sha256") != sha256_file(
        paths["exact_runtime_qualification"]
    ):
        blockers.append({"category": "deployment_exact_runtime_binding_mismatch"})
    owned_units_raw = behavioral.get("owned_units")
    owned_units = (
        {
            row.get("id"): row.get("rva_start")
            for row in owned_units_raw
            if isinstance(row, Mapping)
        }
        if isinstance(owned_units_raw, list)
        else {}
    )
    for ingress in plan.get("ingresses", []):
        unit_id = ingress.get("target_unit_id")
        target_rva = ingress.get("target_rva")
        if owned_units.get(unit_id) != target_rva:
            blockers.append({
                "category": "deployment_behavioral_unit_missing",
                "ingress_id": ingress.get("id"),
                "target_unit_id": unit_id,
                "target_rva": target_rva,
            })
    runtime_requirements = plan.get("runtime_requirements")
    if not isinstance(runtime_requirements, Mapping):
        blockers.append({"category": "deployment_runtime_requirements_missing"})
    else:
        expected_features = set(runtime_requirements.get("features", []))
        observed_features = runtime.get("qualified_native_ingress_features")
        if not isinstance(observed_features, list) or any(
            not isinstance(item, str) for item in observed_features
        ):
            observed_features = []
        missing_features = sorted(expected_features - set(observed_features))
        if missing_features:
            blockers.append({
                "category": "deployment_native_ingress_runtime_unqualified",
                "missing_features": missing_features,
            })
        if runtime.get("native_ingress_plan_sha256") != sha256_file(
            paths["ingress_plan"]
        ):
            blockers.append({
                "category": "deployment_runtime_ingress_plan_mismatch"
            })
        qualified_stack = runtime.get("qualified_private_stack_bytes")
        required_stack = runtime_requirements.get("private_stack_bytes")
        if (
            not isinstance(qualified_stack, int)
            or isinstance(qualified_stack, bool)
            or not isinstance(required_stack, int)
            or qualified_stack < required_stack
        ):
            blockers.append({
                "category": "deployment_runtime_private_stack_unqualified",
                "required": required_stack,
                "qualified": qualified_stack,
            })
    if candidate_interface.get("image_id") != original.get("image_id"):
        blockers.append({"category": "deployment_candidate_image_identity_mismatch"})
    candidate_path = Path(candidate_module)
    candidate_sha256 = sha256_file(candidate_path)
    composed_candidate = loader_surface.get("candidate")
    if (
        not isinstance(composed_candidate, Mapping)
        or composed_candidate.get("sha256") != candidate_sha256
    ):
        blockers.append({"category": "deployment_loader_surface_candidate_hash_mismatch"})
    loader_bindings = loader_surface.get("bindings")
    expected_loader_bindings = {
        "original_module_interface_sha256": sha256_file(
            paths["original_interface"]
        ),
        "native_ingress_plan_sha256": sha256_file(paths["ingress_plan"]),
        "native_ingress_link_receipt_sha256": sha256_file(
            paths["link_receipt"]
        ),
    }
    if not isinstance(loader_bindings, Mapping) or any(
        loader_bindings.get(key) != value
        for key, value in expected_loader_bindings.items()
    ):
        blockers.append({"category": "deployment_loader_surface_binding_mismatch"})
    if (
        not isinstance(composed_candidate, Mapping)
        or composed_candidate.get("module_interface_sha256")
        != sha256_file(paths["candidate_interface"])
    ):
        blockers.append({
            "category": "deployment_loader_surface_interface_mismatch"
        })
    assurance_bindings = assurance.get("bindings")
    if (
        not isinstance(assurance_bindings, Mapping)
        or assurance_bindings.get("candidate_sha256") != candidate_sha256
    ):
        blockers.append({"category": "deployment_static_assurance_candidate_hash_mismatch"})
    if candidate_interface.get("identity", {}).get("pe_sha256") != candidate_sha256:
        blockers.append({"category": "deployment_candidate_interface_hash_mismatch"})
    core = {
        "format": PE32_MODULE_DEPLOYMENT_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "image_id": original["image_id"],
        "module_kind": original["kind"],
        "candidate": {
            "filename": candidate_path.name,
            "sha256": candidate_sha256,
            "decoded_loader_surface_sha256": sha256_file(paths["candidate_interface"]),
        },
        "bindings": {
            key: {"filename": value.name, "sha256": sha256_file(value)}
            for key, value in sorted(paths.items())
        },
        "original_identity": dict(original["identity"]),
        "decoded_loader_surface": {
            "kind": candidate_interface["kind"],
            "loader": candidate_interface["loader"],
            "export_directory": candidate_interface["export_directory"],
            "tls": candidate_interface["tls"],
            "imports": candidate_interface["imports"],
            "load_config": candidate_interface["load_config"],
        },
        "blockers": blockers,
        "definition_of_complete": (
            "behavioral C, exact runtime, native ingress, linked loader surface, "
            "static assurance, and decoded candidate module all agree"
        ),
    }
    payload = {**core, "deployment_sha256": canonical_sha256_v3(core)}
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "module-deployment.json", payload)
    return payload


def _check_export_surface(
    original: Mapping[str, Any],
    candidate: Mapping[str, Any],
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
    blockers: list[dict[str, Any]],
) -> None:
    expected = original["export_directory"]
    observed = candidate["export_directory"]
    for field in ("dll_name", "ordinal_base", "slot_count", "holes", "name_table"):
        if observed.get(field) != expected.get(field):
            blockers.append({
                "category": "loader_surface_export_geometry_mismatch",
                "field": field,
            })
    ingresses = plan.get("ingresses", [])
    data_anchors = plan.get("data_export_anchors", [])
    expected_slots = expected.get("slots", [])
    observed_slots = observed.get("slots", [])
    if len(observed_slots) != len(expected_slots):
        return
    for source, target in zip(expected_slots, observed_slots, strict=True):
        ordinal = source["ordinal"]
        if (
            target.get("slot_index") != source.get("slot_index")
            or target.get("ordinal") != ordinal
            or target.get("names") != source.get("names")
        ):
            blockers.append({
                "category": "loader_surface_export_slot_identity_mismatch",
                "ordinal": ordinal,
            })
            continue
        kind = source["kind"]
        expected_rva: int | None
        if kind == "hole":
            expected_rva = 0
        elif kind == "forwarder":
            expected_rva = None
            if (
                target.get("kind") != "forwarder"
                or target.get("forwarder") != source.get("forwarder")
            ):
                blockers.append({
                    "category": "loader_surface_forwarder_mismatch",
                    "ordinal": ordinal,
                })
            continue
        elif kind == "data":
            aliases = {(name, ordinal) for name in source.get("names", [])} or {
                (None, ordinal)
            }
            anchors = [
                row for row in data_anchors
                if aliases <= {
                    (alias.get("name"), alias.get("ordinal"))
                    for alias in row.get("aliases", [])
                }
            ]
            if len(anchors) != 1:
                blockers.append({
                    "category": "loader_surface_data_anchor_missing",
                    "ordinal": ordinal,
                })
                continue
            locator = anchors[0].get("locator")
            expected_rva = (
                int(locator["rva"]) + int(anchors[0]["byte_offset"])
                if isinstance(locator, Mapping)
                and locator.get("kind") == "image_rva"
                and isinstance(locator.get("rva"), int)
                else -1
            )
            if expected_rva != source["rva"]:
                blockers.append({
                    "category": "loader_surface_data_anchor_source_mismatch",
                    "ordinal": ordinal,
                    "source_rva": source["rva"],
                    "anchor_rva": expected_rva,
                })
        else:
            providers = [
                row for row in ingresses
                if row.get("role") == "export"
                and any(
                    alias.get("ordinal") == ordinal
                    for alias in row.get("exports", [])
                )
            ]
            if len(providers) != 1:
                blockers.append({
                    "category": "loader_surface_code_ingress_missing",
                    "ordinal": ordinal,
                })
                continue
            expected_rva = linked.get(providers[0]["bridge_symbol"], -1)
        if target.get("kind") != kind or target.get("rva") != expected_rva:
            blockers.append({
                "category": "loader_surface_export_target_mismatch",
                "ordinal": ordinal,
                "expected_kind": kind,
                "expected_rva": expected_rva,
                "observed_kind": target.get("kind"),
                "observed_rva": target.get("rva"),
            })


def _check_tls_surface(
    original: Mapping[str, Any],
    candidate: Mapping[str, Any],
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
    blockers: list[dict[str, Any]],
) -> None:
    source = original.get("tls")
    observed = candidate.get("tls")
    layout = plan["tls_layout"]
    runtime_bytes = layout["runtime_bytes"]
    tls_ingresses = sorted(
        (
            row for row in plan.get("ingresses", [])
            if row.get("role") == "tls_callback"
        ),
        key=lambda row: row["tls_order"],
    )
    needs_tls = source is not None or runtime_bytes != 0 or bool(tls_ingresses)
    if not needs_tls:
        if observed is not None:
            blockers.append({"category": "loader_surface_unexpected_tls"})
        return
    if not isinstance(observed, Mapping):
        blockers.append({"category": "loader_surface_tls_missing"})
        return
    source_template = b"" if source is None else bytes.fromhex(
        source["template_data_hex"]
    )
    observed_template = bytes.fromhex(observed["template_data_hex"])
    if not observed_template.startswith(source_template):
        blockers.append({"category": "loader_surface_tls_template_mismatch"})
    source_total = 0 if source is None else (
        source["template_size"] + source["zero_fill_size"]
    )
    required_total = (
        source_total
        if runtime_bytes == 0
        else layout["runtime_offset"] + runtime_bytes
    )
    observed_total = observed["template_size"] + observed["zero_fill_size"]
    if observed_total != required_total:
        blockers.append({
            "category": "loader_surface_tls_extent_mismatch",
            "expected": required_total,
            "observed": observed_total,
        })
    if observed.get("index_rva") is None:
        blockers.append({"category": "loader_surface_tls_index_missing"})
    expected_callbacks = [
        {"order": index, "rva": linked.get(row["bridge_symbol"], -1)}
        for index, row in enumerate(tls_ingresses)
    ]
    if observed.get("callbacks") != expected_callbacks:
        blockers.append({
            "category": "loader_surface_tls_callback_mismatch",
            "expected": expected_callbacks,
            "observed": observed.get("callbacks"),
        })


def _check_import_surface(
    original: Mapping[str, Any],
    candidate: Mapping[str, Any],
    plan: Mapping[str, Any],
    blockers: list[dict[str, Any]],
) -> None:
    def identity(row: Mapping[str, Any]) -> tuple[Any, ...]:
        return row.get("iat_rva"), row.get("dll"), row.get("symbol"), row.get("ordinal")

    source = {identity(row) for row in original.get("imports", [])}
    observed = {identity(row) for row in candidate.get("imports", [])}
    if not source <= observed:
        blockers.append({
            "category": "loader_surface_original_import_slot_mismatch",
            "missing": sorted(source - observed, key=str),
        })
    extras = observed - source
    support = {
        (row.get("dll"), row.get("symbol"), row.get("ordinal"))
        for row in plan.get("required_support_imports", [])
    }
    extra_requests = {(row[1], row[2], row[3]) for row in extras}
    if extra_requests != support:
        blockers.append({
            "category": "loader_surface_runtime_support_import_mismatch",
            "expected": sorted(support, key=str),
            "observed": sorted(extra_requests, key=str),
        })
    def delay_requests(value: Mapping[str, Any]) -> list[tuple[Any, ...]]:
        return sorted(
            (
                descriptor.get("dll"), cell.get("symbol"), cell.get("ordinal"),
            )
            for descriptor in value.get("delay_imports", [])
            for cell in descriptor.get("cells", [])
        )
    if delay_requests(original) != delay_requests(candidate):
        blockers.append({"category": "loader_surface_delay_import_mismatch"})


def _check_load_config_surface(
    candidate: Mapping[str, Any],
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
    blockers: list[dict[str, Any]],
) -> None:
    if candidate.get("status") != "complete" or candidate.get("blockers"):
        blockers.append({"category": "decoded_candidate_loader_surface_incomplete"})
    requirements = plan.get("load_config_requirements")
    observed = candidate.get("load_config")
    needs_seh = bool(plan.get("seh_protocols"))
    if requirements is None and observed is None and not needs_seh:
        return
    if not isinstance(observed, Mapping):
        blockers.append({"category": "loader_surface_load_config_missing"})
        return
    safe = observed.get("safe_seh")
    required_gateways = sorted(
        linked.get(protocol["gateway_handler_symbol"], -1)
        for protocol in plan.get("seh_protocols", [])
    )
    if required_gateways:
        if not isinstance(safe, Mapping):
            blockers.append({"category": "loader_surface_safe_seh_missing"})
        elif not set(required_gateways) <= set(safe.get("handler_rvas", [])):
            blockers.append({"category": "loader_surface_safe_seh_gateway_missing"})
    required_cfg = requirements.get("cfg") if isinstance(requirements, Mapping) else None
    if isinstance(required_cfg, Mapping):
        cfg = observed.get("cfg")
        bridge_rvas = {
            linked[row["symbol"]] for row in plan.get("bridges", [])
            if row.get("symbol") in linked
        }
        if not isinstance(cfg, Mapping) or not bridge_rvas <= set(cfg.get("function_rvas", [])):
            blockers.append({"category": "loader_surface_cfg_bridge_missing"})


def _check_runtime_support_symbols(
    candidate: Mapping[str, Any],
    composition: Mapping[str, Any],
    plan: Mapping[str, Any],
    linked: Mapping[str, int],
    blockers: list[dict[str, Any]],
) -> None:
    expected = plan.get("support_symbols", [])
    loader = composition.get("loader_surface")
    observed = (
        loader.get("runtime_support_symbol_realizations")
        if isinstance(loader, Mapping) else None
    )
    if not isinstance(observed, list):
        if expected:
            blockers.append({"category": "loader_surface_runtime_support_symbols_missing"})
        return
    tls = candidate.get("tls")
    index_rva = tls.get("index_rva") if isinstance(tls, Mapping) else None
    import_slots = (
        loader.get("runtime_support_import_slots", [])
        if isinstance(loader, Mapping) else []
    )

    def target_rva(row: Mapping[str, Any]) -> object:
        target = row.get("target")
        if target == "tls_index_cell_va":
            return index_rva
        if isinstance(target, str) and target.startswith("runtime_support_iat_va:"):
            purpose = target.split(":", 1)[1]
            matches = [
                item.get("iat_rva") for item in import_slots
                if isinstance(item, Mapping) and item.get("purpose") == purpose
            ]
            return matches[0] if len(matches) == 1 else None
        return None
    expected_rows = [
        {
            "symbol": row["symbol"],
            "symbol_rva": linked.get(row["symbol"]),
            "value_kind": "va",
            "target_rva": target_rva(row),
            "relocation_rva": linked.get(row["symbol"]),
            "relocation_kind": row["relocation_kind"],
        }
        for row in expected
    ]
    projected = [
        {
            key: row.get(key) for key in (
                "symbol", "symbol_rva", "value_kind", "target_rva",
                "relocation_rva", "relocation_kind",
            )
        }
        for row in observed if isinstance(row, Mapping)
    ]
    if projected != expected_rows:
        blockers.append({
            "category": "loader_surface_runtime_support_symbol_mismatch",
            "expected": expected_rows,
            "observed": projected,
        })


def _parse_ingress_authority(value: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    fields = {
        "role", "target_rva", "target_unit_id", "root_ids", "root_closure_sha256",
        "call_protocol", "physical_frame", "lifecycle_receipt",
        "outcome_protocol_id", "capability_id", "capability_lifetime",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeIngressError(f"ingress authority {index} has invalid fields")
    role = value["role"]
    if role not in _ROLES:
        raise NativeIngressError(f"ingress authority {index} has an invalid role")
    rva = value["target_rva"]
    if not isinstance(rva, int) or isinstance(rva, bool) or not 0 <= rva <= 0xFFFFFFFF:
        raise NativeIngressError(f"ingress authority {index} has an invalid RVA")
    for field in ("target_unit_id", "outcome_protocol_id"):
        if not isinstance(value[field], str) or not value[field]:
            raise NativeIngressError(f"ingress authority {index} {field} is invalid")
    root_ids = value["root_ids"]
    if (
        not isinstance(root_ids, list)
        or not root_ids
        or any(not isinstance(item, str) or not item for item in root_ids)
        or root_ids != sorted(set(root_ids))
    ):
        raise NativeIngressError(f"ingress authority {index} root IDs are invalid")
    if value["capability_id"] is not None and (not isinstance(value["capability_id"], str) or not value["capability_id"]):
        raise NativeIngressError(f"ingress authority {index} capability is invalid")
    lifetime = value["capability_lifetime"]
    if value["role"] == "callback":
        lifetime_kind, separator, end_event = (
            lifetime.partition(":") if isinstance(lifetime, str) else (None, "", "")
        )
        if lifetime_kind not in {
            "during_call",
            "one_shot_or_process_exit",
            "until_replaced_or_process_exit",
            "until_resource_event_or_process_exit",
        }:
            raise NativeIngressError(
                f"ingress authority {index} capability lifetime is invalid"
            )
        if (
            lifetime_kind == "until_resource_event_or_process_exit"
            and (not separator or not end_event)
        ) or (lifetime_kind != "until_resource_event_or_process_exit" and separator):
            raise NativeIngressError(
                f"ingress authority {index} capability lifetime event is invalid"
            )
    elif lifetime is not None:
        raise NativeIngressError(
            f"ingress authority {index} non-callback carries a capability lifetime"
        )
    closure = value["root_closure_sha256"]
    if not isinstance(closure, str) or len(closure) != 64:
        raise NativeIngressError(f"ingress authority {index} root closure is invalid")
    call = value["call_protocol"]
    frame = value["physical_frame"]
    lifecycle = value["lifecycle_receipt"]
    call_fields = {
        "format", "id", "status", "schema_id", "schema_sha256",
        "layout_sha256", "signature_id", "physical_frame_id",
        "evidence_receipt_id", "lifecycle_sha256",
        "lifecycle_receipt_sha256", "projection_sha256",
        "projection_receipt_sha256", "issues",
    }
    if (
        not isinstance(call, Mapping)
        or set(call) != call_fields
        or call.get("format") != CHECKED_CALL_PROTOCOL_V2_FORMAT
        or call.get("status") != "complete"
        or call.get("issues") != []
    ):
        raise NativeIngressError(f"ingress authority {index} lacks a complete checked call protocol")
    call_core = {key: item for key, item in call.items() if key != "id"}
    if call.get("id") != f"checked-call-protocol-v2:{canonical_sha256_v3(call_core)}":
        raise NativeIngressError(f"ingress authority {index} checked call protocol is stale")
    frame_fields = {
        "format", "id", "schema_sha256", "layout_sha256", "signature_id",
        "transport", "bindings", "dialect_rule_ids",
    }
    if (
        not isinstance(frame, Mapping)
        or set(frame) != frame_fields
        or frame.get("format") != PHYSICAL_CALL_FRAME_V3_FORMAT
        or frame.get("id") != call.get("physical_frame_id")
    ):
        raise NativeIngressError(f"ingress authority {index} physical frame is stale")
    try:
        PhysicalCallFrameV2.parse(frame["transport"])
    except CallProtocolError as exc:
        raise NativeIngressError(
            f"ingress authority {index} has an invalid physical transport: {exc}"
        ) from exc
    frame_core = {key: item for key, item in frame.items() if key != "id"}
    if frame.get("id") != f"physical-call-frame-v3:{canonical_sha256_v3(frame_core)}":
        raise NativeIngressError(f"ingress authority {index} physical frame content ID is stale")
    if any(
        call.get(field) != frame.get(field)
        for field in ("schema_sha256", "layout_sha256", "signature_id")
    ):
        raise NativeIngressError(f"ingress authority {index} call/frame bindings disagree")
    lifecycle_fields = {
        "format", "lifecycle_sha256", "status", "obligations",
        "receipt_sha256",
    }
    if (
        not isinstance(lifecycle, Mapping)
        or set(lifecycle) != lifecycle_fields
        or lifecycle.get("format") != BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT
        or lifecycle.get("status") != "complete"
    ):
        raise NativeIngressError(f"ingress authority {index} lifecycle receipt is incomplete")
    lifecycle_core = {
        key: item for key, item in lifecycle.items() if key != "receipt_sha256"
    }
    if lifecycle.get("receipt_sha256") != canonical_sha256_v3(lifecycle_core):
        raise NativeIngressError(f"ingress authority {index} lifecycle receipt is stale")
    if (
        lifecycle.get("lifecycle_sha256") != call.get("lifecycle_sha256")
        or lifecycle.get("receipt_sha256") != call.get("lifecycle_receipt_sha256")
    ):
        raise NativeIngressError(f"ingress authority {index} lifecycle binding disagrees")
    return dict(value)


def _checked_descriptor(
    spec: Mapping[str, Any],
    authority: Mapping[str, Any],
    outcomes: Mapping[str, CheckedBoundaryOutcomeProtocolV1],
    blockers: list[dict[str, Any]],
) -> dict[str, Any]:
    if spec["root_ids"] != authority["root_ids"]:
        blockers.append({"category": "ingress_root_identity_mismatch", "role": spec["role"], "target_rva": spec["target_rva"]})
    outcome_id = authority["outcome_protocol_id"]
    outcome = outcomes.get(outcome_id)
    if outcome is None or outcome.status != "complete":
        blockers.append({"category": "ingress_outcome_protocol_incomplete", "role": spec["role"], "target_rva": spec["target_rva"]})
    frame = authority["physical_frame"]
    transport = PhysicalCallFrameV2.parse(frame["transport"])
    if outcome is not None and not set(transport.outcomes) <= set(outcome.outcomes):
        blockers.append({
            "category": "ingress_transport_outcome_mismatch",
            "role": spec["role"],
            "target_rva": spec["target_rva"],
            "transport_outcomes": list(transport.outcomes),
            "protocol_outcomes": list(outcome.outcomes),
        })
    bridge_core = {
        # Subject and transfer labels express how authority was obtained, not
        # the bytes presented at the native boundary.  Excluding them is what
        # permits a loader entry, export, and escaped callback with an exactly
        # equal physical frame to retain one stable function address.
        "transport": {
            key: value for key, value in frame.get("transport", {}).items()
            if key not in {"format", "id", "subject", "transfer_kind"}
        },
        "bindings": frame.get("bindings"),
        "schema_sha256": frame.get("schema_sha256"),
        "layout_sha256": frame.get("layout_sha256"),
        # A shared native address cannot discover whether the loader, an export
        # lookup, or a callback registration produced the call.  Therefore only
        # behaviorally identical lifecycle/outcome contracts may share it.
        "lifecycle_receipt": authority["lifecycle_receipt"],
        "outcome_protocol_id": outcome_id,
    }
    return {
        "role": spec["role"],
        "logical_image_id": None,
        "target_rva": spec["target_rva"],
        "target_unit_id": authority["target_unit_id"],
        "root_ids": list(spec["root_ids"]),
        "root_closure_sha256": authority["root_closure_sha256"],
        "call_protocol_id": authority["call_protocol"]["id"],
        "call_protocol": dict(authority["call_protocol"]),
        "physical_frame_id": frame["id"],
        "physical_frame": dict(frame),
        "lifecycle_receipt_id": authority["lifecycle_receipt"].get("id") or authority["lifecycle_receipt"].get("receipt_sha256"),
        "lifecycle_receipt": dict(authority["lifecycle_receipt"]),
        "outcome_protocol_id": outcome_id,
        "exports": list(spec["exports"]),
        "capability_id": spec["capability_id"],
        "capability_lifetime": authority["capability_lifetime"],
        "tls_order": spec["tls_order"],
        "bridge_equivalence_class": canonical_sha256_v3(bridge_core),
    }


def _load_closed(path: Path, expected: str, label: str, digest_field: str) -> dict[str, Any]:
    payload = _load_format(path, expected, label)
    if digest_field not in payload:
        raise NativeIngressError(f"{label} has no self hash")
    core = {key: value for key, value in payload.items() if key != digest_field}
    if payload[digest_field] != canonical_sha256_v3(core):
        raise NativeIngressError(f"{label} self hash is stale")
    return payload


def _validate_module_interface_hash(payload: Mapping[str, Any]) -> None:
    core = {key: value for key, value in payload.items() if key != "interface_sha256"}
    if payload.get("interface_sha256") != canonical_sha256_v3(core):
        raise NativeIngressError("module interface self hash is stale")


def _load_format(path: Path, expected: str, label: str) -> dict[str, Any]:
    payload = _object(path, label)
    if payload.get("format") != expected:
        raise NativeIngressError(f"{label} has unsupported format")
    return dict(payload)


def _object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeIngressError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise NativeIngressError(f"{label} must be an object")
    return value


__all__ = [
    "NativeIngressError",
    "write_native_ingress_link_receipt",
    "write_native_ingress_plan",
    "write_pe32_loader_surface_receipt",
    "write_pe32_module_deployment",
    "write_pe32_machine_object_authority_v2",
]
