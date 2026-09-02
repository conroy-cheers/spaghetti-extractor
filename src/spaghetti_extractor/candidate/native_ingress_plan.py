# ruff: noqa: F401
"""Derived native-ingress planning, link receipts, and module deployment receipts."""

from __future__ import annotations

import json
import re
import struct
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    BOUNDARY_LIFECYCLE_V1_FORMAT,
    BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
    CHECKED_CALL_PROTOCOL_V2_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
    PHYSICAL_CALL_FRAME_V3_FORMAT,
)
from ..semantic_objects.object_authority import (
    MachineObjectAuthorityV2,
    derive_pe32_machine_object_authority_v2,
)
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..calls._canonical import CallProtocolError
from ..calls.frame import PhysicalCallFrameV2
from ..pe32.behavioral_roots import (
    BEHAVIORAL_ROOTS_FORMAT,
    behavioral_roots_sha256,
)
from ..pe32.formats import (
    PE32_MODULE_INTERFACE_FORMAT,
)
from ..transfer.plan import load_executable_transfer_plan
from ..transfer.model import TransferPlanError
from ..semantic_link.formats import LINKED_SEMANTIC_MODULE_V2_FORMAT
from ..semantic_link.module_v2 import (
    LinkedSemanticModuleV2,
    linked_execution_view_v2,
)
from ..util import sha256_file, write_json
from .formats import (
    NATIVE_INGRESS_PLAN_FORMAT,
)
from .outcomes import (
    CheckedBoundaryOutcomeProtocolV1,
    CheckedSEHProtocolV1,
    PinnedCodeLayoutAuthorityV2,
)
from .native_ingress_runtime import (
    boundary_lifecycle_transducer_v1,
    PRIVATE_STACK_SLICE_BYTES,
    MINIMUM_RUNTIME_CONTROL_BYTES,
    exact_tls_regions,
    physical_frame_transducer_v1,
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
    "tls_private_stack_v1",
    "transactional_boundary_writeback_v1",
)
_BEHAVIORAL_ROOT_CONSTRAINTS = {
    "original_binary_executed": False,
    "strict_export_parsing_required": True,
    "strict_tls_parsing_required": True,
    "tls_callback_inventory_immutable": True,
    "roots_in_exactly_one_executable_section": True,
}


def _linked_behavioral_roots_projection(
    linked: LinkedSemanticModuleV2,
    interface: Mapping[str, Any],
) -> dict[str, Any]:
    """Recreate the exact loader-root view from one checked linked package."""

    roots: list[dict[str, Any]] = []
    loader = interface["loader"]
    entry_rva = int(loader["entry_rva"])
    if entry_rva:
        roots.append({
            "kind": "pe_entrypoint",
            "identity": "pe-entrypoint",
            "rva": entry_rva,
        })
    for slot in interface["export_directory"]["slots"]:
        if slot["kind"] != "code":
            continue
        for name in list(slot["names"]) or [None]:
            roots.append({
                "kind": "pe_export",
                "identity": (
                    f"pe-export:ordinal:{slot['ordinal']}:name:"
                    + (str(name) if name is not None else "<ordinal-only>")
                ),
                "rva": int(slot["rva"]),
                "ordinal": int(slot["ordinal"]),
                "name": name,
            })
    tls = interface["tls"]
    if tls is not None:
        for callback in tls["callbacks"]:
            order = int(callback["order"])
            roots.append({
                "kind": "pe_tls_callback",
                "identity": f"pe-tls-callback:index:{order}",
                "rva": int(callback["rva"]),
                "callback_index": order,
            })
    kind_order = {"pe_entrypoint": 0, "pe_export": 1, "pe_tls_callback": 2}
    roots.sort(key=lambda row: (
        kind_order[str(row["kind"])],
        int(
            row.get("ordinal", row.get("callback_index", 0))
        ),
        str(row["identity"]),
    ))
    linked_loader_roots = {
        (str(row["kind"]), int(row["original_rva"]))
        for row in linked.payload["roots"]
        if row.get("origin") == "module_interface"
        and row.get("kind") not in {"data_export", "forwarder"}
    }
    projected_loader_roots = {
        (
            {
                "pe_entrypoint": str(loader["entry_kind"]),
                "pe_export": "export",
                "pe_tls_callback": "tls_callback",
            }[str(row["kind"])],
            int(row["rva"]),
        )
        for row in roots
    }
    if linked_loader_roots != projected_loader_roots:
        raise NativeIngressError(
            "linked semantic roots disagree with the decoded loader surface"
        )
    counts = {kind: 0 for kind in kind_order}
    for row in roots:
        counts[str(row["kind"])] += 1
    core = {
        "format": BEHAVIORAL_ROOTS_FORMAT,
        "status": "complete",
        "authority": "independent_exact_pe_metadata",
        "pe": {
            "sha256": interface["identity"]["pe_sha256"],
            "file_size": int(interface["identity"]["file_size"]),
            "machine": "i386",
            "bitness": 32,
            "image_base": int(loader["preferred_base"]),
            "size_of_image": int(loader["image_size"]),
            "entrypoint_rva": entry_rva,
        },
        "roots": roots,
        "counts": {"roots": len(roots), **counts},
        "constraints": dict(_BEHAVIORAL_ROOT_CONSTRAINTS),
    }
    return {**core, "contract_sha256": behavioral_roots_sha256(core)}



from .native_ingress_values import (
    _parse_ingress_authority,
    _checked_descriptor,
    _load_closed,
    _validate_module_interface_hash,
    _load_format,
    _object,
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


def _write_native_ingress_plan_v2(
    *,
    module_interface: Path,
    behavioral_roots: Path,
    object_authority: Path,
    transfer_plan: Path,
    execution_closure: Path | Mapping[str, Any],
    resolved_external_environment: Path,
    pinned_layout_authorities: Sequence[Mapping[str, Any]] = (),
    runtime_tls_bytes: int = 0,
    private_stack_size: int | None = None,
    out: Path,
) -> dict[str, Any]:
    """Derive every loader/native entry from exact module and checked ABI authority."""

    interface_path = Path(module_interface)
    roots_path = Path(behavioral_roots)
    object_path = Path(object_authority)
    environment_path = Path(resolved_external_environment)
    interface = _load_format(interface_path, PE32_MODULE_INTERFACE_FORMAT, "module interface")
    _validate_module_interface_hash(interface)
    roots = _load_format(roots_path, BEHAVIORAL_ROOTS_FORMAT, "behavioral roots")
    authority = MachineObjectAuthorityV2.parse(_object(object_path, "machine object authority V2"))
    environment = _load_format(
        environment_path,
        RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
        "resolved external environment",
    )
    parsed_pinned_layouts = {
        row.authority_id: row
        for row in (
            PinnedCodeLayoutAuthorityV2.parse(item)
            for item in pinned_layout_authorities
        )
    }
    if len(parsed_pinned_layouts) != len(pinned_layout_authorities):
        raise NativeIngressError(
            "pinned code layout authority IDs are duplicated"
        )
    if roots.get("status") != "complete":
        raise NativeIngressError("behavioral roots are not complete")
    pe_binding = roots.get("pe")
    if not isinstance(pe_binding, Mapping) or pe_binding.get("sha256") != interface.get("identity", {}).get("pe_sha256"):
        raise NativeIngressError("behavioral roots and module interface bind different images")
    interface_sha256 = sha256_file(interface_path)
    object_bindings = authority.bindings
    if object_bindings.get("module_interface_sha256") != interface_sha256:
        raise NativeIngressError("machine object authority does not bind the exact module interface")

    (
        derived_authorities,
        derived_outcomes,
        derived_seh,
        derivation_blockers,
        compact_callbacks,
    ) = (
        _derive_ingress_authorities(
            interface=interface,
            roots=roots,
            transfer_plan=Path(transfer_plan),
            execution_closure=execution_closure,
            resolved_external_environment=environment_path,
            pinned_layout_authorities=tuple(parsed_pinned_layouts.values()),
        )
    )
    parsed_outcomes = {
        row.protocol_id: row
        for row in (
            CheckedBoundaryOutcomeProtocolV1.parse(item)
            for item in derived_outcomes
        )
    }
    if len(parsed_outcomes) != len(derived_outcomes):
        raise NativeIngressError("outcome protocol IDs are duplicated")
    parsed_seh = {
        row.protocol_id: row
        for row in (CheckedSEHProtocolV1.parse(item) for item in derived_seh)
    }
    if len(parsed_seh) != len(derived_seh):
        raise NativeIngressError("SEH protocol IDs are duplicated")
    try:
        transfer_payload, _ = load_executable_transfer_plan(
            Path(transfer_plan), require_complete=True
        )
    except (OSError, TransferPlanError) as exc:
        raise NativeIngressError(
            f"cannot resolve checked SEH unwind effects: {exc}"
        ) from exc
    transfer_rvas = {
        str(row["identity"]): int(row["source"]["rva_start"])
        for row in transfer_payload["transfers"]
    }
    transfer_units_by_rva = {
        int(row["source"]["rva_start"]): str(row["identity"])
        for row in transfer_payload["transfers"]
    }
    closure_payload = (
        dict(execution_closure)
        if isinstance(execution_closure, Mapping)
        else dict(_object(Path(execution_closure), "module execution closure"))
    )
    reachable_unit_ids = {
        str(row["unit_id"])
        for row in closure_payload.get("reachable_units", [])
        if isinstance(row, Mapping) and isinstance(row.get("unit_id"), str)
    }
    for protocol in parsed_seh.values():
        authority_id = protocol.pinned_layout_authority_id
        if authority_id is not None:
            pinned_authority = parsed_pinned_layouts.get(authority_id)
            if pinned_authority is None:
                raise NativeIngressError(
                    "SEH protocol names an unknown pinned code layout authority"
                )
            if not set(protocol.observed_address_fields) <= set(
                pinned_authority.observed_fields
            ):
                raise NativeIngressError(
                    "pinned code layout authority does not cover every observed SEH address field"
                )
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
    referenced_pinned_layouts = {
        protocol.pinned_layout_authority_id
        for protocol in parsed_seh.values()
        if protocol.pinned_layout_authority_id is not None
    }
    unused_pinned_layouts = sorted(
        set(parsed_pinned_layouts) - referenced_pinned_layouts
    )
    if unused_pinned_layouts:
        blockers.append({
            "category": "pinned_code_layout_authority_unreferenced",
            "authority_ids": unused_pinned_layouts,
        })
    original_pe_sha256 = interface.get("identity", {}).get("pe_sha256")
    environment_sha256 = environment.get("resolved_environment_sha256")
    preferred_base = interface.get("loader", {}).get("preferred_base")
    for authority_id in sorted(referenced_pinned_layouts):
        pinned_authority = parsed_pinned_layouts[authority_id]
        if pinned_authority.original_module_sha256 != original_pe_sha256:
            blockers.append({
                "category": "pinned_code_layout_original_module_mismatch",
                "authority_id": authority_id,
            })
        if (
            pinned_authority.resolved_external_environment_sha256
            != environment_sha256
        ):
            blockers.append({
                "category": "pinned_code_layout_environment_mismatch",
                "authority_id": authority_id,
            })
        if pinned_authority.required_image_base != preferred_base:
            blockers.append({
                "category": "pinned_code_layout_required_base_mismatch",
                "authority_id": authority_id,
                "required": pinned_authority.required_image_base,
                "preferred": preferred_base,
            })
    for protocol in parsed_outcomes.values():
        if protocol.nonlocal_protocol_ids:
            blockers.append({
                "category": "native_ingress_nonlocal_dispatch_unsupported",
                "outcome_protocol_id": protocol.protocol_id,
                "nonlocal_protocol_ids": list(protocol.nonlocal_protocol_ids),
            })
    unwind_effects: dict[str, int] = {}
    for protocol in parsed_seh.values():
        for issue in protocol.issues:
            blockers.append({
                "category": "checked_seh_protocol_incomplete",
                "seh_protocol_id": protocol.protocol_id,
                "issue": issue,
            })
        if protocol.handler_rva is not None and (
            protocol.projections["exception_record"]
            or protocol.projections["context"]
        ) and protocol.resumption_rva is None:
            blockers.append({
                "category": (
                    "native_ingress_exception_object_materialization_unavailable"
                ),
                "seh_protocol_id": protocol.protocol_id,
                "required_authority": "checked_guest_resumption",
                "exception_record_fields": list(
                    protocol.projections["exception_record"]
                ),
                "context_fields": list(protocol.projections["context"]),
            })
        if protocol.resumption_unit_id is not None:
            resumption_rva = transfer_rvas.get(protocol.resumption_unit_id)
            if (
                resumption_rva != protocol.resumption_rva
                or protocol.resumption_unit_id not in reachable_unit_ids
            ):
                blockers.append({
                    "category": "native_ingress_exception_resumption_unresolved",
                    "seh_protocol_id": protocol.protocol_id,
                    "resumption_unit_id": protocol.resumption_unit_id,
                    "resumption_rva": protocol.resumption_rva,
                })
        for effect_id in protocol.unwind_effect_ids:
            effect_rva = transfer_rvas.get(effect_id)
            if effect_rva is None or effect_id not in reachable_unit_ids:
                blockers.append({
                    "category": "native_ingress_unwind_effect_unresolved",
                    "seh_protocol_id": protocol.protocol_id,
                    "unwind_effect_id": effect_id,
                })
                continue
            unwind_effects[effect_id] = effect_rva

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
    bridge_class_by_key = {
        key: "native-bridge-equivalence-v1:" + canonical_sha256_v3({
            "target_rva": key[0],
            "target_unit_id": key[1],
            "physical_frame_equivalence_class": key[2],
        })
        for key in bridge_keys
    }
    bridge_by_key = {
        key: f"spx_ingress_{index:04d}" for index, key in enumerate(bridge_keys)
    }
    for descriptor in descriptors:
        key = (
            descriptor["target_rva"], descriptor["target_unit_id"],
            descriptor["bridge_equivalence_class"],
        )
        descriptor["logical_image_id"] = interface["image_id"]
        descriptor["bridge_symbol"] = bridge_by_key[key]
        descriptor["bridge_equivalence_class"] = bridge_class_by_key[key]
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
        max(stack_reserve, PRIVATE_STACK_SLICE_BYTES)
        if private_stack_size is None else private_stack_size
    )
    if (
        not isinstance(selected_stack, int)
        or isinstance(selected_stack, bool)
        or selected_stack <= 0
    ):
        raise NativeIngressError("private stack size is invalid")
    if selected_stack < stack_reserve:
        blockers.append({
            "category": "private_private_stack_below_original_reserve",
            "required": stack_reserve,
            "selected": selected_stack,
        })
    if selected_stack < PRIVATE_STACK_SLICE_BYTES:
        blockers.append({
            "category": "private_private_stack_below_ingress_frame_slice",
            "required": PRIVATE_STACK_SLICE_BYTES,
            "selected": selected_stack,
        })
    if not isinstance(runtime_tls_bytes, int) or isinstance(runtime_tls_bytes, bool) or runtime_tls_bytes < 0:
        raise NativeIngressError("runtime TLS byte count is invalid")
    target_tls_size = 0 if interface["tls"] is None else int(interface["tls"]["template_size"]) + int(interface["tls"]["zero_fill_size"])
    alignment = 16
    runtime_offset = (target_tls_size + alignment - 1) // alignment * alignment
    runtime_control_bytes = max(runtime_tls_bytes, MINIMUM_RUNTIME_CONTROL_BYTES)
    private_stack_offset = (
        runtime_control_bytes + alignment - 1
    ) // alignment * alignment
    combined_runtime_bytes = private_stack_offset + selected_stack
    compact_callback_target_rvas = {
        int(target_rva)
        for domain in compact_callbacks["domains"]
        for target_rva in domain["target_rvas"]
    }
    all_code_target_rvas = set(target_frames) | compact_callback_target_rvas
    code_registry = []
    for target_rva in sorted(all_code_target_rvas):
        rows = [row for row in descriptors if row["target_rva"] == target_rva]
        target_unit_id = (
            rows[0]["target_unit_id"]
            if rows else transfer_units_by_rva[target_rva]
        )
        code_registry.append({
            "id": "native-code-target:" + canonical_sha256_v3({
                "module": interface["image_id"],
                "rva": target_rva,
                "unit": target_unit_id,
            }),
            "logical_image_id": interface["image_id"],
            "rva": target_rva,
            "target_unit_id": target_unit_id,
            "bridge_symbol": (
                rows[0]["bridge_symbol"]
                if rows and len(target_frames[target_rva]) == 1 else None
            ),
        })
    used_seh_ids = {
        seh_id
        for descriptor in descriptors
        for seh_id in parsed_outcomes[
            descriptor["outcome_protocol_id"]
        ].seh_protocol_ids
    }
    used_seh_ids.update(
        seh_id
        for domain in compact_callbacks["domains"]
        for group in domain["outcome_groups"]
        for seh_id in parsed_outcomes[
            group["outcome_protocol_id"]
        ].seh_protocol_ids
    )
    needs_exception_escape = any(
        parsed_seh[seh_id].handler_rva is None
        and parsed_seh[seh_id].escape_disposition != "terminate_process_root"
        for seh_id in used_seh_ids
    )
    support_imports = []
    if needs_exception_escape:
        support_rows = environment.get("generated_runtime_support_imports")
        matches = (
            []
            if not isinstance(support_rows, list)
            else [
                row for row in support_rows
                if isinstance(row, Mapping)
                and row.get("support") == "exception_escape"
            ]
        )
        if (
            len(matches) != 1
            or not isinstance(matches[0].get("identity"), Mapping)
            or matches[0].get("contract") is None
            or matches[0].get("boundary") is None
        ):
            blockers.append({
                "category": "native_ingress_exception_escape_support_missing",
            })
        else:
            identity = matches[0]["identity"]
            support_imports.append({
                "dll": identity.get("dll"),
                "symbol": identity.get("symbol"),
                "ordinal": identity.get("ordinal"),
                "purpose": "checked_exception_escape",
                "ownership": "runtime_support",
            })
    support_symbols = [{
        "symbol": "spx_native_tls_index_cell_pointer",
        "kind": "loader_realized_data_pointer",
        "target": "tls_index_cell_va",
        "width_bytes": 4,
        "relocation_kind": "pe32_highlow",
    }, {
        "symbol": "spx_native_module_base_pointer",
        "kind": "loader_realized_data_pointer",
        "target": "module_base_va",
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
    if compact_callbacks["domains"]:
        runtime_features.append("compact_callback_domains_v1")
    if any(
        descriptor["lifecycle_transducer"].get("bindings")
        for descriptor in descriptors
    ) or any(
        domain["lifecycle_protocol"].get("bindings")
        for domain in compact_callbacks["domains"]
    ):
        runtime_features.append("physical_boundary_lifecycle_transducer_v1")
    if any(
        row["lifecycle_protocol"].get("kind")
        == "reviewed_pe32_loader_lifecycle_v1"
        for row in descriptors
    ):
        runtime_features.append("loader_lifecycle_generations_v1")
    if parsed_seh:
        runtime_features.extend((
            "checked_seh_gateway_v1",
            "exceptional_outcome_dispatch_v1",
            "seh_unwind_frame_cleanup_v1",
        ))
    if any(
        parsed_seh[seh_id].handler_rva is None
        and parsed_seh[seh_id].escape_disposition == "terminate_process_root"
        for seh_id in used_seh_ids
    ):
        runtime_features.append("checked_process_root_termination_v1")
    if any(
        protocol.handler_rva is not None
        and protocol.resumption_rva is not None
        and (
            protocol.projections["exception_record"]
            or protocol.projections["context"]
        )
        for protocol in parsed_seh.values()
    ):
        runtime_features.append("checked_exception_object_resumption_v1")
    if unwind_effects:
        runtime_features.append("checked_transfer_unwind_effects_v1")
    callback_bridge_families: dict[str, dict[str, Any]] = {}
    compact_callback_domains: list[dict[str, Any]] = []
    for domain_index, raw_domain in enumerate(compact_callbacks["domains"]):
        domain = dict(raw_domain)
        physical_transducer, physical_issues = physical_frame_transducer_v1(
            domain["physical_frame"]
        )
        if physical_issues:
            raise NativeIngressError(
                "checked compact callback domain lost its physical transducer"
            )
        physical_transducer = {
            **physical_transducer,
            "transducer_sha256": canonical_sha256_v3(physical_transducer),
        }
        lifecycle_protocol = domain["lifecycle_protocol"]
        if lifecycle_protocol.get("format") == BOUNDARY_LIFECYCLE_V1_FORMAT:
            lifecycle_transducer, lifecycle_issues = (
                boundary_lifecycle_transducer_v1(
                    domain["physical_frame"], lifecycle_protocol
                )
            )
            if lifecycle_issues:
                raise NativeIngressError(
                    "checked compact callback domain lost its lifecycle transducer"
                )
        else:
            lifecycle_transducer = {
                "kind": "reviewed-pe32-loader-lifecycle-transducer-v1",
                "physical_frame_id": domain["physical_frame"].get("id"),
                "lifecycle_sha256": canonical_sha256_v3(lifecycle_protocol),
                "bindings": [],
            }
        lifecycle_transducer = {
            **lifecycle_transducer,
            "transducer_sha256": canonical_sha256_v3(lifecycle_transducer),
        }
        transport = domain["physical_frame"]["transport"]
        frame_equivalence = {
            key: value for key, value in transport.items()
            if key not in {"format", "id", "subject", "transfer_kind"}
        }
        family_id = "callback-bridge-family-v1:" + canonical_sha256_v3(
            frame_equivalence
        )
        family = callback_bridge_families.get(family_id)
        if family is None:
            frame = PhysicalCallFrameV2.parse(transport)
            family = {
                "id": family_id,
                "symbol": (
                    "spx_callback_bridge_family_"
                    f"{len(callback_bridge_families):04d}"
                ),
                "cleanup_bytes": frame.stack.cleanup_bytes,
                "physical_frame_ids": [],
                "domain_ids": [],
            }
            callback_bridge_families[family_id] = family
        family["physical_frame_ids"].append(
            str(domain["physical_frame"]["id"])
        )
        family["domain_ids"].append(str(domain["id"]))
        domain.update({
            "physical_transducer": physical_transducer,
            "lifecycle_transducer": lifecycle_transducer,
            "bridge_family_id": family_id,
            "trampoline_table_symbol": (
                f"spx_callback_trampolines_{domain_index:04d}"
            ),
            "trampoline_stride_bytes": 10,
        })
        compact_callback_domains.append(domain)
    for family in callback_bridge_families.values():
        family["physical_frame_ids"] = sorted(set(
            family["physical_frame_ids"]
        ))
        family["domain_ids"] = sorted(set(family["domain_ids"]))
    module_binding = {
        "image_id": interface["image_id"],
        "kind": interface["kind"],
        "image_base": interface["loader"]["preferred_base"],
        "module_interface_sha256": interface_sha256,
        "behavioral_roots_sha256": sha256_file(roots_path),
        "object_authority_sha256": authority.authority_sha256,
        "executable_transfer_plan_sha256": sha256_file(Path(transfer_plan)),
        "resolved_external_environment_sha256": sha256_file(
            environment_path
        ),
    }
    if isinstance(execution_closure, Mapping):
        source_closure = closure_payload.get(
            "source_execution_closure_sha256"
        )
        linked_identity = closure_payload.get(
            "linked_semantic_module_sha256"
        )
        if isinstance(source_closure, str):
            module_binding["module_execution_closure_sha256"] = (
                source_closure
            )
        if isinstance(linked_identity, str):
            module_binding["linked_semantic_module_sha256"] = linked_identity
    else:
        module_binding["module_execution_closure_sha256"] = sha256_file(
            Path(execution_closure)
        )

    core = {
        "format": NATIVE_INGRESS_PLAN_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "module": module_binding,
        "ingresses": descriptors,
        "callback_domains": compact_callback_domains,
        "callback_publications": compact_callbacks["publications"],
        "callback_bridge_families": [
            callback_bridge_families[key]
            for key in sorted(callback_bridge_families)
        ],
        "bridges": [
            {
                "symbol": bridge_by_key[key],
                "target_rva": key[0],
                "target_unit_id": key[1],
                "equivalence_class": bridge_class_by_key[key],
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
        "unwind_effects": [
            {"id": identity, "rva": unwind_effects[identity]}
            for identity in sorted(unwind_effects)
        ],
        "pinned_code_layout_authorities": [
            parsed_pinned_layouts[key].to_payload()
            for key in sorted(parsed_pinned_layouts)
        ],
        "blockers": blockers,
        "policy": {
            "host_threads_are_concurrency_model": True,
            "same_thread_reentrancy": "per_thread_frame_chain",
            "native_function_pointer_equality": "shared_equivalent_bridge",
            "unknown_nonlocal_transfer": "fail_closed",
            "original_numeric_code_addresses": (
                "pinned_by_explicit_authority"
                if parsed_pinned_layouts else "not_promised"
            ),
        },
    }
    payload = {**core, "plan_sha256": canonical_sha256_v3(core)}
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "native-ingress-plan.json", payload)
    return payload


def _write_native_ingress_plan_from_loaded_module(
    *,
    linked: LinkedSemanticModuleV2,
    pinned_layout_authorities: Sequence[Mapping[str, Any]] = (),
    runtime_tls_bytes: int = 0,
    private_stack_size: int | None = None,
    out: Path,
) -> dict[str, Any]:
    """Lower one already validated module without decoding it again.

    The temporary behavioral-root file is a byte-identical compatibility view
    reconstructed from the checked module interface and linked root table. It
    is never a scheduled input or public artifact.
    """

    if linked.payload.get("format") != LINKED_SEMANTIC_MODULE_V2_FORMAT:
        raise NativeIngressError(
            "linked semantic module has an unsupported format"
        )
    semantic = linked.semantic_object
    if semantic is None:
        raise NativeIngressError(
            "native ingress requires the packaged V2 semantic object"
        )
    interface_path = semantic.module_interface_path
    object_authority_path = semantic.machine_object_authority_path
    transfer_plan_path = semantic.transfer_plan_path
    resolved_environment_path = semantic.resolved_external_environment_path
    execution_semantics = linked_execution_view_v2(linked)
    if linked.package_root is None:
        raise NativeIngressError(
            "native ingress requires one packaged linked semantic module"
        )
    interface = _load_format(
        interface_path, PE32_MODULE_INTERFACE_FORMAT, "module interface"
    )
    roots = _linked_behavioral_roots_projection(linked, interface)
    with tempfile.TemporaryDirectory(prefix="spx-linked-ingress-") as temporary:
        roots_path = Path(temporary) / "behavioral-roots.json"
        write_json(roots_path, roots)
        return _write_native_ingress_plan_v2(
            module_interface=interface_path,
            behavioral_roots=roots_path,
            object_authority=object_authority_path,
            transfer_plan=transfer_plan_path,
            execution_closure=execution_semantics,
            resolved_external_environment=resolved_environment_path,
            pinned_layout_authorities=pinned_layout_authorities,
            runtime_tls_bytes=runtime_tls_bytes,
            private_stack_size=private_stack_size,
            out=out,
        )


def write_native_ingress_plan_from_linked_module(
    *,
    linked_semantic_module: Path,
    pinned_layout_authorities: Sequence[Mapping[str, Any]] = (),
    runtime_tls_bytes: int = 0,
    private_stack_size: int | None = None,
    out: Path,
) -> dict[str, Any]:
    """Load one semantic package once and derive realization ingress."""

    linked_path = Path(linked_semantic_module)
    if linked_path.is_dir():
        linked_path = linked_path / "linked-semantic-module.json"
    raw = _object(linked_path, "linked semantic module")
    if raw.get("format") != LINKED_SEMANTIC_MODULE_V2_FORMAT:
        raise NativeIngressError(
            "linked semantic module has an unsupported format"
        )
    linked = LinkedSemanticModuleV2.load(linked_path)
    return _write_native_ingress_plan_from_loaded_module(
        linked=linked,
        pinned_layout_authorities=pinned_layout_authorities,
        runtime_tls_bytes=runtime_tls_bytes,
        private_stack_size=private_stack_size,
        out=out,
    )
