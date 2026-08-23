"""Derivation of checked native ingress authorities from existing evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
    CHECKED_CALL_PROTOCOL_V2_FORMAT,
    PHYSICAL_CALL_FRAME_V3_FORMAT,
)
from ..calls.frame import PhysicalCallFrameV2
from ..util import sha256_file
from .callback_authority import load_callback_protocol_authority_v1
from .engine_analysis import _adapt_native_machine_ir_unit
from .native_ingress_errors import NativeIngressError
from .outcomes import CheckedBoundaryOutcomeProtocolV1


def _object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeIngressError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise NativeIngressError(f"{label} must be an object")
    return value

def _derive_ingress_authorities(
    *,
    interface: Mapping[str, Any],
    roots: Mapping[str, Any],
    machine_ir: Path,
    root_closure: Path,
    call_protocol_packages: Sequence[Path],
    callback_authority: Path | None,
    outcome_protocols: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, object]], list[dict[str, Any]]]:
    """Derive native entries from loader roots and already checked authorities.

    The two loader-owned PE32 frames are reviewed profiles.  All callable
    exports and callbacks must arrive through the ordinary call-protocol
    checker; there is deliberately no operator-authored ingress JSON escape.
    """

    units: dict[int, str] = {}
    try:
        with machine_ir.open(encoding="utf-8") as source:
            for index, line in enumerate(source):
                if not line.strip():
                    continue
                unit = _adapt_native_machine_ir_unit(json.loads(line), index)
                rva = int(unit["original"]["rva_start"])
                prior = units.setdefault(rva, str(unit["id"]))
                if prior != unit["id"]:
                    raise NativeIngressError(
                        f"machine IR repeats entry RVA 0x{rva:08x}"
                    )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeIngressError(f"cannot read machine IR for ingress derivation: {exc}") from exc

    closure_manifest = root_closure / "manifest.json" if root_closure.is_dir() else root_closure
    if not closure_manifest.is_file():
        raise NativeIngressError("root closure has no exact manifest")
    closure_sha256 = sha256_file(closure_manifest)

    checked_calls: list[dict[str, Any]] = []
    for package in sorted(call_protocol_packages, key=lambda item: str(item)):
        status = _object(package / "call-status.json", "checked call status")
        if status.get("status") != "complete":
            raise NativeIngressError(f"checked call package {package} is incomplete")
        subject = status.get("subject")
        if not isinstance(subject, Mapping):
            raise NativeIngressError(f"checked call package {package} has no subject")
        checked_calls.append({
            "subject": dict(subject),
            "call_protocol": dict(_object(
                package / "checked-call-protocol.json", "checked call protocol"
            )),
            "physical_frame": dict(_object(
                package / "physical-call-frame-v3.json", "physical call frame V3"
            )),
            "lifecycle_receipt": dict(_object(
                package / "boundary-lifecycle-receipt.json",
                "boundary lifecycle receipt",
            )),
        })
    identities = [
        (row["subject"].get("kind"), row["subject"].get("id"))
        for row in checked_calls
    ]
    if len(identities) != len(set(identities)):
        raise NativeIngressError("checked call packages repeat a subject identity")

    blockers: list[dict[str, Any]] = []
    authorities: list[dict[str, Any]] = []
    outcomes: dict[tuple[str, ...], CheckedBoundaryOutcomeProtocolV1] = {}
    supplied_outcomes = tuple(
        CheckedBoundaryOutcomeProtocolV1.parse(item)
        for item in outcome_protocols
    )

    def outcome_for(frame: Mapping[str, Any], role: str) -> CheckedBoundaryOutcomeProtocolV1:
        transport = PhysicalCallFrameV2.parse(frame["transport"])
        kinds = tuple(transport.outcomes)
        matching = [
            item for item in supplied_outcomes if item.outcomes == kinds
        ]
        if len(matching) > 1:
            raise NativeIngressError(
                f"multiple outcome protocols describe physical outcomes {kinds!r}"
            )
        if matching:
            return matching[0]
        unsupported = sorted(set(kinds) & {"exceptional", "nonlocal"})
        if unsupported:
            blockers.append({
                "category": "ingress_outcome_authority_missing",
                "role": role,
                "outcomes": unsupported,
            })
            # Retain a parseable protocol so the normal checker can also expose
            # the exact transport/protocol contradiction.
            kinds = tuple(item for item in kinds if item not in unsupported) or ("normal",)
        key = tuple(sorted(kinds))
        protocol = outcomes.get(key)
        if protocol is None:
            protocol = CheckedBoundaryOutcomeProtocolV1.create(
                outcomes=key,
                normal_projection_id=(
                    "machine-result" if "normal" in key else None
                ),
                no_return_disposition=(
                    "terminate_process" if "no_return" in key else None
                ),
            )
            outcomes[key] = protocol
        return protocol

    def append_authority(
        spec: Mapping[str, Any], checked: Mapping[str, Any]
    ) -> None:
        rva = int(spec["target_rva"])
        unit_id = str(spec.get("target_unit_id") or units.get(rva) or "")
        if not unit_id:
            blockers.append({
                "category": "ingress_target_unit_missing",
                "role": spec["role"],
                "target_rva": rva,
            })
            return
        outcome = outcome_for(checked["physical_frame"], str(spec["role"]))
        authorities.append({
            "role": spec["role"],
            "target_rva": rva,
            "target_unit_id": unit_id,
            "root_ids": list(spec["root_ids"]),
            "root_closure_sha256": closure_sha256,
            "call_protocol": checked["call_protocol"],
            "physical_frame": checked["physical_frame"],
            "lifecycle_receipt": checked["lifecycle_receipt"],
            "outcome_protocol_id": outcome.protocol_id,
            "capability_id": spec.get("capability_id"),
            "capability_lifetime": spec.get("capability_lifetime"),
        })

    for spec in _root_specs(interface, roots):
        role = str(spec["role"])
        if role in {"process_entry", "dll_entry", "tls_callback"}:
            append_authority(spec, _reviewed_loader_call(role, interface["image_id"]))
            continue
        aliases = {
            *(row["name"] for row in spec["exports"] if row["name"] is not None),
            *(f"ordinal:{row['ordinal']}" for row in spec["exports"]),
        }
        matches = [
            row for row in checked_calls
            if row["subject"].get("kind") == "export"
            and row["subject"].get("id") in aliases
            and row["subject"].get("image_selector") in {None, interface["image_id"]}
        ]
        if len(matches) != 1:
            blockers.append({
                "category": "export_call_protocol_missing_or_ambiguous",
                "target_rva": spec["target_rva"],
                "aliases": sorted(aliases),
            })
            continue
        append_authority(spec, matches[0])

    if callback_authority is not None:
        callback_index = load_callback_protocol_authority_v1(callback_authority)
        for callback in callback_index.callbacks:
            protocol_id = callback.protocol.to_value().get("id")
            matches = [
                row for row in checked_calls
                if row["subject"].get("kind") == "callback"
                and row["subject"].get("id") == protocol_id
            ]
            if len(matches) > 1:
                blockers.append({
                    "category": "callback_call_protocol_missing_or_ambiguous",
                    "capability_id": callback.callback_id,
                    "target_rva": callback.target_rva,
                    "protocol_id": protocol_id,
                })
                continue
            checked = (
                matches[0]
                if matches
                else _callback_authority_call(
                    callback=callback,
                    image_id=str(interface["image_id"]),
                    authority_manifest_sha256=callback_index.manifest_sha256,
                )
            )
            append_authority({
                "role": "callback",
                "target_rva": callback.target_rva,
                "target_unit_id": callback.target_unit_id,
                "root_ids": [callback.callback_id],
                "capability_id": callback.callback_id,
                "capability_lifetime": callback.lifetime,
            }, checked)

    return (
        authorities,
        [outcomes[key].to_payload() for key in sorted(outcomes)],
        blockers,
    )


def _reviewed_loader_call(role: str, image_id: str) -> dict[str, Any]:
    if role == "process_entry":
        convention, argument_count, cleanup = "custom", 0, 0
        transfer_kind, result = "direct", False
    elif role == "dll_entry":
        convention, argument_count, cleanup = "stdcall", 3, 12
        transfer_kind, result = "direct", True
    elif role == "tls_callback":
        convention, argument_count, cleanup = "stdcall", 3, 12
        transfer_kind, result = "callback", False
    else:  # pragma: no cover - private caller constrains this
        raise NativeIngressError(f"no reviewed loader frame for {role!r}")

    def slot(identity: str, *, offset: int, slot_role: str) -> dict[str, Any]:
        return {
            "id": identity,
            "role": slot_role,
            "storage_bits": 32,
            "value_bits": 32,
            "pass_mode": "direct",
            "logical_path": [],
            "fragments": [{
                "logical_offset_bits": 0,
                "width_bits": 32,
                "location_offset_bits": 0,
                "representation": "identity",
                "specified": True,
                "location": {
                    "kind": "stack",
                    "phase": "callee_entry",
                    "width_bits": 32,
                    "bank": None,
                    "name": None,
                    "stack_base": "callee-entry-esp-v1",
                    "stack_offset_bytes": offset,
                    "memory_slot": None,
                },
            }],
        }

    arguments = [
        slot(f"arg{index}", offset=4 + 4 * index, slot_role="parameter")
        for index in range(argument_count)
    ]
    results = []
    if result:
        result_slot = slot("result0", offset=0, slot_role="result")
        result_slot["fragments"][0]["location"] = {
            "kind": "register", "phase": "callee_exit", "width_bits": 32,
            "bank": "gpr", "name": "eax", "stack_base": None,
            "stack_offset_bytes": None, "memory_slot": None,
        }
        results.append(result_slot)
    transport = PhysicalCallFrameV2.create(
        subject={"kind": "function", "id": f"pe32-{role}", "image_selector": image_id},
        transfer_kind=transfer_kind,
        target="i686-pc-windows-pe32",
        abi_dialect="pe32-i386-loader-v1",
        calling_convention=convention,
        arguments=arguments,
        results=results,
        stack={
            "coordinate": "callee-entry-esp-v1", "alignment_bytes": 4,
            "cleanup": "custom" if role == "process_entry" else "callee",
            "cleanup_bytes": cleanup, "reserved_bytes": 0,
        },
        preserved_state=("ebp", "ebx", "edi", "esi", "esp"),
        clobbered_state=("eax", "ecx", "edx", "eflags", "st0", "st1"),
        outcomes=("normal",),
    )
    reviewed_profile = {
        "role": role,
        "transport": transport.to_payload(),
        "review": "pe32-loader-entry-profile-v1",
    }
    schema_sha256 = canonical_sha256_v3({"schema": reviewed_profile})
    layout_sha256 = canonical_sha256_v3({"layout": reviewed_profile})
    signature_id = f"pe32-{role}-signature-v1"
    bindings = [
        {
            "slot_id": item["id"],
            "path": {
                "root": "parameter" if item["role"] == "parameter" else "result",
                "value_id": item["id"],
                "fields": [],
            },
            "transport": "semantic",
        }
        for item in (*arguments, *results)
    ]
    frame = {
        "format": PHYSICAL_CALL_FRAME_V3_FORMAT,
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "transport": transport.to_payload(),
        "bindings": bindings,
        "dialect_rule_ids": [f"pe32.loader.{role}.v1"],
    }
    frame["id"] = f"physical-call-frame-v3:{canonical_sha256_v3(frame)}"
    lifecycle = {
        "format": BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
        "lifecycle_sha256": canonical_sha256_v3({
            "role": role, "policy": "loader-owned-lifecycle-v1"
        }),
        "status": "complete",
        "obligations": [{
            "id": f"pe32.loader.{role}.lifecycle",
            "status": "checked",
            "code": "loader_owned_transition_checked",
        }],
    }
    lifecycle["receipt_sha256"] = canonical_sha256_v3(lifecycle)
    protocol = {
        "format": CHECKED_CALL_PROTOCOL_V2_FORMAT,
        "status": "complete",
        "schema_id": f"pe32-{role}-schema-v1",
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "physical_frame_id": frame["id"],
        "evidence_receipt_id": f"reviewed-pe32-loader-frame:{role}:v1",
        "lifecycle_sha256": lifecycle["lifecycle_sha256"],
        "lifecycle_receipt_sha256": lifecycle["receipt_sha256"],
        "projection_sha256": None,
        "projection_receipt_sha256": None,
        "issues": [],
    }
    protocol["id"] = f"checked-call-protocol-v2:{canonical_sha256_v3(protocol)}"
    return {
        "call_protocol": protocol,
        "physical_frame": frame,
        "lifecycle_receipt": lifecycle,
    }


def _callback_authority_call(
    *, callback: Any, image_id: str, authority_manifest_sha256: str
) -> dict[str, Any]:
    """Migrate a complete callback-authority entry frame into call protocol V2."""

    entry = callback.entry_state.to_value()
    abi = entry.get("abi") if isinstance(entry, Mapping) else None
    if not isinstance(abi, Mapping):
        raise NativeIngressError(
            f"callback {callback.callback_id!r} has no checked entry ABI"
        )
    words = abi.get("argument_words")
    cleanup = abi.get("stack_cleanup_bytes")
    template = abi.get("abi_template")
    result_spec = abi.get("result")
    if (
        not isinstance(words, int) or isinstance(words, bool) or words < 0
        or not isinstance(cleanup, int) or isinstance(cleanup, bool)
        or cleanup < 0 or cleanup % 4
        or template not in {"pe32-cdecl-v1", "pe32-stdcall-v1"}
        or not isinstance(result_spec, Mapping)
    ):
        raise NativeIngressError(
            f"callback {callback.callback_id!r} entry ABI is unsupported"
        )

    def slot(identity: str, *, offset: int, role: str) -> dict[str, Any]:
        location = {
            "kind": "stack", "phase": "callee_entry", "width_bits": 32,
            "bank": None, "name": None,
            "stack_base": "callee-entry-esp-v1",
            "stack_offset_bytes": offset, "memory_slot": None,
        }
        if role == "result":
            location = {
                "kind": "register", "phase": "callee_exit", "width_bits": 32,
                "bank": "gpr", "name": "eax", "stack_base": None,
                "stack_offset_bytes": None, "memory_slot": None,
            }
        return {
            "id": identity, "role": role, "storage_bits": 32,
            "value_bits": 32, "pass_mode": "direct", "logical_path": [],
            "fragments": [{
                "logical_offset_bits": 0, "width_bits": 32,
                "location_offset_bits": 0, "representation": "identity",
                "specified": True, "location": location,
            }],
        }

    arguments = [
        slot(f"arg{index}", offset=4 + 4 * index, role="parameter")
        for index in range(words)
    ]
    results = (
        [slot("result0", offset=0, role="result")]
        if result_spec.get("kind") == "word"
        and result_spec.get("register") == "eax"
        else []
    )
    if result_spec.get("kind") not in {"word", "void"}:
        raise NativeIngressError(
            f"callback {callback.callback_id!r} result ABI is unsupported"
        )
    protocol_payload = callback.protocol.to_value()
    protocol_id = str(protocol_payload["id"])
    transport = PhysicalCallFrameV2.create(
        subject={"kind": "callback", "id": protocol_id, "image_selector": image_id},
        transfer_kind="callback",
        target="i686-pc-windows-pe32",
        abi_dialect="pe32-i386-authority-v1",
        calling_convention="cdecl" if template == "pe32-cdecl-v1" else "stdcall",
        arguments=arguments,
        results=results,
        stack={
            "coordinate": "callee-entry-esp-v1", "alignment_bytes": 4,
            "cleanup": "caller" if template == "pe32-cdecl-v1" else "callee",
            "cleanup_bytes": cleanup, "reserved_bytes": 0,
        },
        preserved_state=("ebp", "ebx", "edi", "esi", "esp"),
        clobbered_state=("eax", "ecx", "edx", "eflags", "st0", "st1"),
        outcomes=("normal",),
    )
    evidence = {
        "callback_id": callback.callback_id,
        "target_unit_sha256": callback.target_unit_sha256,
        "abi_sha256": callback.abi_sha256,
        "authority_manifest_sha256": authority_manifest_sha256,
        "entry_state": entry,
    }
    schema_sha256 = canonical_sha256_v3({"callback_schema": evidence})
    layout_sha256 = canonical_sha256_v3({"callback_layout": evidence})
    signature_id = f"callback-authority-signature:{callback.abi_sha256}"
    frame = {
        "format": PHYSICAL_CALL_FRAME_V3_FORMAT,
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "transport": transport.to_payload(),
        "bindings": [{
            "slot_id": item["id"],
            "path": {
                "root": "parameter" if item["role"] == "parameter" else "result",
                "value_id": item["id"], "fields": [],
            },
            "transport": "semantic",
        } for item in (*arguments, *results)],
        "dialect_rule_ids": ["pe32.callback-authority-entry-state.v1"],
    }
    frame["id"] = f"physical-call-frame-v3:{canonical_sha256_v3(frame)}"
    lifecycle_material = {
        "callback_id": callback.callback_id,
        "lifetime": callback.lifetime,
        "protocol_lifetime": protocol_payload.get("lifetime"),
    }
    lifecycle = {
        "format": BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
        "lifecycle_sha256": canonical_sha256_v3(lifecycle_material),
        "status": "complete",
        "obligations": [{
            "id": f"callback-authority:{callback.callback_id}",
            "status": "checked", "code": "callback_lifetime_authority_checked",
        }],
    }
    lifecycle["receipt_sha256"] = canonical_sha256_v3(lifecycle)
    protocol = {
        "format": CHECKED_CALL_PROTOCOL_V2_FORMAT,
        "status": "complete",
        "schema_id": f"callback-authority-schema:{callback.callback_id}",
        "schema_sha256": schema_sha256,
        "layout_sha256": layout_sha256,
        "signature_id": signature_id,
        "physical_frame_id": frame["id"],
        "evidence_receipt_id": (
            f"callback-authority-evidence:{canonical_sha256_v3(evidence)}"
        ),
        "lifecycle_sha256": lifecycle["lifecycle_sha256"],
        "lifecycle_receipt_sha256": lifecycle["receipt_sha256"],
        "projection_sha256": None,
        "projection_receipt_sha256": None,
        "issues": [],
    }
    protocol["id"] = f"checked-call-protocol-v2:{canonical_sha256_v3(protocol)}"
    return {
        "call_protocol": protocol,
        "physical_frame": frame,
        "lifecycle_receipt": lifecycle,
    }


def _root_specs(interface: Mapping[str, Any], roots: Mapping[str, Any]) -> list[dict[str, Any]]:
    export_slots: dict[int, list[Mapping[str, Any]]] = {}
    for row in interface["export_directory"]["slots"]:
        if row["kind"] == "code":
            export_slots.setdefault(int(row["rva"]), []).append(row)
    grouped: dict[tuple[str, int], dict[str, Any]] = {}
    for root in roots.get("roots", []):
        if not isinstance(root, Mapping):
            raise NativeIngressError("behavioral root is malformed")
        kind = root.get("kind")
        rva = root.get("rva")
        if not isinstance(rva, int) or isinstance(rva, bool):
            raise NativeIngressError("behavioral root RVA is invalid")
        if kind == "pe_entrypoint":
            role = "dll_entry" if interface["kind"] == "dll" else "process_entry"
            exports: list[dict[str, Any]] = []
            tls_order = None
        elif kind == "pe_export":
            role = "export"
            slots = export_slots.get(rva)
            if slots is None:
                raise NativeIngressError("behavioral export root has no code EAT slot")
            exports = sorted(
                (
                    {"name": name, "ordinal": slot["ordinal"]}
                    for slot in slots for name in slot["names"]
                ),
                key=lambda item: (item["ordinal"], item["name"]),
            )
            exports.extend(
                {"name": None, "ordinal": slot["ordinal"]}
                for slot in slots if not slot["names"]
            )
            exports.sort(key=lambda item: (item["ordinal"], item["name"] or ""))
            tls_order = None
        elif kind == "pe_tls_callback":
            role = "tls_callback"
            exports = []
            tls_order = root.get("callback_index")
        else:
            continue
        key = (role, rva)
        row = grouped.setdefault(key, {
            "role": role,
            "target_rva": rva,
            "root_ids": [],
            "exports": exports,
            "capability_id": None,
            "tls_order": tls_order,
        })
        identity = root.get("identity")
        if not isinstance(identity, str) or not identity:
            raise NativeIngressError("behavioral root identity is invalid")
        row["root_ids"].append(identity)
        if row["exports"] != exports or row["tls_order"] != tls_order:
            raise NativeIngressError("behavioral roots disagree for one native target")
    result = list(grouped.values())
    for row in result:
        row["root_ids"] = sorted(set(row["root_ids"]))
    return sorted(result, key=lambda row: (row["target_rva"], row["role"]))
