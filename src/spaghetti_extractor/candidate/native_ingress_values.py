# ruff: noqa: F401
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
from ..pe32.behavioral_roots import BEHAVIORAL_ROOTS_FORMAT
from ..pe32.formats import (
    PE32_MODULE_INTERFACE_FORMAT,
)
from ..transfer.plan import load_executable_transfer_plan
from ..transfer.closure import validate_module_execution_closure_v1
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



def _parse_ingress_authority(value: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    fields = {
        "role", "target_rva", "target_unit_id", "root_ids",
        "execution_closure_sha256",
        "call_protocol", "physical_frame", "lifecycle_protocol",
        "lifecycle_receipt",
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
    closure = value["execution_closure_sha256"]
    if not isinstance(closure, str) or len(closure) != 64:
        raise NativeIngressError(
            f"ingress authority {index} execution closure is invalid"
        )
    call = value["call_protocol"]
    frame = value["physical_frame"]
    lifecycle_protocol = value["lifecycle_protocol"]
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
    if not isinstance(lifecycle_protocol, Mapping):
        raise NativeIngressError(
            f"ingress authority {index} lifecycle protocol is malformed"
        )
    if lifecycle_protocol.get("format") == BOUNDARY_LIFECYCLE_V1_FORMAT:
        lifecycle_protocol_sha256 = lifecycle_protocol.get("lifecycle_sha256")
        lifecycle_protocol_core = {
            key: item for key, item in lifecycle_protocol.items()
            if key != "lifecycle_sha256"
        }
        if lifecycle_protocol_sha256 != canonical_sha256_v3(
            lifecycle_protocol_core
        ):
            raise NativeIngressError(
                f"ingress authority {index} lifecycle protocol is stale"
            )
    elif lifecycle_protocol.get("kind") == "reviewed_pe32_loader_lifecycle_v1":
        lifecycle_protocol_sha256 = canonical_sha256_v3(lifecycle_protocol)
    else:
        raise NativeIngressError(
            f"ingress authority {index} lifecycle protocol is unsupported"
        )
    if (
        lifecycle.get("lifecycle_sha256") != lifecycle_protocol_sha256
        or lifecycle.get("lifecycle_sha256") != call.get("lifecycle_sha256")
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
    physical_transducer, transducer_issues = physical_frame_transducer_v1(frame)
    if transducer_issues:
        blockers.append({
            "category": "native_ingress_physical_transducer_incomplete",
            "role": spec["role"],
            "target_rva": spec["target_rva"],
            "issues": [dict(item) for item in transducer_issues],
        })
    physical_transducer = {
        **physical_transducer,
        "transducer_sha256": canonical_sha256_v3(physical_transducer),
    }
    lifecycle_protocol = authority["lifecycle_protocol"]
    if lifecycle_protocol.get("format") == BOUNDARY_LIFECYCLE_V1_FORMAT:
        lifecycle_transducer, lifecycle_issues = (
            boundary_lifecycle_transducer_v1(frame, lifecycle_protocol)
        )
        if lifecycle_issues:
            blockers.append({
                "category": "native_ingress_lifecycle_transducer_incomplete",
                "role": spec["role"],
                "target_rva": spec["target_rva"],
                "issues": [dict(item) for item in lifecycle_issues],
            })
    else:
        lifecycle_transducer = {
            "kind": "reviewed-pe32-loader-lifecycle-transducer-v1",
            "physical_frame_id": frame.get("id"),
            "lifecycle_sha256": canonical_sha256_v3(lifecycle_protocol),
            "bindings": [],
        }
    lifecycle_transducer = {
        **lifecycle_transducer,
        "transducer_sha256": canonical_sha256_v3(lifecycle_transducer),
    }
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
        "execution_closure_sha256": authority["execution_closure_sha256"],
        "call_protocol_id": authority["call_protocol"]["id"],
        "call_protocol": dict(authority["call_protocol"]),
        "physical_frame_id": frame["id"],
        "physical_frame": dict(frame),
        "physical_transducer": physical_transducer,
        "lifecycle_transducer": lifecycle_transducer,
        "lifecycle_receipt_id": authority["lifecycle_receipt"].get("id") or authority["lifecycle_receipt"].get("receipt_sha256"),
        "lifecycle_protocol": dict(authority["lifecycle_protocol"]),
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
