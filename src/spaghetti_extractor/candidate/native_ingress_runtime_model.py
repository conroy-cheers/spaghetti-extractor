# ruff: noqa: F401
"""Exact IA-32 PE-TLS ABI and table-driven native-ingress source emission."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..calls.frame import PhysicalCallFrameV2
from ..errors import ToolkitInputError
from .native_ingress_runtime_abi import (
    INGRESS_FRAME_BYTES,
    MACHINE_STATE_BYTES,
    MAX_INGRESS_DEPTH,
    MINIMUM_RUNTIME_CONTROL_BYTES,
    PRIVATE_STACK_SLICE_BYTES,
    STATE_PAIR_BYTES,
)

_CAPABILITY_LIFETIME_MODES = {
    "during_call": 0,
    "one_shot_or_process_exit": 1,
    "until_replaced_or_process_exit": 2,
    "until_resource_event_or_process_exit": 3,
}
_CAPTURED_GPRS = frozenset({
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
})
_CAPTURED_X87 = frozenset(f"st{index}" for index in range(8))


@dataclass(frozen=True)
class CompactCallbackTargetV1:
    """One dense runtime row derived from a compact callback domain."""

    flat_index: int
    domain_index: int
    target_index: int
    global_target_index: int
    target_rva: int
    outcome_protocol_id: str
    capability_id: str


@dataclass(frozen=True)
class CompactCallbackDomainV1:
    """Validated domain metadata shared by every callback renderer."""

    identity: str
    protocol_id: str
    bridge_family_id: str
    trampoline_table_symbol: str
    trampoline_stride_bytes: int
    physical_frame_id: str
    cleanup_bytes: int
    flat_first: int
    targets: tuple[CompactCallbackTargetV1, ...]
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class CompactCallbackBridgeFamilyV1:
    """One physical gateway shared by ABI-equivalent callback domains."""

    identity: str
    symbol: str
    cleanup_bytes: int
    physical_frame_ids: tuple[str, ...]
    domain_ids: tuple[str, ...]


@dataclass(frozen=True)
class CompactCallbackRuntimeV1:
    """The sole lowering of compact callback authority into native rows."""

    domains: tuple[CompactCallbackDomainV1, ...]
    families: tuple[CompactCallbackBridgeFamilyV1, ...]
    targets: tuple[CompactCallbackTargetV1, ...]
    publications: tuple[Mapping[str, Any], ...]


def compact_callback_runtime_v1(
    plan: Mapping[str, Any],
) -> CompactCallbackRuntimeV1:
    """Validate and densely index compact callback authority.

    The native plan remains domain based.  This projection is deliberately
    shared by assembly, runtime C, and module-runtime planning so none of those
    consumers can grow an independent site-by-target interpretation.
    """

    raw_domains = plan.get("callback_domains", [])
    raw_families = plan.get("callback_bridge_families", [])
    raw_publications = plan.get("callback_publications", [])
    if not all(isinstance(value, list) for value in (
        raw_domains, raw_families, raw_publications,
    )):
        raise ToolkitInputError("native ingress compact callback inventory is malformed")
    if not raw_domains:
        if raw_families or raw_publications:
            raise ToolkitInputError(
                "native ingress compact callback inventory is not closed"
            )
        return CompactCallbackRuntimeV1((), (), (), ())

    outcome_ids = {
        str(row["id"])
        for row in plan.get("outcome_protocols", [])
        if isinstance(row, Mapping)
        and isinstance(row.get("id"), str)
        and row["id"]
    }
    family_by_id: dict[str, CompactCallbackBridgeFamilyV1] = {}
    for index, raw in enumerate(raw_families):
        if not isinstance(raw, Mapping):
            raise ToolkitInputError(
                f"native ingress callback bridge family {index} is malformed"
            )
        identity = raw.get("id")
        symbol = raw.get("symbol")
        physical_frame_ids = raw.get("physical_frame_ids")
        domain_ids = raw.get("domain_ids")
        cleanup = raw.get("cleanup_bytes")
        if (
            not isinstance(identity, str) or not identity
            or not isinstance(symbol, str) or not symbol
            or not isinstance(cleanup, int) or isinstance(cleanup, bool)
            or cleanup < 0 or cleanup > 0xFFFFFFFF
            or not isinstance(physical_frame_ids, list)
            or not isinstance(domain_ids, list)
            or any(not isinstance(value, str) or not value for value in physical_frame_ids)
            or any(not isinstance(value, str) or not value for value in domain_ids)
            or physical_frame_ids != sorted(set(physical_frame_ids))
            or domain_ids != sorted(set(domain_ids))
            or identity in family_by_id
        ):
            raise ToolkitInputError(
                "native ingress callback bridge family is non-canonical"
            )
        family_by_id[identity] = CompactCallbackBridgeFamilyV1(
            identity=identity,
            symbol=symbol,
            cleanup_bytes=cleanup,
            physical_frame_ids=tuple(physical_frame_ids),
            domain_ids=tuple(domain_ids),
        )
    if list(family_by_id) != sorted(family_by_id):
        raise ToolkitInputError(
            "native ingress callback bridge families are not canonical"
        )

    domains: list[CompactCallbackDomainV1] = []
    targets: list[CompactCallbackTargetV1] = []
    global_target_index = {
        target_rva: index
        for index, target_rva in enumerate(sorted({
            int(target_rva)
            for raw in raw_domains if isinstance(raw, Mapping)
            for target_rva in raw.get("target_rvas", [])
            if isinstance(target_rva, int) and not isinstance(target_rva, bool)
        }))
    }
    domain_by_id: dict[str, CompactCallbackDomainV1] = {}
    table_symbols: set[str] = set()
    for domain_index, raw in enumerate(raw_domains):
        if not isinstance(raw, Mapping):
            raise ToolkitInputError(
                f"native ingress callback domain {domain_index} is malformed"
            )
        identity = raw.get("id")
        protocol_id = raw.get("protocol_id")
        family_id = raw.get("bridge_family_id")
        table_symbol = raw.get("trampoline_table_symbol")
        stride = raw.get("trampoline_stride_bytes")
        target_rvas = raw.get("target_rvas")
        physical = raw.get("physical_frame")
        outcome_groups = raw.get("outcome_groups")
        if (
            not isinstance(identity, str) or not identity
            or not isinstance(protocol_id, str) or not protocol_id
            or not isinstance(family_id, str) or family_id not in family_by_id
            or not isinstance(table_symbol, str) or not table_symbol
            or table_symbol in table_symbols
            or stride != 10
            or not isinstance(target_rvas, list) or not target_rvas
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                or value < 0 or value > 0xFFFFFFFF
                for value in target_rvas
            )
            or target_rvas != sorted(set(target_rvas))
            or not isinstance(physical, Mapping)
            or not isinstance(outcome_groups, list)
            or identity in domain_by_id
        ):
            raise ToolkitInputError(
                "native ingress callback domain is non-canonical"
            )
        physical_id = physical.get("id")
        transport_payload = physical.get("transport")
        if (
            not isinstance(physical_id, str) or not physical_id
            or not isinstance(transport_payload, Mapping)
        ):
            raise ToolkitInputError(
                "native ingress callback domain physical frame is malformed"
            )
        transport = PhysicalCallFrameV2.parse(transport_payload)
        family = family_by_id[family_id]
        if (
            identity not in family.domain_ids
            or physical_id not in family.physical_frame_ids
            or transport.stack.cleanup_bytes != family.cleanup_bytes
        ):
            raise ToolkitInputError(
                "native ingress callback domain disagrees with its bridge family"
            )
        outcome_by_target: dict[int, str] = {}
        for group_index, group in enumerate(outcome_groups):
            if not isinstance(group, Mapping):
                raise ToolkitInputError(
                    f"native ingress callback outcome group {group_index} is malformed"
                )
            outcome_id = group.get("outcome_protocol_id")
            group_targets = group.get("target_rvas")
            if (
                not isinstance(outcome_id, str) or outcome_id not in outcome_ids
                or not isinstance(group_targets, list)
                or group_targets != sorted(set(group_targets))
                or any(target not in target_rvas for target in group_targets)
            ):
                raise ToolkitInputError(
                    "native ingress callback outcome group is non-canonical"
                )
            for target in group_targets:
                if target in outcome_by_target:
                    raise ToolkitInputError(
                        "native ingress callback target has ambiguous outcomes"
                    )
                outcome_by_target[target] = outcome_id
        if set(outcome_by_target) != set(target_rvas):
            raise ToolkitInputError(
                "native ingress callback outcomes do not cover their domain"
            )
        flat_first = len(targets)
        domain_targets = tuple(
            CompactCallbackTargetV1(
                flat_index=flat_first + target_index,
                domain_index=domain_index,
                target_index=target_index,
                global_target_index=global_target_index[target_rva],
                target_rva=target_rva,
                outcome_protocol_id=outcome_by_target[target_rva],
                capability_id="compact-code-capability-v1:" + canonical_sha256_v3({
                    "domain_id": identity,
                    "target_rva": target_rva,
                }),
            )
            for target_index, target_rva in enumerate(target_rvas)
        )
        domain = CompactCallbackDomainV1(
            identity=identity,
            protocol_id=protocol_id,
            bridge_family_id=family_id,
            trampoline_table_symbol=table_symbol,
            trampoline_stride_bytes=10,
            physical_frame_id=physical_id,
            cleanup_bytes=family.cleanup_bytes,
            flat_first=flat_first,
            targets=domain_targets,
            payload=raw,
        )
        domains.append(domain)
        domain_by_id[identity] = domain
        table_symbols.add(table_symbol)
        targets.extend(domain_targets)
    if [domain.identity for domain in domains] != sorted(domain_by_id):
        raise ToolkitInputError("native ingress callback domains are not canonical")
    for family in family_by_id.values():
        actual_domains = tuple(sorted(
            domain.identity for domain in domains
            if domain.bridge_family_id == family.identity
        ))
        actual_frames = tuple(sorted({
            domain.physical_frame_id for domain in domains
            if domain.bridge_family_id == family.identity
        }))
        if actual_domains != family.domain_ids or actual_frames != family.physical_frame_ids:
            raise ToolkitInputError(
                "native ingress callback bridge family coverage is stale"
            )

    publications: list[Mapping[str, Any]] = []
    publication_ids: set[str] = set()
    for index, raw in enumerate(raw_publications):
        if not isinstance(raw, Mapping):
            raise ToolkitInputError(
                f"native ingress callback publication {index} is malformed"
            )
        identity = raw.get("id")
        domain_id = raw.get("domain_id")
        instruction_rva = raw.get("instruction_rva")
        if (
            not isinstance(identity, str) or not identity
            or identity in publication_ids
            or not isinstance(domain_id, str) or domain_id not in domain_by_id
            or not isinstance(instruction_rva, int)
            or isinstance(instruction_rva, bool)
            or instruction_rva < 0 or instruction_rva > 0xFFFFFFFF
            or not isinstance(raw.get("escape_id"), str)
            or not isinstance(raw.get("lifetime"), str)
        ):
            raise ToolkitInputError(
                "native ingress callback publication is non-canonical"
            )
        _capability_lifetime(raw["lifetime"])
        publication_ids.add(identity)
        publications.append(raw)
    if publications != sorted(
        publications, key=lambda row: (row["instruction_rva"], row["id"])
    ):
        raise ToolkitInputError(
            "native ingress callback publications are not canonical"
        )
    referenced = {str(row["domain_id"]) for row in publications}
    if referenced != set(domain_by_id):
        raise ToolkitInputError(
            "native ingress callback publications do not cover their domains"
        )
    return CompactCallbackRuntimeV1(
        domains=tuple(domains),
        families=tuple(family_by_id.values()),
        targets=tuple(targets),
        publications=tuple(publications),
    )


def _uint(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolkitInputError(f"{label} must be an unsigned integer")
    return value


def checked_unwind_effect_catalog_v1(
    plan: Mapping[str, Any],
) -> dict[str, int]:
    """Resolve the canonical transfer identities executable during unwind."""

    raw_effects = plan.get("unwind_effects", [])
    if not isinstance(raw_effects, list):
        raise ToolkitInputError("native ingress unwind-effect catalog is malformed")
    result: dict[str, int] = {}
    ordered: list[tuple[str, int]] = []
    for raw_effect in raw_effects:
        if (
            not isinstance(raw_effect, Mapping)
            or set(raw_effect) != {"id", "rva"}
            or not isinstance(raw_effect.get("id"), str)
            or not raw_effect["id"]
        ):
            raise ToolkitInputError(
                "native ingress unwind-effect catalog entry is malformed"
            )
        identity = str(raw_effect["id"])
        rva = _uint(raw_effect.get("rva"), "native ingress unwind-effect RVA")
        if rva > 0xFFFFFFFF or identity in result:
            raise ToolkitInputError(
                "native ingress unwind-effect catalog is ambiguous"
            )
        result[identity] = rva
        ordered.append((identity, rva))
    if ordered != sorted(ordered):
        raise ToolkitInputError(
            "native ingress unwind-effect catalog is not canonical"
        )
    return result


def require_realized_native_outcome_v1(outcome: Mapping[str, Any]) -> None:
    """Reject outcome authority that has no checked native realization."""

    if "nonlocal" in outcome.get("outcomes", []) or outcome.get(
        "nonlocal_protocol_ids"
    ):
        raise ToolkitInputError(
            "native ingress nonlocal dispatch is unsupported until its "
            "checked transfer-v2 authority and frame transition are realized"
        )


def physical_frame_transducer_v1(
    frame: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    """Project a checked frame onto the one physical state captured by ingress.

    The faithful backend consumes the physical machine state directly, so this
    projection does not invent a second value representation.  It proves that
    every specified slot is present in the captured GPR/EFLAGS/x87 state or in
    a bounded callee-entry stack range.  Anything needing an abstract memory
    slot, XMM/custom bank, or another phase remains an explicit blocker.
    """

    transport_payload = frame.get("transport")
    if not isinstance(transport_payload, Mapping):
        raise ToolkitInputError("native ingress physical frame lacks transport")
    transport = PhysicalCallFrameV2.parse(transport_payload)
    issues: list[dict[str, Any]] = []
    ranges: set[tuple[int, int, str, str]] = set()
    slots: list[dict[str, Any]] = []
    for direction, inventory, phase in (
        ("input", transport.arguments, "callee_entry"),
        ("output", transport.results, "callee_exit"),
    ):
        for slot in inventory:
            covered: list[dict[str, Any]] = []
            for fragment_index, fragment in enumerate(slot.fragments):
                if not fragment.specified:
                    continue
                location = fragment.location
                reason: str | None = None
                if location.phase != phase:
                    reason = "phase_not_captured"
                elif location.kind == "register":
                    if location.bank == "gpr":
                        if location.name not in _CAPTURED_GPRS or location.width_bits > 32:
                            reason = "gpr_not_captured"
                    elif location.bank == "flags":
                        if location.name != "eflags" or location.width_bits > 32:
                            reason = "flags_not_captured"
                    elif location.bank == "x87":
                        if location.name not in _CAPTURED_X87 or location.width_bits > 80:
                            reason = "x87_register_not_captured"
                    else:
                        reason = "register_bank_not_captured"
                elif location.kind == "stack":
                    if location.stack_base != transport.stack.coordinate:
                        reason = "stack_coordinate_mismatch"
                    else:
                        size = (location.width_bits + 7) // 8
                        offset = int(location.stack_offset_bytes or 0)
                        ranges.add((offset, size, direction, slot.identity))
                else:
                    reason = "location_not_captured"
                if reason is not None:
                    issues.append({
                        "slot_id": slot.identity,
                        "fragment_index": fragment_index,
                        "direction": direction,
                        "reason": reason,
                    })
                    continue
                covered.append({
                    "fragment_index": fragment_index,
                    "logical_offset_bits": fragment.logical_offset_bits,
                    "width_bits": fragment.width_bits,
                    "representation": fragment.representation,
                    "location": location.to_payload(),
                })
            slots.append({
                "slot_id": slot.identity,
                "direction": direction,
                "storage_bits": slot.storage_bits,
                "value_bits": slot.value_bits,
                "pass_mode": slot.pass_mode,
                "fragments": covered,
            })
    core = {
        "kind": "faithful-physical-frame-transducer-v1",
        "physical_frame_id": frame.get("id") or transport.frame_id,
        "stack_coordinate": transport.stack.coordinate,
        "slots": slots,
        "stack_ranges": [
            {
                "offset_bytes": offset,
                "extent_bytes": extent,
                "direction": direction,
                "slot_id": slot_id,
            }
            for offset, extent, direction, slot_id in sorted(ranges)
        ],
    }
    return core, tuple(issues)


def boundary_lifecycle_transducer_v1(
    frame: Mapping[str, Any], lifecycle: Mapping[str, Any]
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    """Lower checked transient resource borrows onto the physical frame.

    This is deliberately a section of the ingress transducer rather than a
    second lifecycle engine.  Only resource values whose complete physical
    word is present at callee entry are accepted.  Ownership changes and
    memory-reference lifetimes remain explicit blockers until their canonical
    object/service transactions are implemented.
    """

    issues: list[dict[str, Any]] = []
    physical, physical_issues = physical_frame_transducer_v1(frame)
    if physical_issues:
        return {
            "kind": "physical-boundary-lifecycle-transducer-v1",
            "physical_frame_id": frame.get("id"),
            "lifecycle_sha256": lifecycle.get("lifecycle_sha256"),
            "bindings": [],
        }, tuple(physical_issues)
    roots: dict[tuple[str, str], Mapping[str, Any]] = {}
    for root in lifecycle.get("roots", []):
        if not isinstance(root, Mapping) or not isinstance(
            root.get("values"), list
        ):
            continue
        root_name = root.get("root")
        for value in root["values"]:
            if isinstance(root_name, str) and isinstance(value, Mapping):
                value_id = value.get("id")
                if isinstance(value_id, str):
                    roots[(root_name, value_id)] = value
    slots = {
        (str(row.get("direction")), str(row.get("slot_id"))): row
        for row in physical["slots"]
        if isinstance(row, Mapping)
    }
    frame_bindings = [
        row for row in frame.get("bindings", []) if isinstance(row, Mapping)
    ]
    rows: list[dict[str, Any]] = []
    for index, binding in enumerate(lifecycle.get("bindings", [])):
        if not isinstance(binding, Mapping):
            issues.append({"binding_index": index, "reason": "binding_malformed"})
            continue
        identity = binding.get("id")
        path = binding.get("path")
        transition = binding.get("transition")
        reason: str | None = None
        if not isinstance(identity, str) or not identity:
            reason = "binding_identity_missing"
        elif not isinstance(path, Mapping):
            reason = "path_malformed"
        elif path.get("root") != "parameter":
            reason = "lifecycle_root_not_input"
        elif path.get("fields") != []:
            reason = "lifecycle_field_path_not_lowered"
        elif transition not in {"borrow_shared", "borrow_mutable"}:
            reason = "lifecycle_transition_not_lowered"
        value = (
            None
            if not isinstance(path, Mapping)
            else roots.get((str(path.get("root")), str(path.get("value_id"))))
        )
        if reason is None and value is None:
            reason = "lifecycle_value_missing"
        if reason is None and value.get("interpretation") != "resource":
            reason = "lifecycle_value_not_resource"
        if reason is None and (
            value.get("resource_kind") != binding.get("resource_kind")
            or value.get("provider_domain") != binding.get("provider_domain")
        ):
            reason = "lifecycle_resource_metadata_mismatch"
        path_matches = (
            []
            if not isinstance(path, Mapping)
            else [
                row for row in frame_bindings
                if row.get("path") == path and row.get("transport") == "semantic"
            ]
        )
        if reason is None and len(path_matches) != 1:
            reason = "lifecycle_physical_binding_not_unique"
        slot = None
        if reason is None:
            slot = slots.get(("input", str(path_matches[0].get("slot_id"))))
            if slot is None:
                reason = "lifecycle_input_slot_missing"
        fragments = [] if slot is None else slot.get("fragments")
        if reason is None and (
            not isinstance(fragments, list)
            or len(fragments) != 1
            or fragments[0].get("logical_offset_bits") != 0
            or fragments[0].get("width_bits") != slot.get("storage_bits")
            or fragments[0].get("representation") != "identity"
            or not isinstance(slot.get("storage_bits"), int)
            or int(slot["storage_bits"]) > 32
        ):
            reason = "lifecycle_resource_word_not_fully_captured"
        location = None if reason is not None else fragments[0].get("location")
        if reason is None and (
            not isinstance(location, Mapping)
            or (
                location.get("kind") == "register"
                and (
                    location.get("bank") != "gpr"
                    or location.get("name") not in _CAPTURED_GPRS
                )
            )
            or location.get("kind") not in {"register", "stack"}
        ):
            reason = "lifecycle_resource_location_not_addressable"
        if reason is not None:
            issues.append({
                "binding_id": identity,
                "binding_index": index,
                "reason": reason,
            })
            continue
        rows.append({
            "binding_id": str(identity),
            "transition": str(transition),
            "resource_kind": str(binding["resource_kind"]),
            "provider_domain": str(binding["provider_domain"]),
            "nullable": bool(value["nullable"]),
            "slot_id": str(path_matches[0]["slot_id"]),
            "location": dict(location),
        })
    return {
        "kind": "physical-boundary-lifecycle-transducer-v1",
        "physical_frame_id": frame.get("id"),
        "lifecycle_sha256": lifecycle.get("lifecycle_sha256"),
        "bindings": sorted(rows, key=lambda row: row["binding_id"]),
    }, tuple(issues)


def _checked_lifecycle_bindings_v1(
    transducer: Mapping[str, Any], *, physical_frame_id: object
) -> list[dict[str, Any]]:
    """Validate the content-bound lifecycle rows before rendering C tables."""

    kind = transducer.get("kind")
    if (
        kind not in {
            "physical-boundary-lifecycle-transducer-v1",
            "reviewed-pe32-loader-lifecycle-transducer-v1",
        }
        or transducer.get("physical_frame_id") != physical_frame_id
    ):
        raise ToolkitInputError(
            "native ingress lifecycle transducer does not bind its physical frame"
        )
    raw_bindings = transducer.get("bindings")
    if not isinstance(raw_bindings, list):
        raise ToolkitInputError(
            "native ingress lifecycle transducer bindings are malformed"
        )
    if kind == "reviewed-pe32-loader-lifecycle-transducer-v1" and raw_bindings:
        raise ToolkitInputError(
            "reviewed PE32 loader lifecycle transducer cannot carry boundary bindings"
        )
    result: list[dict[str, Any]] = []
    identities: set[str] = set()
    for row in raw_bindings:
        if not isinstance(row, Mapping):
            raise ToolkitInputError(
                "native ingress lifecycle transducer binding is malformed"
            )
        identity = row.get("binding_id")
        transition = row.get("transition")
        location = row.get("location")
        if (
            not isinstance(identity, str)
            or not identity
            or identity in identities
            or transition not in {"borrow_shared", "borrow_mutable"}
            or not isinstance(row.get("resource_kind"), str)
            or not row["resource_kind"]
            or not isinstance(row.get("provider_domain"), str)
            or not row["provider_domain"]
            or not isinstance(row.get("nullable"), bool)
            or not isinstance(row.get("slot_id"), str)
            or not row["slot_id"]
            or not isinstance(location, Mapping)
            or not isinstance(location.get("width_bits"), int)
            or not 1 <= int(location["width_bits"]) <= 32
        ):
            raise ToolkitInputError(
                "native ingress lifecycle transducer binding is malformed"
            )
        if location.get("kind") == "register":
            if (
                location.get("bank") != "gpr"
                or location.get("name") not in _CAPTURED_GPRS
            ):
                raise ToolkitInputError(
                    "native ingress lifecycle register binding is unsupported"
                )
        elif location.get("kind") == "stack":
            if not isinstance(location.get("stack_offset_bytes"), int):
                raise ToolkitInputError(
                    "native ingress lifecycle stack binding is malformed"
                )
        else:
            raise ToolkitInputError(
                "native ingress lifecycle binding location is unsupported"
            )
        identities.add(identity)
        result.append(dict(row))
    if result != sorted(result, key=lambda row: row["binding_id"]):
        raise ToolkitInputError(
            "native ingress lifecycle transducer bindings are not canonical"
        )
    return result


def _capability_lifetime(value: object) -> tuple[str, str | None]:
    """Normalize the checked lifetime identity retained by callback authority."""

    if not isinstance(value, str) or not value:
        raise ToolkitInputError("native ingress capability lifetime is missing")
    kind, separator, end_event = value.partition(":")
    if kind not in _CAPABILITY_LIFETIME_MODES:
        raise ToolkitInputError(
            f"native ingress capability lifetime {value!r} is unsupported"
        )
    if kind == "until_resource_event_or_process_exit":
        if not separator or not end_event:
            raise ToolkitInputError(
                "resource-event callback lifetime lacks its checked end event"
            )
        return kind, end_event
    if separator:
        raise ToolkitInputError(
            f"native ingress capability lifetime {kind!r} cannot name an end event"
        )
    return kind, None


@dataclass(frozen=True)
class NativeIngressSupportABI:
    runtime_offset: int
    runtime_control_bytes: int
    private_stack_offset: int
    private_stack_bytes: int

    @classmethod
    def parse(cls, plan: Mapping[str, Any]) -> "NativeIngressSupportABI":
        layout = plan.get("tls_layout")
        if not isinstance(layout, Mapping):
            raise ToolkitInputError("native ingress plan lacks a TLS layout")
        regions = layout.get("runtime_regions")
        if not isinstance(regions, Mapping):
            raise ToolkitInputError("native ingress TLS regions are malformed")
        stack = regions.get("private_stack")
        if not isinstance(stack, Mapping):
            raise ToolkitInputError("native ingress plan lacks a private stack")
        result = cls(
            _uint(layout.get("runtime_offset"), "runtime TLS offset"),
            _uint(layout.get("runtime_control_bytes"), "runtime TLS control size"),
            _uint(stack.get("offset"), "private stack offset"),
            _uint(stack.get("extent"), "private stack size"),
        )
        if result.runtime_control_bytes < MINIMUM_RUNTIME_CONTROL_BYTES:
            raise ToolkitInputError("native ingress TLS control region is below the exact runtime ABI")
        if result.private_stack_offset < result.runtime_control_bytes:
            raise ToolkitInputError("native ingress private stack overlaps runtime control state")
        if result.private_stack_bytes < PRIVATE_STACK_SLICE_BYTES:
            raise ToolkitInputError("native ingress private stack cannot hold one checked frame")
        return result
