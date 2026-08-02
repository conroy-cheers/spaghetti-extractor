"""Deterministic contract hypotheses over normalized reconstruction machine IR.

This module does not replace the concrete machine semantics.  It projects
cluster-wide memory views, locked atomic operations, and external service
metadata while retaining the exact semantic memory events that justify those
hypotheses.  Every inference is conditional on explicit memory and aliasing
preconditions; malformed or ambiguous evidence produces an ``incomplete``
result instead of a stronger guess.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .artifact_formats import RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT

_ACCESS_ORDER = {"read": 0, "write": 1, "read_write": 2}
_ATOMIC_OPERATIONS = {
    "adc": "add_with_carry",
    "add": "add",
    "and": "bitwise_and",
    "btc": "bit_test_complement",
    "btr": "bit_test_reset",
    "bts": "bit_test_set",
    "cmpxchg": "compare_exchange",
    "cmpxchg8b": "compare_exchange_double_word",
    "dec": "decrement",
    "inc": "increment",
    "neg": "negate",
    "not": "bitwise_not",
    "or": "bitwise_or",
    "sbb": "subtract_with_borrow",
    "sub": "subtract",
    "xadd": "exchange_add",
    "xchg": "exchange",
    "xor": "bitwise_xor",
}
_TEMPLATE_CONVENTIONS = {
    "pe32-cdecl-v1": "cdecl",
    "pe32-stdcall-v1": "stdcall",
    "cdecl": "cdecl",
    "stdcall": "stdcall",
}


class ReconstructionContractAnalysisError(ValueError):
    """The normalized units or signature catalog are structurally malformed."""


def analyze_reconstruction_contracts(
    units: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    signature_catalog: Any | None = None,
    *,
    cluster_id: str | None = None,
) -> dict[str, Any]:
    """Build deterministic generic contract metadata for a unit neighborhood.

    ``units`` may be a sequence of normalized machine-IR records or an object
    containing a ``units`` sequence.  The optional catalog accepts normalized
    ``entries``, ``machine_import_call_contracts``,
    ``machine_import_signatures``, or a bare sequence of signatures.
    """

    normalized_units = _normalize_units(units)
    issues: list[dict[str, Any]] = []
    catalog, catalog_supplied = _catalog_index(signature_catalog)

    concrete_memory, memory_views, valid_memory, aliasing = _analyze_memory(
        normalized_units, issues
    )
    atomic_effects = _analyze_atomics(normalized_units, concrete_memory, issues)
    external_services, callbacks = _analyze_external_events(
        normalized_units,
        catalog,
        catalog_supplied=catalog_supplied,
        issues=issues,
    )

    issues.sort(key=_issue_sort_key)
    unit_enrichments = _unit_enrichments(
        normalized_units,
        memory_views,
        atomic_effects,
        external_services,
        callbacks,
        issues,
    )
    unit_ids = [str(unit["id"]) for unit in normalized_units]
    resolved_cluster_id = cluster_id or _stable_id(
        "machine-ir-neighborhood", {"unit_ids": unit_ids}
    )
    status = "incomplete" if issues else "complete"
    return {
        "format": RECONSTRUCTION_CONTRACT_ANALYSIS_FORMAT,
        "status": status,
        "cluster": {"id": resolved_cluster_id, "unit_ids": unit_ids},
        "concrete_effects": {"memory_events": concrete_memory},
        "memory_views": memory_views,
        "preconditions": {
            "valid_memory": valid_memory,
            "aliasing": aliasing,
        },
        "atomic_effects": atomic_effects,
        "external_services": external_services,
        "callbacks": callbacks,
        "unit_enrichments": unit_enrichments,
        "issues": issues,
        "counts": {
            "units": len(normalized_units),
            "concrete_memory_events": len(concrete_memory),
            "memory_views": len(memory_views),
            "valid_memory_preconditions": len(valid_memory),
            "alias_preconditions": len(aliasing),
            "atomic_effects": len(atomic_effects),
            "external_services": len(external_services),
            "callbacks": len(callbacks),
            "issues": len(issues),
        },
    }


def enrich_reconstruction_contracts(
    units: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    signature_catalog: Any | None = None,
    *,
    cluster_id: str | None = None,
) -> dict[str, Any]:
    """Compatibility spelling for :func:`analyze_reconstruction_contracts`."""

    return analyze_reconstruction_contracts(
        units, signature_catalog, cluster_id=cluster_id
    )


def enrich_machine_ir_contracts(
    units: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    signature_catalog: Any | None = None,
    *,
    cluster_id: str | None = None,
) -> dict[str, Any]:
    """Machine-IR-oriented spelling for the same deterministic analysis."""

    return analyze_reconstruction_contracts(
        units, signature_catalog, cluster_id=cluster_id
    )


def _normalize_units(
    units: Sequence[Mapping[str, Any]] | Mapping[str, Any],
) -> list[dict[str, Any]]:
    raw_units: Any = units.get("units") if isinstance(units, Mapping) else units
    if (
        not isinstance(raw_units, Sequence)
        or isinstance(raw_units, (str, bytes, bytearray))
    ):
        raise ReconstructionContractAnalysisError("units must be a sequence")

    result: list[tuple[tuple[int, str], dict[str, Any]]] = []
    identities: set[str] = set()
    for index, raw in enumerate(raw_units):
        if not isinstance(raw, Mapping):
            raise ReconstructionContractAnalysisError(
                f"unit {index} must be an object"
            )
        unit = _json_copy(raw, f"unit {index}")
        identity = unit.get("id")
        if not isinstance(identity, str) or not identity:
            raise ReconstructionContractAnalysisError(
                f"unit {index} must have a non-empty id"
            )
        if identity in identities:
            raise ReconstructionContractAnalysisError(
                f"duplicate unit id {identity!r}"
            )
        identities.add(identity)
        semantics = unit.get("semantics")
        if not isinstance(semantics, Mapping):
            raise ReconstructionContractAnalysisError(
                f"unit {identity!r} must have normalized semantics"
            )
        result.append(((_unit_rva(unit), identity), unit))
    result.sort(key=lambda item: item[0])
    return [unit for _, unit in result]


def _unit_rva(unit: Mapping[str, Any]) -> int:
    source = unit.get("source")
    if isinstance(source, Mapping):
        original = source.get("original")
        if isinstance(original, Mapping):
            value = original.get("rva_start")
            if _is_int(value) and value >= 0:
                return value
    location = unit.get("source_location")
    if isinstance(location, Mapping):
        value = location.get("rva_start")
        if _is_int(value) and value >= 0:
            return value
    return 0x1_0000_0000


def _analyze_memory(
    units: Sequence[Mapping[str, Any]], issues: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    concrete: list[dict[str, Any]] = []
    groups: dict[str, dict[str, Any]] = {}

    for unit in units:
        identity = str(unit["id"])
        events = unit["semantics"].get("memory_events")
        if not isinstance(events, list):
            _add_issue(
                issues,
                "malformed_memory_inventory",
                "normalized memory_events is not a list",
                unit_id=identity,
            )
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                _add_issue(
                    issues,
                    "malformed_memory_event",
                    "memory event is not an object",
                    unit_id=identity,
                    event_index=event_index,
                )
                continue
            copied_event = _json_copy(event, "memory event")
            concrete.append(
                {
                    "unit_id": identity,
                    "event_index": event_index,
                    "event": copied_event,
                }
            )
            access = event.get("kind")
            width = event.get("width")
            address = event.get("address")
            if access not in _ACCESS_ORDER:
                _add_issue(
                    issues,
                    "ambiguous_memory_access",
                    "memory access kind is not read, write, or read_write",
                    unit_id=identity,
                    event_index=event_index,
                )
                continue
            if not _is_int(width) or width <= 0:
                _add_issue(
                    issues,
                    "ambiguous_memory_width",
                    "memory event has no exact positive byte width",
                    unit_id=identity,
                    event_index=event_index,
                )
                continue
            decomposed = _decompose_address(address)
            if decomposed is None:
                _add_issue(
                    issues,
                    "ambiguous_memory_base",
                    "address is not one symbolic base plus a constant offset",
                    unit_id=identity,
                    event_index=event_index,
                )
                continue
            base, offset = decomposed
            base_key = _canonical_json(_canonical_expr(base))
            group = groups.setdefault(
                base_key,
                {
                    "base": _canonical_expr(base),
                    "role": _base_role(base),
                    "observations": [],
                },
            )
            group["observations"].append(
                {
                    "unit_id": identity,
                    "event_index": event_index,
                    "offset": offset,
                    "width_bytes": width,
                    "access": access,
                    "address": _json_copy(address, "memory address"),
                }
            )

    concrete.sort(key=lambda item: (_unit_position(units, item["unit_id"]), item["event_index"]))
    views: list[dict[str, Any]] = []
    valid_memory: list[dict[str, Any]] = []
    for base_key in sorted(groups):
        group = groups[base_key]
        fields_by_shape: dict[tuple[int, int], list[dict[str, Any]]] = {}
        for observation in group["observations"]:
            shape = (observation["offset"], observation["width_bytes"])
            fields_by_shape.setdefault(shape, []).append(observation)

        view_seed = {"base": group["base"], "role": group["role"]}
        view_id = _stable_id("memory-view", view_seed)
        fields: list[dict[str, Any]] = []
        for offset, width in sorted(fields_by_shape):
            observations = sorted(
                fields_by_shape[(offset, width)],
                key=lambda item: (
                    _unit_position(units, item["unit_id"]),
                    item["event_index"],
                    _ACCESS_ORDER[item["access"]],
                ),
            )
            accesses = sorted(
                {item["access"] for item in observations},
                key=lambda value: _ACCESS_ORDER[value],
            )
            field = {
                "offset": offset,
                "width_bytes": width,
                "width_bits": width * 8,
                "type": {"kind": "opaque_bits", "width_bits": width * 8},
                "accesses": accesses,
                "observations": observations,
            }
            field["id"] = _stable_id(
                f"{view_id}:field", {"offset": offset, "width_bytes": width}
            )
            fields.append(field)
            precondition = {
                "kind": "valid_memory",
                "view_id": view_id,
                "base": _json_copy(group["base"], "memory base"),
                "offset": offset,
                "width_bytes": width,
                "permissions": accesses,
                "required": True,
            }
            precondition["id"] = _stable_id(
                "memory-precondition", precondition
            )
            valid_memory.append(precondition)

        view_status = "complete"
        for left_index, left in enumerate(fields):
            left_end = left["offset"] + left["width_bytes"]
            for right in fields[left_index + 1 :]:
                right_end = right["offset"] + right["width_bytes"]
                if max(left["offset"], right["offset"]) < min(left_end, right_end):
                    view_status = "incomplete"
                    _add_issue(
                        issues,
                        "overlapping_memory_fields",
                        "one base has incompatible overlapping field hypotheses",
                        view_id=view_id,
                        left_field_id=left["id"],
                        right_field_id=right["id"],
                    )
        minimum = min(field["offset"] for field in fields)
        maximum = max(field["offset"] + field["width_bytes"] for field in fields)
        views.append(
            {
                "id": view_id,
                "status": view_status,
                "hypothesis": "grouped_typed_memory_view",
                "base": _json_copy(group["base"], "memory base"),
                "base_role": group["role"],
                "relative_span": {
                    "offset_start": minimum,
                    "offset_end": maximum,
                    "size": maximum - minimum,
                },
                "fields": fields,
            }
        )

    views.sort(key=lambda item: item["id"])
    valid_memory.sort(
        key=lambda item: (item["view_id"], item["offset"], item["width_bytes"])
    )
    aliasing = _alias_preconditions(views)
    return concrete, views, valid_memory, aliasing


def _alias_preconditions(views: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for left_index, left in enumerate(views):
        for right in views[left_index + 1 :]:
            roles = {str(left["base_role"]), str(right["base_role"])}
            relationship = (
                "stack_object"
                if "stack_frame" in roles and "object_pointer" in roles
                else "distinct_symbolic_bases"
            )
            precondition = {
                "kind": "alias_resolution",
                "relationship": relationship,
                "left_view_id": left["id"],
                "right_view_id": right["id"],
                "left_range": {
                    "base": _json_copy(left["base"], "left memory base"),
                    **dict(left["relative_span"]),
                },
                "right_range": {
                    "base": _json_copy(right["base"], "right memory base"),
                    **dict(right["relative_span"]),
                },
                "requirement": "disjoint_or_same_object_with_compatible_fields",
                "required": True,
            }
            precondition["id"] = _stable_id("alias-precondition", precondition)
            result.append(precondition)
    result.sort(key=lambda item: (item["left_view_id"], item["right_view_id"]))
    return result


def _analyze_atomics(
    units: Sequence[Mapping[str, Any]],
    concrete_memory: Sequence[Mapping[str, Any]],
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_unit: dict[str, list[Mapping[str, Any]]] = {}
    for concrete in concrete_memory:
        by_unit.setdefault(str(concrete["unit_id"]), []).append(concrete)

    result: list[dict[str, Any]] = []
    for unit in units:
        identity = str(unit["id"])
        instructions = unit.get("instructions")
        if not isinstance(instructions, list):
            _add_issue(
                issues,
                "malformed_instruction_inventory",
                "normalized instructions is not a list",
                unit_id=identity,
            )
            continue
        locked_count = sum(
            1
            for instruction in instructions
            if isinstance(instruction, Mapping) and _has_lock_prefix(instruction)
        )
        for instruction_index, instruction in enumerate(instructions):
            if not isinstance(instruction, Mapping) or not _has_lock_prefix(instruction):
                continue
            mnemonic = _base_mnemonic(instruction)
            operation = _ATOMIC_OPERATIONS.get(mnemonic)
            local_complete = True
            if operation is None:
                local_complete = False
                operation = "unknown_locked_operation"
                _add_issue(
                    issues,
                    "unsupported_locked_operation",
                    "LOCK-prefixed instruction is not a recognized read-modify-write form",
                    unit_id=identity,
                    instruction_index=instruction_index,
                    mnemonic=mnemonic,
                )
            operands = instruction.get("operands")
            memory_operands = (
                [item for item in operands if isinstance(item, Mapping) and item.get("kind") == "memory"]
                if isinstance(operands, list)
                else []
            )
            target_operand = memory_operands[0] if len(memory_operands) == 1 else None
            if target_operand is None:
                local_complete = False
                _add_issue(
                    issues,
                    "ambiguous_atomic_target",
                    "LOCK-prefixed operation does not have one exact memory operand",
                    unit_id=identity,
                    instruction_index=instruction_index,
                )

            target_address = _instruction_operand_address(target_operand)
            width_bits = target_operand.get("width_bits") if target_operand else None
            width_bytes = (
                width_bits // 8
                if _is_int(width_bits) and width_bits > 0 and width_bits % 8 == 0
                else None
            )
            if target_operand is not None and (target_address is None or width_bytes is None):
                local_complete = False
                _add_issue(
                    issues,
                    "ambiguous_atomic_target",
                    "atomic memory operand has no exact address or byte width",
                    unit_id=identity,
                    instruction_index=instruction_index,
                )

            candidates: list[dict[str, Any]] = []
            if target_address is not None and width_bytes is not None:
                target_key = _canonical_json(_canonical_expr(target_address))
                for concrete in by_unit.get(identity, []):
                    event = concrete["event"]
                    if (
                        event.get("width") == width_bytes
                        and event.get("kind") in {"read", "write", "read_write"}
                        and _canonical_json(_canonical_expr(event.get("address")))
                        == target_key
                    ):
                        candidates.append(_json_copy(concrete, "concrete atomic event"))
            reads = [
                item
                for item in candidates
                if item["event"].get("kind") in {"read", "read_write"}
            ]
            writes = [
                item
                for item in candidates
                if item["event"].get("kind") in {"write", "read_write"}
            ]
            if len(reads) != 1 or len(writes) != 1 or locked_count != 1:
                local_complete = False
                _add_issue(
                    issues,
                    "ambiguous_atomic_concrete_effects",
                    "atomic operation cannot be tied to one exact concrete read and write",
                    unit_id=identity,
                    instruction_index=instruction_index,
                    candidate_reads=len(reads),
                    candidate_writes=len(writes),
                    locked_instructions=locked_count,
                )

            effect = {
                "unit_id": identity,
                "instruction_index": instruction_index,
                "instruction_rva": instruction.get(
                    "rva_start", instruction.get("rva")
                ),
                "effect_kind": "atomic_read_modify_write",
                "operation": operation,
                "lock_prefix": True,
                "ordering": {
                    "architecture": "x86",
                    "kind": "locked_instruction_order",
                },
                "target": {
                    "operand": _json_copy(target_operand, "atomic target operand")
                    if target_operand is not None
                    else None,
                    "address": target_address,
                    "width_bytes": width_bytes,
                    "width_bits": width_bits if _is_int(width_bits) else None,
                },
                "conditional_write": mnemonic.startswith("cmpxchg"),
                "concrete_memory_events": sorted(
                    candidates, key=lambda item: item["event_index"]
                ),
                "concrete_reads": sorted(
                    reads, key=lambda item: item["event_index"]
                ),
                "concrete_writes": sorted(
                    writes, key=lambda item: item["event_index"]
                ),
                "status": "complete" if local_complete else "incomplete",
            }
            if mnemonic == "cmpxchg":
                effect["compare"] = {
                    "kind": "implicit_accumulator",
                    "register": _accumulator_name(width_bits),
                    "width_bits": width_bits if _is_int(width_bits) else None,
                }
                effect["replacement_operand"] = (
                    _json_copy(operands[1], "cmpxchg replacement operand")
                    if isinstance(operands, list) and len(operands) == 2
                    else None
                )
            effect["id"] = _stable_id(
                "atomic-effect",
                {
                    "unit_id": identity,
                    "instruction_index": instruction_index,
                    "operation": operation,
                },
            )
            result.append(effect)
    result.sort(
        key=lambda item: (
            _unit_position(units, item["unit_id"]),
            item["instruction_index"],
            item["id"],
        )
    )
    return result


def _analyze_external_events(
    units: Sequence[Mapping[str, Any]],
    catalog: Mapping[tuple[str, str, str | int], Sequence[Mapping[str, Any]]],
    *,
    catalog_supplied: bool,
    issues: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    services: list[dict[str, Any]] = []
    callbacks: list[dict[str, Any]] = []
    for unit in units:
        identity = str(unit["id"])
        events = unit["semantics"].get("external_events")
        if not isinstance(events, list):
            _add_issue(
                issues,
                "malformed_external_inventory",
                "normalized external_events is not a list",
                unit_id=identity,
            )
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping) or event.get("kind") != "external_call":
                continue
            service, callback = _external_service(
                identity,
                event_index,
                event,
                catalog,
                catalog_supplied=catalog_supplied,
                issues=issues,
            )
            services.append(service)
            if callback is not None:
                callbacks.append(callback)
                service["callback_id"] = callback["id"]
    services.sort(key=lambda item: (item["unit_id"], item["event_index"]))
    callbacks.sort(key=lambda item: (item["unit_id"], item["event_index"]))
    return services, callbacks


def _external_service(
    unit_id: str,
    event_index: int,
    event: Mapping[str, Any],
    catalog: Mapping[tuple[str, str, str | int], Sequence[Mapping[str, Any]]],
    *,
    catalog_supplied: bool,
    issues: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    event_identity = _external_identity(event)
    local_complete = True
    signature: Mapping[str, Any] | None = None
    if event_identity is None:
        local_complete = False
        _add_issue(
            issues,
            "ambiguous_external_identity",
            "external event does not name exactly one symbol or ordinal",
            unit_id=unit_id,
            event_index=event_index,
        )
    else:
        matches = list(catalog.get(event_identity, ()))
        if len(matches) == 1:
            signature = matches[0]
        elif len(matches) > 1:
            local_complete = False
            _add_issue(
                issues,
                "ambiguous_external_signature",
                "signature catalog has multiple entries for one external identity",
                unit_id=unit_id,
                event_index=event_index,
                identity=_identity_payload(event_identity),
            )
        elif catalog_supplied:
            local_complete = False
            _add_issue(
                issues,
                "missing_external_signature",
                "supplied signature catalog does not cover the external event",
                unit_id=unit_id,
                event_index=event_index,
                identity=_identity_payload(event_identity),
            )

    abi = event.get("abi_contract")
    if not isinstance(abi, Mapping):
        abi = event.get("abi") if isinstance(event.get("abi"), Mapping) else {}
    argument_values = _external_argument_values(event)

    calling_convention, conflict = _reconcile_values(
        _calling_convention(abi), _calling_convention(signature)
    )
    if conflict or calling_convention is None:
        local_complete = False
        _add_issue(
            issues,
            "ambiguous_external_abi",
            "external calling convention is missing or conflicting",
            unit_id=unit_id,
            event_index=event_index,
        )
    argument_words, conflict = _reconcile_values(
        _argument_words(abi),
        _argument_words(signature),
        len(argument_values) if argument_values else None,
    )
    if conflict or not _is_int(argument_words) or argument_words < 0:
        local_complete = False
        argument_words = None
        _add_issue(
            issues,
            "ambiguous_external_arguments",
            "external argument count is missing or conflicting",
            unit_id=unit_id,
            event_index=event_index,
        )
    elif len(argument_values) != argument_words:
        local_complete = False
        _add_issue(
            issues,
            "ambiguous_external_arguments",
            "external event does not carry the exact ABI argument inventory",
            unit_id=unit_id,
            event_index=event_index,
            expected=argument_words,
            observed=len(argument_values),
        )

    world_effect, conflict = _reconcile_values(
        event.get("world_effect"),
        abi.get("world_effect"),
        signature.get("world_effect") if signature else None,
    )
    if conflict or not isinstance(world_effect, str) or not world_effect:
        local_complete = False
        world_effect = "unknown"
        _add_issue(
            issues,
            "ambiguous_external_world_effect",
            "external world effect is missing or conflicting",
            unit_id=unit_id,
            event_index=event_index,
        )
    memory_effect, conflict = _reconcile_values(
        event.get("memory_effect"),
        abi.get("memory_effect"),
        signature.get("memory_effect") if signature else None,
    )
    if conflict or not isinstance(memory_effect, str) or not memory_effect:
        local_complete = False
        memory_effect = "unknown"
        _add_issue(
            issues,
            "ambiguous_external_memory_effect",
            "external memory effect is missing or conflicting",
            unit_id=unit_id,
            event_index=event_index,
        )

    typed_arguments = _typed_arguments(
        signature, argument_words, argument_values
    )
    service_identity = (
        _identity_payload(event_identity)
        if event_identity is not None
        else {
            "dll": event.get("dll"),
            "symbol": event.get("symbol"),
            "ordinal": event.get("ordinal"),
        }
    )
    service = {
        "unit_id": unit_id,
        "event_index": event_index,
        "event": _json_copy(event, "external event"),
        "identity": service_identity,
        "service_kind": _service_kind(world_effect),
        "signature": {
            "calling_convention": calling_convention,
            "argument_words": argument_words,
            "arguments": typed_arguments,
            "result": _typed_result(signature, abi),
        },
        "effects": {
            "disposition": (
                signature.get("disposition", "returns")
                if signature
                else event.get(
                    "disposition", abi.get("disposition", "unknown")
                )
            ),
            "memory_effect": memory_effect,
            "memory_footprints": _memory_footprints(signature, event, abi),
            "world_effect": world_effect,
        },
        "catalog": {
            "matched": signature is not None,
            "catalog_id": signature.get("id", signature.get("catalog_id"))
            if signature
            else None,
        },
        "status": "complete" if local_complete else "incomplete",
    }
    service["id"] = _stable_id(
        "external-service", {"unit_id": unit_id, "event_index": event_index}
    )

    callback = None
    if world_effect == "callbackRegistration":
        callback = _callback_metadata(
            service,
            event,
            abi,
            signature,
            argument_values,
            issues,
        )
        if callback["status"] == "incomplete":
            service["status"] = "incomplete"
    return service, callback


def _callback_metadata(
    service: Mapping[str, Any],
    event: Mapping[str, Any],
    abi: Mapping[str, Any],
    signature: Mapping[str, Any] | None,
    argument_values: Sequence[Any],
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    unit_id = str(service["unit_id"])
    event_index = int(service["event_index"])
    local_complete = True
    argument_index, conflict = _reconcile_values(
        event.get("world_effect_argument"),
        abi.get("world_effect_argument"),
        signature.get("world_effect_argument") if signature else None,
    )
    if (
        conflict
        or not _is_int(argument_index)
        or argument_index < 0
        or argument_index >= len(argument_values)
    ):
        local_complete = False
        target = None
        _add_issue(
            issues,
            "ambiguous_callback_target",
            "callback registration does not identify one concrete target argument",
            unit_id=unit_id,
            event_index=event_index,
        )
    else:
        target = _json_copy(argument_values[argument_index], "callback target")

    callback_abi, conflict = _reconcile_mappings(
        event.get("callback_abi"),
        abi.get("callback_abi"),
        signature.get("callback_abi") if signature else None,
    )
    if conflict or not _valid_callback_abi(callback_abi):
        local_complete = False
        callback_abi = callback_abi if isinstance(callback_abi, Mapping) else {}
        _add_issue(
            issues,
            "ambiguous_callback_abi",
            "callback registration lacks one exact target ABI",
            unit_id=unit_id,
            event_index=event_index,
        )

    lifetime, conflict = _reconcile_values(
        event.get("callback_lifetime"),
        abi.get("callback_lifetime", abi.get("lifetime")),
        signature.get("callback_lifetime", signature.get("lifetime"))
        if signature
        else None,
        callback_abi.get("lifetime") if isinstance(callback_abi, Mapping) else None,
    )
    if conflict or lifetime is None:
        local_complete = False
        lifetime_metadata = {"status": "incomplete", "policy": "unknown"}
        _add_issue(
            issues,
            "ambiguous_callback_lifetime",
            "callback registration has no exact lifetime policy",
            unit_id=unit_id,
            event_index=event_index,
        )
    else:
        lifetime_metadata = {
            "status": "complete",
            "policy": _json_copy(lifetime, "callback lifetime"),
        }

    callback_words = callback_abi.get("argument_words")
    cleanup = callback_abi.get("stack_cleanup_bytes")
    nested_complete = (
        target is not None
        and _is_int(callback_words)
        and callback_words >= 0
        and _is_int(cleanup)
        and cleanup >= 0
    )
    if not nested_complete:
        local_complete = False
    nested_frame = {
        "required": True,
        "required_when": "target_is_non_null"
        if callback_abi.get("nullable") is True
        else "always",
        "status": "complete" if nested_complete else "incomplete",
        "entry_target": target,
        "abi_kind": callback_abi.get("kind"),
        "calling_convention": _calling_convention(callback_abi),
        "argument_words": callback_words if _is_int(callback_words) else None,
        "stack_cleanup_bytes": cleanup if _is_int(cleanup) else None,
        "outer_frame_requirement": "suspend_and_resume_exact_machine_frame",
        "callback_frame_requirement": "fresh_nested_machine_frame",
        "return_requirement": "resume_registering_external_service",
    }
    if signature and signature.get("nested_frame_requirements") is not None:
        nested_frame["catalog_requirements"] = _json_copy(
            signature["nested_frame_requirements"], "nested-frame requirements"
        )

    callback = {
        "unit_id": unit_id,
        "event_index": event_index,
        "service_id": service["id"],
        "registration_argument_index": argument_index
        if _is_int(argument_index)
        else None,
        "target": target,
        "abi": _json_copy(callback_abi, "callback ABI"),
        "lifetime": lifetime_metadata,
        "nested_frame": nested_frame,
        "status": "complete" if local_complete else "incomplete",
    }
    callback["id"] = _stable_id(
        "callback-registration",
        {"unit_id": unit_id, "event_index": event_index},
    )
    return callback


def _catalog_index(
    catalog: Any | None,
) -> tuple[dict[tuple[str, str, str | int], list[dict[str, Any]]], bool]:
    if catalog is None:
        return {}, False
    rows: Any
    if isinstance(catalog, Mapping):
        for key in (
            "entries",
            "machine_import_call_contracts",
            "machine_import_signatures",
            "signatures",
        ):
            if key in catalog:
                rows = catalog[key]
                break
        else:
            if catalog and all(isinstance(value, Mapping) for value in catalog.values()):
                rows = list(catalog.values())
            else:
                raise ReconstructionContractAnalysisError(
                    "signature catalog has no normalized entry sequence"
                )
    elif isinstance(catalog, Sequence) and not isinstance(
        catalog, (str, bytes, bytearray)
    ):
        rows = catalog
    elif hasattr(catalog, "entries"):
        rows = getattr(catalog, "entries")
    else:
        raise ReconstructionContractAnalysisError(
            "signature catalog must contain normalized entries"
        )
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        raise ReconstructionContractAnalysisError("signature catalog entries must be a sequence")

    result: dict[tuple[str, str, str | int], list[dict[str, Any]]] = {}
    for index, raw in enumerate(rows):
        if hasattr(raw, "as_json"):
            raw = raw.as_json()
        if not isinstance(raw, Mapping):
            raise ReconstructionContractAnalysisError(
                f"signature catalog entry {index} must be an object"
            )
        normalized = _flatten_signature(raw)
        identity = _external_identity(normalized)
        if identity is None:
            raise ReconstructionContractAnalysisError(
                f"signature catalog entry {index} has an ambiguous import identity"
            )
        result.setdefault(identity, []).append(normalized)
    for entries in result.values():
        entries.sort(key=_canonical_json)
    return result, True


def _flatten_signature(raw: Mapping[str, Any]) -> dict[str, Any]:
    contract = raw.get("contract")
    result = dict(contract) if isinstance(contract, Mapping) else {}
    result.update(raw)
    result.pop("contract", None)
    imported = result.get("import")
    if isinstance(imported, Mapping):
        result.setdefault("dll", imported.get("dll"))
        result.setdefault("symbol", imported.get("symbol"))
        result.setdefault("ordinal", imported.get("ordinal"))
    return _json_copy(result, "signature catalog entry")


def _external_identity(value: Mapping[str, Any]) -> tuple[str, str, str | int] | None:
    imported = value.get("import")
    source = imported if isinstance(imported, Mapping) else value
    dll = source.get("dll")
    symbol = source.get("symbol")
    ordinal = source.get("ordinal")
    if not isinstance(dll, str) or not dll:
        return None
    has_symbol = isinstance(symbol, str) and bool(symbol)
    has_ordinal = _is_int(ordinal) and ordinal >= 0
    if has_symbol == has_ordinal:
        return None
    return (
        dll.lower(),
        "symbol" if has_symbol else "ordinal",
        symbol if has_symbol else ordinal,
    )


def _identity_payload(identity: tuple[str, str, str | int]) -> dict[str, Any]:
    result: dict[str, Any] = {"dll": identity[0]}
    result[identity[1]] = identity[2]
    return result


def _calling_convention(value: Mapping[str, Any] | None) -> str | None:
    if not isinstance(value, Mapping):
        return None
    raw = value.get(
        "calling_convention", value.get("abi_template", value.get("template"))
    )
    return _TEMPLATE_CONVENTIONS.get(raw) if isinstance(raw, str) else None


def _argument_words(value: Mapping[str, Any] | None) -> int | None:
    if not isinstance(value, Mapping):
        return None
    direct = value.get("argument_words")
    if _is_int(direct) and direct >= 0:
        return direct
    arity = value.get("arity")
    if isinstance(arity, Mapping) and arity.get("kind") == "fixed":
        words = arity.get("words")
        if _is_int(words) and words >= 0:
            return words
    offsets = value.get("stack_argument_offsets")
    if isinstance(offsets, list) and all(_is_int(item) for item in offsets):
        return len(offsets)
    parameters = value.get("parameters")
    if isinstance(parameters, list):
        return len(parameters)
    argument_types = value.get("argument_types")
    if isinstance(argument_types, list):
        return len(argument_types)
    return None


def _typed_arguments(
    signature: Mapping[str, Any] | None,
    argument_words: int | None,
    values: Sequence[Any],
) -> list[dict[str, Any]]:
    count = argument_words if _is_int(argument_words) and argument_words >= 0 else len(values)
    parameters = signature.get("parameters") if signature else None
    argument_types = signature.get("argument_types") if signature else None
    result = []
    for index in range(count):
        parameter = (
            parameters[index]
            if isinstance(parameters, list)
            and index < len(parameters)
            and isinstance(parameters[index], Mapping)
            else {}
        )
        if parameter.get("type") is not None:
            type_metadata = _json_copy(parameter["type"], "parameter type")
            type_source = "catalog"
        elif isinstance(argument_types, list) and index < len(argument_types):
            type_metadata = _json_copy(argument_types[index], "argument type")
            type_source = "catalog"
        else:
            type_metadata = {"kind": "opaque_bits", "width_bits": 32}
            type_source = "machine_abi"
        result.append(
            {
                "index": index,
                "name": parameter.get("name", f"argument_{index}"),
                "direction": parameter.get("direction", "in"),
                "type": type_metadata,
                "type_source": type_source,
                "value": _json_copy(values[index], "external argument")
                if index < len(values)
                else None,
            }
        )
    return result


def _typed_result(
    signature: Mapping[str, Any] | None, abi: Mapping[str, Any]
) -> Any:
    for source in (signature, abi):
        if not isinstance(source, Mapping):
            continue
        for key in ("return_type", "result_type", "result"):
            if source.get(key) is not None:
                return {
                    "kind": "typed",
                    "type": _json_copy(source[key], "external result type"),
                }
    relations = None
    for source in (signature, abi):
        if isinstance(source, Mapping) and isinstance(
            source.get("result_register_relations"), list
        ):
            relations = source["result_register_relations"]
            break
    if relations is None:
        return {"kind": "unknown"}
    return {
        "kind": "machine_register_relations",
        "relations": _json_copy(relations, "result register relations"),
    }


def _external_argument_values(event: Mapping[str, Any]) -> list[Any]:
    """Return the most concrete checked machine-call argument inventory."""

    stack_inputs = event.get("stack_inputs")
    if isinstance(stack_inputs, list) and stack_inputs and all(
        isinstance(item, Mapping) for item in stack_inputs
    ):
        ordered_stack = sorted(
            stack_inputs,
            key=lambda item: item.get("offset")
            if _is_int(item.get("offset"))
            else 0x1_0000_0000,
        )
        if all("value" in item for item in ordered_stack):
            return [item.get("value") for item in ordered_stack]
    arguments = event.get("arguments")
    return list(arguments) if isinstance(arguments, list) else []


def _memory_footprints(
    signature: Mapping[str, Any] | None,
    event: Mapping[str, Any],
    abi: Mapping[str, Any],
) -> list[Any]:
    value = None
    for source in (signature, event, abi):
        if isinstance(source, Mapping) and source.get("memory_footprints") is not None:
            value = source["memory_footprints"]
            break
    return _json_copy(value, "external memory footprints") if isinstance(value, list) else []


def _service_kind(world_effect: str) -> str:
    return {
        "callbackRegistration": "callback_registration",
        "dynamicRangeRelease": "dynamic_range_release",
        "dynamicRanges": "dynamic_range_service",
        "opaqueResources": "opaque_resource_service",
        "tlsState": "thread_local_service",
        "none": "external_service",
    }.get(world_effect, "unknown_external_service")


def _valid_callback_abi(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and isinstance(value.get("kind"), str)
        and _is_int(value.get("argument_words"))
        and value["argument_words"] >= 0
        and _is_int(value.get("stack_cleanup_bytes"))
        and value["stack_cleanup_bytes"] >= 0
        and isinstance(value.get("nullable"), bool)
    )


def _reconcile_values(*values: Any) -> tuple[Any, bool]:
    present = [value for value in values if value is not None]
    if not present:
        return None, False
    canonical = {_canonical_json(value) for value in present}
    return (_json_copy(present[0], "reconciled metadata"), len(canonical) > 1)


def _reconcile_mappings(*values: Any) -> tuple[Mapping[str, Any] | None, bool]:
    present = [value for value in values if isinstance(value, Mapping)]
    if not present:
        return None, any(value is not None for value in values)
    canonical = {_canonical_json(value) for value in present}
    return _json_copy(present[0], "reconciled object"), len(canonical) > 1


def _decompose_address(value: Any) -> tuple[Any, int] | None:
    terms = _linear_address_terms(value)
    if terms is None:
        return None
    dynamic, offset = terms
    if not dynamic and isinstance(value, Mapping) and value.get("op") == "const":
        return _canonical_expr(value), 0
    if len(dynamic) != 1:
        return None
    return _canonical_expr(dynamic[0]), offset


def _linear_address_terms(value: Any) -> tuple[list[Any], int] | None:
    if not isinstance(value, Mapping):
        return None
    operation = value.get("op")
    if operation == "const":
        constant = value.get("value")
        width = value.get("width", 32)
        if not _is_int(constant) or not _is_int(width) or not 1 <= width <= 64:
            return None
        mask = (1 << width) - 1
        unsigned = constant & mask
        sign = 1 << (width - 1)
        return [], unsigned - (1 << width) if unsigned & sign else unsigned
    if operation in {"add", "add32", "add64"}:
        arguments = value.get("args")
        if not isinstance(arguments, list) or not arguments:
            return None
        dynamic: list[Any] = []
        offset = 0
        for argument in arguments:
            decomposed = _linear_address_terms(argument)
            if decomposed is None:
                return None
            terms, amount = decomposed
            dynamic.extend(terms)
            offset += amount
        return dynamic, offset
    if operation in {"sub", "sub32", "sub64"}:
        arguments = value.get("args")
        if not isinstance(arguments, list) or len(arguments) != 2:
            return None
        left = _linear_address_terms(arguments[0])
        right = _linear_address_terms(arguments[1])
        if left is None or right is None or right[0]:
            return None
        return left[0], left[1] - right[1]
    return [_canonical_expr(value)], 0


def _canonical_expr(value: Any) -> Any:
    if isinstance(value, Mapping):
        operation = value.get("op")
        result = {
            str(key): _canonical_expr(item)
            for key, item in value.items()
            if key != "args"
        }
        arguments = value.get("args")
        if isinstance(arguments, list):
            canonical_arguments = [_canonical_expr(item) for item in arguments]
            if operation in {"add", "add32", "add64"}:
                canonical_arguments.sort(key=_canonical_json)
            result["args"] = canonical_arguments
        return result
    if isinstance(value, list):
        return [_canonical_expr(item) for item in value]
    return value


def _base_role(base: Any) -> str:
    if isinstance(base, Mapping):
        operation = base.get("op")
        if operation == "reg":
            register = str(base.get("name", "")).lower()
            if register in {"esp", "ebp", "rsp", "rbp"}:
                return "stack_frame"
            return "object_pointer"
        if operation in {"fs_base", "gs_base"}:
            return "thread_local"
        if operation == "const":
            return "absolute_location"
    return "derived_object_pointer"


def _has_lock_prefix(instruction: Mapping[str, Any]) -> bool:
    mnemonic = instruction.get("mnemonic")
    if isinstance(mnemonic, str) and mnemonic.strip().lower().startswith("lock "):
        return True
    if instruction.get("lock_prefix") is True:
        return True
    for key in ("prefix", "prefixes"):
        value = instruction.get(key)
        values = [value] if isinstance(value, str) else value
        if isinstance(values, list) and any(
            isinstance(item, str) and item.strip().lower() == "lock"
            for item in values
        ):
            return True
    attributes = instruction.get("attributes")
    return isinstance(attributes, Mapping) and attributes.get("lock_prefix") is True


def _base_mnemonic(instruction: Mapping[str, Any]) -> str:
    mnemonic = instruction.get("mnemonic")
    if not isinstance(mnemonic, str):
        return ""
    words = mnemonic.strip().lower().split()
    return words[1] if len(words) >= 2 and words[0] == "lock" else words[0]


def _instruction_operand_address(operand: Mapping[str, Any] | None) -> Any | None:
    if not isinstance(operand, Mapping):
        return None
    terms: list[dict[str, Any]] = []
    segment = operand.get("segment")
    if isinstance(segment, str) and segment.lower() in {"fs", "gs"}:
        terms.append({"op": f"{segment.lower()}_base", "width": 32})
    elif segment not in {None, "", "cs", "ds", "es", "ss"}:
        return None
    base = operand.get("base")
    if isinstance(base, str) and base:
        terms.append({"op": "reg", "name": base.lower(), "width": 32})
    index = operand.get("index")
    if isinstance(index, str) and index:
        scale = operand.get("scale", 1)
        if not _is_int(scale) or scale not in {1, 2, 4, 8}:
            return None
        index_expr: dict[str, Any] = {
            "op": "reg",
            "name": index.lower(),
            "width": 32,
        }
        if scale != 1:
            index_expr = {
                "op": "mul32",
                "args": [
                    index_expr,
                    {"op": "const", "value": scale, "width": 32},
                ],
            }
        terms.append(index_expr)
    displacement = operand.get("displacement", 0)
    if not _is_int(displacement):
        return None
    if displacement or not terms:
        terms.append({"op": "const", "value": displacement, "width": 32})
    if len(terms) == 1:
        return terms[0]
    return _canonical_expr({"op": "add32", "args": terms})


def _accumulator_name(width_bits: Any) -> str | None:
    return {8: "al", 16: "ax", 32: "eax", 64: "rax"}.get(width_bits)


def _unit_enrichments(
    units: Sequence[Mapping[str, Any]],
    views: Sequence[Mapping[str, Any]],
    atomics: Sequence[Mapping[str, Any]],
    services: Sequence[Mapping[str, Any]],
    callbacks: Sequence[Mapping[str, Any]],
    issues: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result = []
    for unit in units:
        identity = str(unit["id"])
        view_ids = sorted(
            {
                view["id"]
                for view in views
                if any(
                    observation["unit_id"] == identity
                    for field in view["fields"]
                    for observation in field["observations"]
                )
            }
        )
        unit_issues = [
            issue["id"]
            for issue in issues
            if issue.get("location", {}).get("unit_id") == identity
        ]
        result.append(
            {
                "unit_id": identity,
                "status": "incomplete" if unit_issues else "complete",
                "memory_view_ids": view_ids,
                "atomic_effect_ids": [
                    item["id"] for item in atomics if item["unit_id"] == identity
                ],
                "external_service_ids": [
                    item["id"] for item in services if item["unit_id"] == identity
                ],
                "callback_ids": [
                    item["id"] for item in callbacks if item["unit_id"] == identity
                ],
                "issue_ids": unit_issues,
            }
        )
    return result


def _add_issue(
    issues: list[dict[str, Any]],
    category: str,
    message: str,
    *,
    unit_id: str | None = None,
    event_index: int | None = None,
    instruction_index: int | None = None,
    **details: Any,
) -> None:
    location: dict[str, Any] = {}
    if unit_id is not None:
        location["unit_id"] = unit_id
    if event_index is not None:
        location["event_index"] = event_index
    if instruction_index is not None:
        location["instruction_index"] = instruction_index
    body = {
        "status": "incomplete",
        "category": category,
        "message": message,
        "location": location,
        "details": _json_copy(details, "issue details"),
    }
    body["id"] = _stable_id("contract-analysis-issue", body)
    issues.append(body)


def _issue_sort_key(issue: Mapping[str, Any]) -> tuple[Any, ...]:
    location = issue.get("location", {})
    return (
        str(location.get("unit_id", "")),
        location.get("event_index", -1),
        location.get("instruction_index", -1),
        str(issue.get("category", "")),
        str(issue.get("id", "")),
    )


def _unit_position(units: Sequence[Mapping[str, Any]], identity: str) -> int:
    for index, unit in enumerate(units):
        if unit.get("id") == identity:
            return index
    return len(units)


def _stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:20]}"


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ReconstructionContractAnalysisError(
            "analysis input is not normalized JSON data"
        ) from exc


def _json_copy(value: Any, label: str) -> Any:
    try:
        copied = copy.deepcopy(value)
        _canonical_json(copied)
        return copied
    except ReconstructionContractAnalysisError as exc:
        raise ReconstructionContractAnalysisError(
            f"{label} is not normalized JSON data"
        ) from exc


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
