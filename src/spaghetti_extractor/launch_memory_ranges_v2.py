"""Checked spatial facts derived from explicit PE32 launch-memory ranges.

This analysis is intentionally independent of rooted control and abstract
register propagation.  It recognizes exact memory events whose address is an
affine offset from a launch-provided machine input, and authorizes image-alias
exclusion only when the launch profile explicitly declares a bounded private
range for that input.  The first supported range is the Win32 TEB at ``FS``.

The claim is spatial only.  It does not make TEB contents immutable and does
not model SEH behavior or any particular TEB field.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from .address_expression_v2 import affine_special_offset
from .artifact_identity_v2 import canonical_sha256


LAUNCH_MEMORY_RANGE_ANALYSIS_V2_FORMAT = (
    "spaghetti-extractor-launch-memory-range-analysis-v2"
)
CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT = (
    "stage-a-checked-launch-memory-spatial-fact-v2"
)
_TEB_RANGE_CONTRACT = "private-non-image-thread-environment-range-v1"
_TEB_PARENT_CONTRACT = "pe32-user-thread-fs-v1"
_UINT32_LIMIT = 1 << 32
_MEMORY_KINDS = frozenset({"read", "write", "read_write"})


def derive_launch_memory_range_analysis_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    launch_assumptions: Mapping[str, Any],
    pe_sha256: str,
    machine_ir_sha256: str,
    image_base: int,
    size_of_image: int,
) -> dict[str, Any]:
    """Derive exact event-bound non-image facts from launch assumptions."""

    binding = {
        "pe_sha256": _digest(pe_sha256, "PE SHA-256"),
        "machine_ir_sha256": _digest(
            machine_ir_sha256, "machine-IR SHA-256"
        ),
        "launch_assumptions_sha256": canonical_sha256(launch_assumptions),
        "image_base": _u32(image_base, "image base"),
        "size_of_image": _positive_u32(size_of_image, "image size"),
    }
    if binding["image_base"] + binding["size_of_image"] > _UINT32_LIMIT:
        raise ValueError("PE image range wraps the 32-bit address space")

    normalized_units = _normalize_units(units)
    range_contract, issues = _teb_range_contract(launch_assumptions)
    facts: list[dict[str, Any]] = []
    if range_contract is not None:
        for unit_id, unit in sorted(normalized_units.items()):
            events = unit["semantics"].get("memory_events")
            if not isinstance(events, list):
                continue
            for event_index, event in enumerate(events):
                fact = _event_fact(
                    unit_id=unit_id,
                    event_index=event_index,
                    event=event,
                    range_contract=range_contract,
                    binding=binding,
                    image_base=image_base,
                    size_of_image=size_of_image,
                )
                if fact is not None:
                    facts.append(fact)

    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete" if issues else "complete"
    )
    body = {
        "format": LAUNCH_MEMORY_RANGE_ANALYSIS_V2_FORMAT,
        "status": status,
        "binding": binding,
        "range_contracts": (
            [] if range_contract is None else [copy.deepcopy(range_contract)]
        ),
        "counts": {
            "units": len(normalized_units),
            "range_contracts": 0 if range_contract is None else 1,
            "checked_spatial_facts": len(facts),
            "issues": len(issues),
        },
        "checked_spatial_facts": sorted(
            facts,
            key=lambda row: (
                str(row["unit_id"]),
                int(row["event_index"]),
                str(row["id"]),
            ),
        ),
        "issues": issues,
    }
    return {**body, "analysis_sha256": canonical_sha256(body)}


def validate_launch_memory_range_analysis_v2(
    analysis: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    launch_assumptions: Mapping[str, Any],
    pe_sha256: str,
    machine_ir_sha256: str,
    image_base: int,
    size_of_image: int,
) -> dict[str, Mapping[str, Any]]:
    """Re-derive the complete artifact and index its exact event facts."""

    expected = derive_launch_memory_range_analysis_v2(
        units=units,
        launch_assumptions=launch_assumptions,
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256,
        image_base=image_base,
        size_of_image=size_of_image,
    )
    if dict(analysis) != expected:
        raise ValueError("launch-memory range analysis does not replay exactly")
    result: dict[str, Mapping[str, Any]] = {}
    for fact in expected["checked_spatial_facts"]:
        event_id = f"event:{fact['unit_id']}:{fact['event_index']}"
        if event_id in result:
            raise ValueError("launch-memory spatial facts duplicate an event")
        result[event_id] = fact
    return result


def _event_fact(
    *,
    unit_id: str,
    event_index: int,
    event: Any,
    range_contract: Mapping[str, Any],
    binding: Mapping[str, Any],
    image_base: int,
    size_of_image: int,
) -> dict[str, Any] | None:
    if not isinstance(event, Mapping):
        return None
    kind = event.get("kind")
    width = event.get("width")
    if (
        kind not in _MEMORY_KINDS
        or not isinstance(width, int)
        or isinstance(width, bool)
        or not 0 < width <= 4096
    ):
        return None
    offset = affine_special_offset(event.get("address"), "fs_base")
    lower = int(range_contract["lower_bound"])
    upper = int(range_contract["upper_bound_exclusive"])
    if offset is None or offset < lower or offset + width > upper:
        return None
    core = {
        "format": CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT,
        "status": "complete",
        "unit_id": unit_id,
        "event_index": event_index,
        "memory_kind": kind,
        "width_bytes": width,
        "address_expression": copy.deepcopy(event.get("address")),
        "base_kind": "fs_base",
        "address_base_offset": offset,
        "minimum_start_offset": offset,
        "maximum_start_offset": offset,
        "range_contract": copy.deepcopy(dict(range_contract)),
        "disjoint_from_image": {
            "image_base": image_base,
            "size_of_image": size_of_image,
        },
        "authority_binding": copy.deepcopy(dict(binding)),
    }
    identity = "checked-launch-memory-spatial-v2:" + canonical_sha256(core)
    payload = {**core, "id": identity}
    return {**payload, "fact_sha256": canonical_sha256(payload)}


def _teb_range_contract(
    launch_assumptions: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    assumptions = launch_assumptions.get("assumptions")
    if not isinstance(assumptions, Mapping):
        return None, [_issue("violated", "launch_assumptions_malformed")]
    raw = assumptions.get("fs")
    if not isinstance(raw, Mapping):
        return None, [_issue("incomplete", "fs_launch_contract_missing")]
    required = {
        "contract": _TEB_PARENT_CONTRACT,
        "teb_fields": "profiled-accesses-only",
        "range_contract": _TEB_RANGE_CONTRACT,
        "mapped_separately_from_image": True,
    }
    for key, expected in required.items():
        if raw.get(key) != expected:
            return None, [_issue(
                "incomplete",
                "fs_launch_range_contract_missing",
                field=key,
            )]
    size = raw.get("minimum_accessible_bytes")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 1 <= size <= 0x10_0000
    ):
        return None, [_issue("violated", "fs_launch_range_size_invalid")]
    return {
        "assumption_kind": "fs",
        "base_kind": "fs_base",
        "contract": _TEB_RANGE_CONTRACT,
        "lower_bound": 0,
        "upper_bound_exclusive": size,
        "mapped_separately_from_image": True,
    }, []


def _normalize_units(
    units: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for index, unit in enumerate(units):
        if not isinstance(unit, Mapping):
            raise ValueError(f"machine-IR unit {index} is not an object")
        unit_id = unit.get("id")
        semantics = unit.get("semantics")
        if (
            not isinstance(unit_id, str)
            or not unit_id
            or unit_id in result
            or not isinstance(semantics, Mapping)
        ):
            raise ValueError(f"machine-IR unit {index} is malformed")
        result[unit_id] = unit
    return result


def _issue(status: str, code: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "code": code, **details}


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{context} is invalid")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{context} is invalid") from exc
    return value


def _u32(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < _UINT32_LIMIT
    ):
        raise ValueError(f"{context} is invalid")
    return value


def _positive_u32(value: Any, context: str) -> int:
    result = _u32(value, context)
    if result == 0:
        raise ValueError(f"{context} is invalid")
    return result


__all__ = [
    "CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT",
    "LAUNCH_MEMORY_RANGE_ANALYSIS_V2_FORMAT",
    "derive_launch_memory_range_analysis_v2",
    "validate_launch_memory_range_analysis_v2",
]
