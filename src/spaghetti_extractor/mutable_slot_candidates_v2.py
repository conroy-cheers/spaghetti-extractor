"""Stable discovery boundary for rooted writable 32-bit image slots."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .stage_binary import StageABinary


def derive_mutable_slot_candidates(
    binary: StageABinary,
    provenance: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]] = (),
    graph: Mapping[str, Any] | None = None,
) -> list[int]:
    candidates: set[int] = set()
    for field in ("static_interface_slots", "rejected_tainted_slots"):
        rows = provenance.get(field, [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            address = row.get("address") if isinstance(row, Mapping) else None
            if (
                isinstance(address, int)
                and not isinstance(address, bool)
                and writable_image_span(binary, address, 4)
            ):
                candidates.add(address)
    if graph is not None:
        reachable = rooted_reachable_unit_ids(graph)
        for unit in units:
            unit_id = unit.get("id")
            if not isinstance(unit_id, str) or unit_id not in reachable:
                continue
            semantics = unit.get("semantics")
            if not isinstance(semantics, Mapping):
                continue
            raw_events = semantics.get("ordered_events")
            if not isinstance(raw_events, list):
                raw_events = semantics.get("memory_events", [])
            if not isinstance(raw_events, list):
                continue
            for event in raw_events:
                if (
                    not isinstance(event, Mapping)
                    or event.get("kind") not in {"read", "write", "read_write"}
                    or event.get("width") != 4
                    or isinstance(event.get("width"), bool)
                ):
                    continue
                address = constant_address(event.get("address"))
                if address is not None and writable_image_span(binary, address, 4):
                    candidates.add(address)
    return sorted(candidates)


def rooted_reachable_unit_ids(graph: Mapping[str, Any]) -> frozenset[str]:
    roots = {
        str(row.get("unit_id"))
        for row in graph.get("roots", ())
        if isinstance(row, Mapping) and isinstance(row.get("unit_id"), str)
    }
    successors: dict[str, set[str]] = {}
    for row in graph.get("direct_edges", ()):
        if not isinstance(row, Mapping):
            continue
        source = row.get("source_unit_id")
        target = row.get("target_unit_id")
        if isinstance(source, str) and isinstance(target, str):
            successors.setdefault(source, set()).add(target)
    for row in graph.get("indirect_exits", ()):
        if not isinstance(row, Mapping) or row.get("status") != "complete":
            continue
        source = row.get("source_unit_id")
        targets = row.get("target_unit_ids")
        if isinstance(source, str) and isinstance(targets, list):
            successors.setdefault(source, set()).update(
                target for target in targets if isinstance(target, str)
            )
    seen: set[str] = set()
    pending = list(roots)
    while pending:
        unit_id = pending.pop()
        if unit_id in seen:
            continue
        seen.add(unit_id)
        pending.extend(successors.get(unit_id, ()))
    return frozenset(seen)


def constant_address(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value & 0xFFFFFFFF
    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op in {"const", "constant"}:
        constant = value.get("value")
        return (
            constant & 0xFFFFFFFF
            if isinstance(constant, int) and not isinstance(constant, bool)
            else None
        )
    args = value.get("args")
    if op in {"add", "add32", "sub", "sub32", "mul", "mul32"}:
        if not isinstance(args, list) or len(args) != 2:
            return None
        left = constant_address(args[0])
        right = constant_address(args[1])
        if left is None or right is None:
            return None
        if op in {"add", "add32"}:
            return (left + right) & 0xFFFFFFFF
        if op in {"sub", "sub32"}:
            return (left - right) & 0xFFFFFFFF
        return (left * right) & 0xFFFFFFFF
    if op in {"truncate", "zero_extend", "zeroExtend"}:
        child = value.get("value")
        if child is None and isinstance(args, list) and len(args) == 1:
            child = args[0]
        return constant_address(child)
    return None


def writable_image_span(binary: StageABinary, address: int, width: int) -> bool:
    if width <= 0:
        return False
    rva = address - binary.image_base
    return any(
        section.writable
        and section.rva_start <= rva
        and rva + width <= section.rva_end
        for section in binary.sections
    )


__all__ = [
    "constant_address",
    "derive_mutable_slot_candidates",
    "rooted_reachable_unit_ids",
    "writable_image_span",
]
