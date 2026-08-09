"""Stable discovery boundary for rooted writable 32-bit image slots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .stage_binary import StageABinary


@dataclass(frozen=True, order=True)
class MutableSlotUseV2:
    """One exact indirect-exit dependency on a writable image slot."""

    exit_id: str
    read_sites: tuple[tuple[str, int], ...]
    origin_witnessed: bool

    def dependency_rows(self, slot_rva: int) -> tuple[dict[str, Any], ...]:
        if self.read_sites:
            return tuple({
                "slot_rva": slot_rva,
                "exit_id": self.exit_id,
                "unit_id": unit_id,
                "event_index": event_index,
                "proof_authority": False,
            } for unit_id, event_index in self.read_sites)
        return ({
            "slot_rva": slot_rva,
            "exit_id": self.exit_id,
            "witness_only": True,
            "proof_authority": False,
        },)


@dataclass(frozen=True, order=True)
class MutableSlotRequirementV2:
    """Canonical non-authorizing requirement consumed by slot replay."""

    slot_rva: int
    width_bytes: int
    uses: tuple[MutableSlotUseV2, ...]

    def dependency_rows(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            row
            for use in self.uses
            for row in use.dependency_rows(self.slot_rva)
        )


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


def derive_proposal_slot_dependencies(
    binary: StageABinary,
    recoveries: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Nominate writable slots referenced by non-authorizing target proposals.

    The returned rows are discovery inputs only.  They identify slots that the
    point-sensitive replay must check; neither a proposal nor its embedded PE
    value is accepted as evidence for the resulting global-slot invariant.
    """

    dependencies: set[tuple[int, str]] = set()
    for recovery in recoveries:
        if (
            not isinstance(recovery, Mapping)
            or recovery.get("status") != "recovered"
        ):
            continue
        exit_id = recovery.get("id")
        witnesses = recovery.get("target_origin_witnesses")
        if (
            not isinstance(exit_id, str)
            or not exit_id
            or not isinstance(witnesses, Sequence)
            or isinstance(witnesses, (str, bytes))
        ):
            continue
        for witness in witnesses:
            if (
                not isinstance(witness, Mapping)
                or witness.get("kind") not in {"static_code", "static_data"}
            ):
                continue
            key = witness.get("key")
            sources = key[1] if isinstance(key, list) and len(key) == 2 else None
            if not isinstance(sources, list):
                continue
            for address in sources:
                if (
                    isinstance(address, int)
                    and not isinstance(address, bool)
                    and writable_image_span(binary, address, 4)
                ):
                    dependencies.add((address - binary.image_base, exit_id))
    return [
        {
            "slot_rva": slot_rva,
            "exit_id": exit_id,
            "witness_only": True,
            "proof_authority": False,
        }
        for slot_rva, exit_id in sorted(dependencies)
    ]


def derive_recovery_slot_requirements_v2(
    binary: StageABinary,
    recoveries: Sequence[Mapping[str, Any]],
) -> tuple[MutableSlotRequirementV2, ...]:
    """Derive the exact mutable-slot inventory required by cold recoveries.

    Unlike the broader candidate finder, this inventory contains exactly the
    slots named by the current unseeded interprocedural result. A requirement
    is not a value fact and grants no proof authority; it tells point-sensitive
    replay which locations must receive independently checked invariants.
    """

    by_slot: dict[int, dict[str, MutableSlotUseV2]] = {}
    for recovery in recoveries:
        if not isinstance(recovery, Mapping):
            raise ValueError("mutable-slot recovery is not an object")
        raw_dependencies = recovery.get("mutable_slot_dependencies", ())
        if not isinstance(raw_dependencies, Sequence) or isinstance(
            raw_dependencies, (str, bytes)
        ):
            raise ValueError("mutable-slot dependency inventory is not an array")
        if not raw_dependencies:
            continue
        exit_id = recovery.get("id")
        if not isinstance(exit_id, str) or not exit_id:
            raise ValueError("mutable-slot recovery has no exact exit ID")
        for raw in raw_dependencies:
            if not isinstance(raw, Mapping):
                raise ValueError("mutable-slot dependency is not an object")
            slot_rva = _slot_rva(raw)
            address = binary.image_base + slot_rva
            if not writable_image_span(binary, address, 4):
                raise ValueError(
                    f"mutable-slot requirement {slot_rva:#x} is not writable image data"
                )
            read_sites = _read_sites(raw.get("read_sites", ()))
            origin_witnessed = raw.get("origin_witnessed", False)
            if not isinstance(origin_witnessed, bool):
                raise ValueError("mutable-slot origin witness is not Boolean")
            previous = by_slot.setdefault(slot_rva, {}).get(exit_id)
            if previous is not None:
                read_sites = tuple(sorted(set(previous.read_sites) | set(read_sites)))
                origin_witnessed = previous.origin_witnessed or origin_witnessed
            by_slot[slot_rva][exit_id] = MutableSlotUseV2(
                exit_id=exit_id,
                read_sites=read_sites,
                origin_witnessed=origin_witnessed,
            )
    return tuple(
        MutableSlotRequirementV2(
            slot_rva=slot_rva,
            width_bytes=4,
            uses=tuple(sorted(uses.values())),
        )
        for slot_rva, uses in sorted(by_slot.items())
    )


def required_recovery_slot_rvas_v2(
    recoveries: Sequence[Mapping[str, Any]],
) -> frozenset[int]:
    """Strictly parse the exact slot-RVA set named by cold recoveries."""

    result: set[int] = set()
    for recovery in recoveries:
        if not isinstance(recovery, Mapping):
            raise ValueError("mutable-slot recovery is not an object")
        raw_dependencies = recovery.get("mutable_slot_dependencies", ())
        if not isinstance(raw_dependencies, Sequence) or isinstance(
            raw_dependencies, (str, bytes)
        ):
            raise ValueError("mutable-slot dependency inventory is not an array")
        for raw in raw_dependencies:
            if not isinstance(raw, Mapping):
                raise ValueError("mutable-slot dependency is not an object")
            result.add(_slot_rva(raw))
    return frozenset(result)


def _slot_rva(raw: Mapping[str, Any]) -> int:
    slot_rva = raw.get("slot_rva")
    width_bytes = raw.get("width_bytes")
    if (
        not isinstance(slot_rva, int)
        or isinstance(slot_rva, bool)
        or not 0 <= slot_rva <= 0xFFFF_FFFB
        or width_bytes != 4
        or isinstance(width_bytes, bool)
    ):
        raise ValueError("mutable-slot dependency has an invalid exact span")
    return slot_rva


def _read_sites(value: Any) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("mutable-slot read-site inventory is not an array")
    result: set[tuple[str, int]] = set()
    for row in value:
        if not isinstance(row, Mapping):
            raise ValueError("mutable-slot read site is not an object")
        unit_id = row.get("unit_id")
        event_index = row.get("event_index")
        if (
            not isinstance(unit_id, str)
            or not unit_id
            or not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
        ):
            raise ValueError("mutable-slot read site is malformed")
        result.add((unit_id, event_index))
    return tuple(sorted(result))


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
    "MutableSlotRequirementV2",
    "MutableSlotUseV2",
    "constant_address",
    "derive_mutable_slot_candidates",
    "derive_proposal_slot_dependencies",
    "derive_recovery_slot_requirements_v2",
    "required_recovery_slot_rvas_v2",
    "rooted_reachable_unit_ids",
    "writable_image_span",
]
