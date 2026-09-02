"""Root-independent SCC inventory for inductive portable components.

The machine IR is the only source of control-flow facts here.  Operator
declarations may later choose portable state variables and coarsen cutpoints,
but they cannot add or remove machine transitions from this inventory.
"""

from __future__ import annotations

import copy
from collections import defaultdict
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .semantic_contract import transfer_expression_view_v2


INDUCTIVE_MACHINE_SHAPE_V1 = (
    "spaghetti-extractor-component-inductive-machine-shape-v1"
)
INDUCTIVE_SEGMENT_INVENTORY_V1 = (
    "spaghetti-extractor-component-inductive-segment-inventory-v1"
)


class SemanticInductionError(ValueError):
    """Exact operation semantics cannot form a closed SCC inventory."""


@dataclass(frozen=True)
class _Unit:
    identity: str
    rva: int
    semantics: Mapping[str, object]


def build_inductive_machine_shape(
    operation: Mapping[str, object],
) -> dict[str, object]:
    """Derive the exact cyclic control inventory for one semantic operation."""

    operation_id = _text(operation.get("operation_id"), "operation id")
    raw_units = _rows(operation.get("units"), "operation units")
    units: dict[str, _Unit] = {}
    by_rva: dict[int, str] = {}
    for raw in raw_units:
        identity = _text(raw.get("id"), "semantic unit id")
        if identity in units:
            raise SemanticInductionError("operation has duplicate semantic unit ids")
        source = _object(raw.get("source"), "semantic unit source")
        original = _object(source.get("original"), "semantic unit original range")
        rva = original.get("rva_start")
        if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
            raise SemanticInductionError("semantic unit RVA is invalid")
        if rva in by_rva:
            raise SemanticInductionError("operation has duplicate semantic unit RVAs")
        semantics = _object(raw.get("semantics"), "semantic unit semantics")
        units[identity] = _Unit(identity, rva, copy.deepcopy(dict(semantics)))
        by_rva[rva] = identity

    entries = _identities(operation.get("entry_unit_ids"), "operation entries")
    exits = _identities(operation.get("exit_unit_ids"), "operation exits")
    if not entries or not exits:
        raise SemanticInductionError("operation requires entry and exit units")
    unknown_roots = (set(entries) | set(exits)) - set(units)
    if unknown_roots:
        raise SemanticInductionError(
            f"operation roots reference unknown units {sorted(unknown_roots)!r}"
        )

    outgoing: dict[str, tuple[tuple[str, Mapping[str, object]], ...]] = {}
    edges: list[dict[str, object]] = []
    for identity in sorted(units, key=lambda item: units[item].rva):
        if identity in exits:
            outgoing[identity] = ()
            continue
        edge_rows = _edge_rows(units[identity].semantics)
        if not edge_rows:
            raise SemanticInductionError(
                f"non-exit semantic unit {identity!r} has no direct transition"
            )
        resolved: list[tuple[str, Mapping[str, object]]] = []
        seen_targets: set[str] = set()
        for condition, target_rva in edge_rows:
            target = by_rva.get(target_rva)
            if target is None:
                raise SemanticInductionError(
                    f"semantic edge from {identity!r} leaves the operation at RVA "
                    f"{target_rva:#x}"
                )
            if target in seen_targets:
                raise SemanticInductionError(
                    f"semantic unit {identity!r} has duplicate target {target!r}"
                )
            seen_targets.add(target)
            resolved.append((target, condition))
            edges.append(
                {
                    "source_unit_id": identity,
                    "target_unit_id": target,
                    "condition": copy.deepcopy(dict(condition)),
                }
            )
        outgoing[identity] = tuple(resolved)

    reachable = _reachable(entries, outgoing)
    if reachable != set(units):
        raise SemanticInductionError(
            "operation unit inventory contains unreachable units: "
            f"{sorted(set(units) - reachable)!r}"
        )
    reverse = _reverse(outgoing)
    can_exit = _reachable(exits, reverse)
    if can_exit != set(units):
        raise SemanticInductionError(
            "operation contains units with no path to a declared exit: "
            f"{sorted(set(units) - can_exit)!r}"
        )

    components = _tarjan(tuple(units), outgoing)
    component_by_unit = {
        unit_id: index for index, component in enumerate(components)
        for unit_id in component
    }
    cyclic_components: list[dict[str, object]] = []
    for index, component in enumerate(components):
        members = set(component)
        self_loop = any(
            target == source
            for source in members
            for target, _condition in outgoing[source]
        )
        if len(members) == 1 and not self_loop:
            continue
        ordered_members = sorted(members, key=lambda item: units[item].rva)
        incoming = sorted(
            {
                target
                for source, targets in outgoing.items()
                if source not in members
                for target, _condition in targets
                if target in members
            },
            key=lambda item: units[item].rva,
        )
        if any(entry in members for entry in entries):
            incoming = sorted(
                set(incoming) | (set(entries) & members),
                key=lambda item: units[item].rva,
            )
        internal_edges = [
            edge for edge in edges
            if edge["source_unit_id"] in members
            and edge["target_unit_id"] in members
        ]
        exit_edges = [
            edge for edge in edges
            if edge["source_unit_id"] in members
            and edge["target_unit_id"] not in members
        ]
        cyclic_components.append(
            {
                "scc_id": _scc_id(operation_id, ordered_members),
                "member_unit_ids": ordered_members,
                "entry_unit_ids": incoming,
                "internal_edges": sorted(
                    internal_edges,
                    key=lambda row: (
                        units[str(row["source_unit_id"])].rva,
                        units[str(row["target_unit_id"])].rva,
                        canonical_sha256_v3(row["condition"]),
                    ),
                ),
                "exit_edges": sorted(
                    exit_edges,
                    key=lambda row: (
                        units[str(row["source_unit_id"])].rva,
                        units[str(row["target_unit_id"])].rva,
                        canonical_sha256_v3(row["condition"]),
                    ),
                ),
            }
        )

    component_edges = sorted(
        {
            (component_by_unit[source], component_by_unit[target])
            for source, targets in outgoing.items()
            for target, _condition in targets
            if component_by_unit[source] != component_by_unit[target]
        }
    )
    semantic_units = [
        {
            "unit_id": identity,
            "rva": units[identity].rva,
            "semantics_sha256": canonical_sha256_v3(units[identity].semantics),
        }
        for identity in sorted(units, key=lambda item: units[item].rva)
    ]
    core: dict[str, object] = {
        "format": INDUCTIVE_MACHINE_SHAPE_V1,
        "operation_id": operation_id,
        "entry_unit_ids": list(entries),
        "exit_unit_ids": list(exits),
        "semantic_units": semantic_units,
        "control_edges": sorted(
            edges,
            key=lambda row: (
                units[str(row["source_unit_id"])].rva,
                units[str(row["target_unit_id"])].rva,
                canonical_sha256_v3(row["condition"]),
            ),
        ),
        "cyclic_sccs": sorted(
            cyclic_components, key=lambda row: str(row["scc_id"])
        ),
        "condensation_edges": [list(edge) for edge in component_edges],
        "requires_induction": bool(cyclic_components),
        "policy": {
            "control_inventory_machine_derived": True,
            "operator_edges_accepted": False,
            "unresolved_targets_fail_closed": True,
        },
    }
    return {**core, "shape_sha256": canonical_sha256_v3(core)}


def build_inductive_segment_inventory(
    operation: Mapping[str, object],
    *,
    cutpoint_unit_ids: Sequence[str],
) -> dict[str, object]:
    """Cut exact operation control into finite paths between cutpoints.

    At least one submitted cutpoint must intersect every cyclic SCC.  The
    resulting segment inventory is checked against every direct machine edge,
    so a declaration cannot make a difficult branch disappear.
    """

    shape = build_inductive_machine_shape(operation)
    operation_id = str(shape["operation_id"])
    unit_rows = _rows(shape["semantic_units"], "semantic units")
    rvas = {
        _text(row.get("unit_id"), "semantic unit id"): int(row["rva"])
        for row in unit_rows
    }
    entries = tuple(str(item) for item in shape["entry_unit_ids"])
    exits = set(str(item) for item in shape["exit_unit_ids"])
    cutpoints = tuple(cutpoint_unit_ids)
    if not cutpoints or any(not isinstance(item, str) or not item for item in cutpoints):
        raise SemanticInductionError("inductive cutpoints must be nonempty strings")
    if len(cutpoints) != len(set(cutpoints)):
        raise SemanticInductionError("inductive cutpoints contain duplicates")
    if set(cutpoints) - set(rvas):
        raise SemanticInductionError(
            "inductive cutpoints reference unknown semantic units: "
            f"{sorted(set(cutpoints) - set(rvas))!r}"
        )
    ordered_cutpoints = tuple(sorted(cutpoints, key=lambda item: rvas[item]))
    cyclic_rows = _rows(shape["cyclic_sccs"], "cyclic SCCs")
    for scc in cyclic_rows:
        members = set(_identities(scc.get("member_unit_ids"), "SCC members"))
        if not members & set(cutpoints):
            raise SemanticInductionError(
                f"cyclic SCC {scc.get('scc_id')!r} has no selected cutpoint"
            )

    edge_rows = _rows(shape["control_edges"], "control edges")
    outgoing: dict[str, list[tuple[int, str, Mapping[str, object]]]] = {
        identity: [] for identity in rvas
    }
    edge_keys: set[tuple[str, str, str]] = set()
    for edge in edge_rows:
        source = _text(edge.get("source_unit_id"), "edge source")
        target = _text(edge.get("target_unit_id"), "edge target")
        condition = _object(edge.get("condition"), "edge condition")
        key = (source, target, canonical_sha256_v3(condition))
        edge_keys.add(key)
        outgoing[source].append((len(outgoing[source]), target, condition))
    for source in outgoing:
        outgoing[source].sort(
            key=lambda row: (rvas[row[1]], canonical_sha256_v3(row[2]))
        )

    segments: list[dict[str, object]] = []

    def record(
        *,
        source_kind: str,
        source_id: str,
        target_kind: str,
        target_id: str,
        path: Sequence[str],
        traversed: Sequence[Mapping[str, object]],
    ) -> None:
        core = {
            "source": {"kind": source_kind, "id": source_id},
            "target": {"kind": target_kind, "id": target_id},
            "unit_ids": list(path),
            "edges": [copy.deepcopy(dict(row)) for row in traversed],
        }
        segments.append(
            {
                "segment_id": "component-segment-v1:"
                + canonical_sha256_v3(
                    {"operation_id": operation_id, **core}
                ),
                **core,
            }
        )

    def walk(
        current: str,
        *,
        source_kind: str,
        source_id: str,
        path: tuple[str, ...],
        traversed: tuple[Mapping[str, object], ...],
        visited: frozenset[str],
        stop_at_cutpoint: bool,
    ) -> None:
        if stop_at_cutpoint and current in cutpoints:
            record(
                source_kind=source_kind,
                source_id=source_id,
                target_kind="cutpoint",
                target_id=current,
                path=path,
                traversed=traversed,
            )
            return
        if current in visited:
            raise SemanticInductionError(
                "machine path cycles without crossing a selected cutpoint at "
                f"{current!r}"
            )
        next_path = (*path, current)
        if current in exits:
            record(
                source_kind=source_kind,
                source_id=source_id,
                target_kind="operation_exit",
                target_id=current,
                path=next_path,
                traversed=traversed,
            )
            return
        next_visited = frozenset((*visited, current))
        for _index, target, condition in outgoing[current]:
            edge = {
                "source_unit_id": current,
                "target_unit_id": target,
                "condition": copy.deepcopy(dict(condition)),
            }
            walk(
                target,
                source_kind=source_kind,
                source_id=source_id,
                path=next_path,
                traversed=(*traversed, edge),
                visited=next_visited,
                stop_at_cutpoint=True,
            )

    for entry in entries:
        if entry in cutpoints:
            record(
                source_kind="operation_entry",
                source_id=entry,
                target_kind="cutpoint",
                target_id=entry,
                path=(),
                traversed=(),
            )
        else:
            walk(
                entry,
                source_kind="operation_entry",
                source_id=entry,
                path=(),
                traversed=(),
                visited=frozenset(),
                stop_at_cutpoint=True,
            )
    for cutpoint in ordered_cutpoints:
        walk(
            cutpoint,
            source_kind="cutpoint",
            source_id=cutpoint,
            path=(),
            traversed=(),
            visited=frozenset(),
            stop_at_cutpoint=False,
        )

    covered_edges = {
        (
            str(edge["source_unit_id"]),
            str(edge["target_unit_id"]),
            canonical_sha256_v3(edge["condition"]),
        )
        for segment in segments
        for edge in _rows(segment["edges"], "segment edges")
    }
    if covered_edges != edge_keys:
        raise SemanticInductionError(
            "inductive segment inventory does not cover exact control edges: "
            f"missing={sorted(edge_keys - covered_edges)!r}, "
            f"extra={sorted(covered_edges - edge_keys)!r}"
        )
    segments.sort(key=lambda row: str(row["segment_id"]))
    core: dict[str, object] = {
        "format": INDUCTIVE_SEGMENT_INVENTORY_V1,
        "operation_id": operation_id,
        "machine_shape_sha256": shape["shape_sha256"],
        "cutpoint_unit_ids": list(ordered_cutpoints),
        "segments": segments,
        "control_edge_count": len(edge_keys),
        "covered_control_edge_count": len(covered_edges),
        "policy": {
            "every_cycle_cut": True,
            "every_direct_edge_covered": True,
            "operator_edges_accepted": False,
            "bounded_unrolling_used": False,
        },
    }
    return {**core, "inventory_sha256": canonical_sha256_v3(core)}


def _edge_rows(
    semantics: Mapping[str, object],
) -> tuple[tuple[Mapping[str, object], int], ...]:
    transfer = semantics.get("transfer_v2")
    if isinstance(transfer, Mapping):
        terminator = _object(
            transfer.get("terminator"), "canonical transfer terminator"
        )
        operation = terminator.get("op")
        operands = terminator.get("operands")
        if not isinstance(operands, list) or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 0
            for item in operands
        ):
            raise SemanticInductionError(
                "canonical transfer terminator operands are malformed"
            )
        if operation in {"outcome_fallthrough", "outcome_jump"}:
            if len(operands) != 1:
                raise SemanticInductionError(
                    "canonical direct transfer has invalid arity"
                )
            return (({"op": "true"}, operands[0]),)
        if operation == "outcome_branch":
            if len(operands) != 3:
                raise SemanticInductionError(
                    "canonical branch transfer has invalid arity"
                )
            condition = transfer_expression_view_v2(transfer, operands[0])
            return (
                (condition, operands[1]),
                ({"op": "not", "args": [copy.deepcopy(condition)]}, operands[2]),
            )
        if operation in {
            "outcome_return",
            "outcome_indirect",
            "outcome_nonlocal",
            "outcome_external",
        }:
            return ()
        raise SemanticInductionError(
            "canonical transfer terminator operation is unsupported"
        )
    raw_edges = semantics.get("edge_conditions", [])
    if not isinstance(raw_edges, list) or any(
        not isinstance(row, Mapping) for row in raw_edges
    ):
        raise SemanticInductionError("semantic edge inventory is malformed")
    if raw_edges:
        result: list[tuple[Mapping[str, object], int]] = []
        for row in raw_edges:
            target = row.get("target_rva")
            condition = row.get("condition")
            if (
                not isinstance(target, int)
                or isinstance(target, bool)
                or not isinstance(condition, Mapping)
            ):
                raise SemanticInductionError("semantic direct edge is malformed")
            result.append((condition, target))
        return tuple(result)
    outcome = _object(semantics.get("outcome"), "semantic outcome")
    target = outcome.get("target_rva")
    if isinstance(target, int) and not isinstance(target, bool):
        return (({"op": "true"}, target),)
    return ()


def _reachable(
    roots: Sequence[str],
    outgoing: Mapping[str, Sequence[tuple[str, Mapping[str, object]]]],
) -> set[str]:
    visited: set[str] = set()
    pending = list(roots)
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        pending.extend(target for target, _condition in outgoing.get(current, ()))
    return visited


def _reverse(
    outgoing: Mapping[str, Sequence[tuple[str, Mapping[str, object]]]],
) -> dict[str, tuple[tuple[str, Mapping[str, object]], ...]]:
    result: dict[str, list[tuple[str, Mapping[str, object]]]] = defaultdict(list)
    for source, targets in outgoing.items():
        result.setdefault(source, [])
        for target, condition in targets:
            result[target].append((source, condition))
    return {key: tuple(value) for key, value in result.items()}


def _tarjan(
    unit_ids: Sequence[str],
    outgoing: Mapping[str, Sequence[tuple[str, Mapping[str, object]]]],
) -> tuple[tuple[str, ...], ...]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

    def visit(unit_id: str) -> None:
        nonlocal index
        indices[unit_id] = index
        lowlinks[unit_id] = index
        index += 1
        stack.append(unit_id)
        on_stack.add(unit_id)
        for target, _condition in outgoing[unit_id]:
            if target not in indices:
                visit(target)
                lowlinks[unit_id] = min(lowlinks[unit_id], lowlinks[target])
            elif target in on_stack:
                lowlinks[unit_id] = min(lowlinks[unit_id], indices[target])
        if lowlinks[unit_id] != indices[unit_id]:
            return
        component: list[str] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == unit_id:
                break
        components.append(tuple(sorted(component)))

    for unit_id in sorted(unit_ids):
        if unit_id not in indices:
            visit(unit_id)
    return tuple(components)


def _scc_id(operation_id: str, member_unit_ids: Sequence[str]) -> str:
    digest = canonical_sha256_v3(
        {"operation_id": operation_id, "member_unit_ids": list(member_unit_ids)}
    )
    return f"component-scc-v1:{digest}"


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticInductionError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, Mapping) for row in value):
        raise SemanticInductionError(f"{context} must be an array of objects")
    return list(value)


def _identities(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise SemanticInductionError(f"{context} must be an array of strings")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise SemanticInductionError(f"{context} contains duplicates")
    return result


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticInductionError(f"{context} must be a nonempty string")
    return value


__all__ = [
    "INDUCTIVE_MACHINE_SHAPE_V1",
    "INDUCTIVE_SEGMENT_INVENTORY_V1",
    "SemanticInductionError",
    "build_inductive_machine_shape",
    "build_inductive_segment_inventory",
]
