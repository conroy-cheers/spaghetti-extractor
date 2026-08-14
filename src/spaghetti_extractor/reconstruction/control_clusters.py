"""Deterministic semantic cluster proposals over control graphs."""

from __future__ import annotations

import copy
from typing import Any, Mapping

from .control_common import _deduplicate_mappings, _is_u32, _stable_id
from .control_reachability import (
    _edge_endpoints,
    _source_unit_id,
    _unit_inventory,
)


def propose_semantic_clusters(
    *,
    units: Mapping[str, Any] | Sequence[str | Mapping[str, Any]],
    direct_edges: Sequence[Mapping[str, Any]],
    reachable_units: Iterable[str] | None = None,
    roots: Iterable[str] = (),
    internal_call_edges: Sequence[Mapping[str, Any]] = (),
    external_exits: Sequence[str | Mapping[str, Any]] = (),
    fault_exits: Sequence[str | Mapping[str, Any]] = (),
    indirect_exits: Sequence[str | Mapping[str, Any]] = (),
    max_cluster_units: int = 64,
) -> dict[str, Any]:
    """Propose deterministic loop SCCs and maximal straight-line clusters.

    Call, external, fault, and indirect sources are terminal cutpoints for this
    analysis.  Normal direct edges out of those units are kept as boundary
    metadata but are excluded from SCC and chain formation.  Cyclic SCCs are
    never split; an SCC larger than ``max_cluster_units`` is left unclustered
    and reported as incomplete instead of silently weakening its loop shape.
    """

    if max_cluster_units <= 0:
        raise ValueError("max_cluster_units must be positive")
    unit_ids, rva_index, issues = _unit_inventory(units)
    requested_reachable = (
        None
        if reachable_units is None
        else {str(unit_id) for unit_id in reachable_units}
    )
    active = set(unit_ids) if requested_reachable is None else requested_reachable & unit_ids
    if reachable_units is not None:
        assert requested_reachable is not None
        unknown = sorted(requested_reachable - unit_ids)
        issues.extend(
            {"code": "unknown_reachable_unit", "unit_id": unit_id}
            for unit_id in unknown
        )

    cutpoint_rows: set[tuple[str, str]] = set()
    for record in internal_call_edges:
        source = _source_unit_id(record)
        if source in active:
            cutpoint_rows.add((source, "call"))
    for kind, records in (
        ("external", external_exits),
        ("fault", fault_exits),
        ("indirect", indirect_exits),
    ):
        for record in records:
            source = str(record) if isinstance(record, str) else _source_unit_id(record)
            if source in active:
                cutpoint_rows.add((source, kind))

    all_direct: set[tuple[str, str]] = set()
    for record in direct_edges:
        parsed = _edge_endpoints(record, unit_ids, rva_index)
        source = _source_unit_id(record)
        if parsed is None:
            if source in active:
                cutpoint_rows.add((source, "external"))
            issues.append(
                {"code": "unresolved_direct_edge", "source_unit_id": source}
            )
            continue
        edge = parsed
        if edge[0] in active and edge[1] in active:
            all_direct.add(edge)

    cutpoint_sources = {source for source, _kind in cutpoint_rows}
    graph = {unit_id: [] for unit_id in sorted(active)}
    for source, target in sorted(all_direct):
        if source not in cutpoint_sources:
            graph[source].append(target)

    components = _strongly_connected_components(graph)
    cyclic_components: list[tuple[str, ...]] = []
    cyclic_units: set[str] = set()
    for component in components:
        cyclic = len(component) > 1 or (
            len(component) == 1 and component[0] in graph[component[0]]
        )
        if cyclic:
            cyclic_components.append(component)
            cyclic_units.update(component)

    groups: list[tuple[str, tuple[str, ...]]] = []
    oversized: set[str] = set()
    for component in sorted(cyclic_components):
        if len(component) > max_cluster_units:
            oversized.update(component)
            issues.append(
                {
                    "code": "oversized_loop_scc",
                    "unit_ids": list(component),
                    "limit": max_cluster_units,
                }
            )
        else:
            groups.append(("loop_scc", component))

    chain_nodes = active - cyclic_units
    chain_predecessors = {unit_id: [] for unit_id in chain_nodes}
    chain_successors = {unit_id: [] for unit_id in chain_nodes}
    for source, targets in graph.items():
        if source not in chain_nodes:
            continue
        for target in targets:
            if target in chain_nodes:
                chain_successors[source].append(target)
                chain_predecessors[target].append(source)
    for values in (*chain_predecessors.values(), *chain_successors.values()):
        values.sort()

    visited: set[str] = set()
    starts = [
        unit_id
        for unit_id in sorted(chain_nodes)
        if len(chain_predecessors[unit_id]) != 1
        or len(chain_successors[chain_predecessors[unit_id][0]]) != 1
    ]
    for start in starts:
        _append_bounded_chain_groups(
            start,
            chain_predecessors,
            chain_successors,
            visited,
            max_cluster_units,
            groups,
        )
    for start in sorted(chain_nodes - visited):
        _append_bounded_chain_groups(
            start,
            chain_predecessors,
            chain_successors,
            visited,
            max_cluster_units,
            groups,
        )

    groups.sort(key=lambda item: (item[1][0], item[0], item[1]))
    root_set = {str(root) for root in roots}
    cutpoints = [
        {"source_unit_id": source, "kind": kind}
        for source, kind in sorted(cutpoint_rows)
    ]
    clusters: list[dict[str, Any]] = []
    unit_to_cluster: dict[str, str] = {}
    for group_kind, members_tuple in groups:
        members = set(members_tuple)
        identity = _stable_id(
            "semantic-cluster",
            {"kind": group_kind, "unit_ids": list(members_tuple)},
        )
        entries = {
            target
            for source, target in all_direct
            if source not in members and target in members
        } | (members & root_set)
        exits = {
            source
            for source, target in all_direct
            if source in members and target not in members
        } | (members & cutpoint_sources)
        if not entries:
            entries.add(members_tuple[0])
        member_cutpoints = [
            row for row in cutpoints if row["source_unit_id"] in members
        ]
        cluster = {
            "id": identity,
            "kind": group_kind if len(members_tuple) > 1 else "singleton",
            "unit_ids": list(members_tuple),
            "entry_unit_ids": sorted(entries),
            "exit_unit_ids": sorted(exits),
            "cutpoints": member_cutpoints,
            "bounded": True,
        }
        clusters.append(cluster)
        for unit_id in members_tuple:
            unit_to_cluster[unit_id] = identity

    sorted_issues = _deduplicate_mappings(issues)
    unclustered = sorted((active - set(unit_to_cluster)) | oversized)
    return {
        "status": "incomplete" if sorted_issues or unclustered else "complete",
        "max_cluster_units": max_cluster_units,
        "clusters": clusters,
        "unit_to_cluster": dict(sorted(unit_to_cluster.items())),
        "cutpoints": cutpoints,
        "excluded_unit_ids": sorted(unit_ids - active),
        "unclustered_unit_ids": unclustered,
        "issues": sorted_issues,
        "counts": {
            "clusters": len(clusters),
            "loop_sccs": sum(cluster["kind"] == "loop_scc" for cluster in clusters),
            "clustered_units": len(unit_to_cluster),
            "unclustered_units": len(unclustered),
        },
    }


def _strongly_connected_components(graph: Mapping[str, Sequence[str]]) -> list[tuple[str, ...]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for successor in sorted(graph[node]):
            if successor not in indices:
                visit(successor)
                lowlinks[node] = min(lowlinks[node], lowlinks[successor])
            elif successor in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[successor])
        if lowlinks[node] == indices[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(tuple(sorted(component)))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return sorted(components)


def _append_bounded_chain_groups(
    start: str,
    predecessors: Mapping[str, Sequence[str]],
    successors: Mapping[str, Sequence[str]],
    visited: set[str],
    limit: int,
    groups: list[tuple[str, tuple[str, ...]]],
) -> None:
    current = start
    chunk: list[str] = []
    while current not in visited:
        visited.add(current)
        chunk.append(current)
        if len(chunk) == limit:
            groups.append(("straight_line_chain", tuple(chunk)))
            chunk = []
        outgoing = successors[current]
        if len(outgoing) != 1:
            break
        following = outgoing[0]
        if len(predecessors[following]) != 1 or following in visited:
            break
        current = following
    if chunk:
        groups.append(("straight_line_chain", tuple(chunk)))
