from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True)
class StronglyConnectedComponents:
    components: tuple[tuple[int, ...], ...]
    component_by_region: tuple[int, ...]
    predecessor_component_ids: tuple[tuple[int, ...], ...]
    successor_component_ids: tuple[tuple[int, ...], ...]
    source_component_ids: tuple[int, ...]
    topological_component_ids: tuple[int, ...]


@dataclass(frozen=True)
class StableDataflowComponent:
    id: str
    region_ids: tuple[str, ...]
    region_indices: tuple[int, ...]
    predecessor_ids: tuple[str, ...]
    successor_ids: tuple[str, ...]
    local_semantics_sha256: str
    boundary_sha256: str
    resource_class: str

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "region_ids": list(self.region_ids),
            "region_indices": list(self.region_indices),
            "predecessor_ids": list(self.predecessor_ids),
            "successor_ids": list(self.successor_ids),
            "local_semantics_sha256": self.local_semantics_sha256,
            "boundary_sha256": self.boundary_sha256,
            "resource_class": self.resource_class,
        }


@dataclass(frozen=True)
class StableDataflowPack:
    id: str
    component_ids: tuple[str, ...]
    predecessor_ids: tuple[str, ...]
    topological_depth: int
    region_count: int
    local_semantics_sha256: str
    resource_class: str

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "component_ids": list(self.component_ids),
            "predecessor_ids": list(self.predecessor_ids),
            "topological_depth": self.topological_depth,
            "region_count": self.region_count,
            "local_semantics_sha256": self.local_semantics_sha256,
            "resource_class": self.resource_class,
        }


@dataclass(frozen=True)
class StableDataflowGraph:
    region_count: int
    graph_sha256: str
    topological_component_ids: tuple[str, ...]
    components: tuple[StableDataflowComponent, ...]
    topological_pack_ids: tuple[str, ...]
    packs: tuple[StableDataflowPack, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "format": "stage-a-register-dataflow-graph-v1",
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
            "region_count": self.region_count,
            "component_count": len(self.components),
            "graph_sha256": self.graph_sha256,
            "topological_component_ids": list(
                self.topological_component_ids
            ),
            "components": [
                component.to_payload() for component in self.components
            ],
            "pack_count": len(self.packs),
            "topological_pack_ids": list(self.topological_pack_ids),
            "packs": [pack.to_payload() for pack in self.packs],
        }


_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PACK_HASH_BUCKET_COUNT = 4


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _resource_class(region_count: int) -> str:
    if region_count <= 64:
        return "small"
    if region_count <= 512:
        return "medium"
    return "large"


def strongly_connected_components(
    successors: Sequence[Iterable[int]],
) -> StronglyConnectedComponents:
    """Return a deterministic SCC partition and its source components."""
    region_count = len(successors)
    normalized = tuple(
        tuple(sorted(set(int(target) for target in targets)))
        for targets in successors
    )
    if any(
        target < 0 or target >= region_count
        for targets in normalized
        for target in targets
    ):
        raise ValueError("dataflow successor is outside the region inventory")

    predecessors: list[list[int]] = [[] for _ in range(region_count)]
    for source, targets in enumerate(normalized):
        for target in targets:
            predecessors[target].append(source)

    visited = [False] * region_count
    finish_order: list[int] = []
    for root in range(region_count):
        if visited[root]:
            continue
        visited[root] = True
        stack: list[tuple[int, int]] = [(root, 0)]
        while stack:
            region, successor_index = stack[-1]
            targets = normalized[region]
            if successor_index < len(targets):
                target = targets[successor_index]
                stack[-1] = (region, successor_index + 1)
                if not visited[target]:
                    visited[target] = True
                    stack.append((target, 0))
                continue
            finish_order.append(region)
            stack.pop()

    assigned = [False] * region_count
    discovered: list[tuple[int, ...]] = []
    for root in reversed(finish_order):
        if assigned[root]:
            continue
        assigned[root] = True
        component: list[int] = []
        stack = [(root, 0)]
        while stack:
            member, predecessor_index = stack[-1]
            member_predecessors = predecessors[member]
            if predecessor_index < len(member_predecessors):
                predecessor = member_predecessors[predecessor_index]
                stack[-1] = (member, predecessor_index + 1)
                if not assigned[predecessor]:
                    assigned[predecessor] = True
                    stack.append((predecessor, 0))
                continue
            component.append(member)
            stack.pop()
        discovered.append(tuple(sorted(component)))

    components = tuple(sorted(discovered, key=lambda component: component[0]))
    component_by_region = [-1] * region_count
    for component_id, component in enumerate(components):
        for region in component:
            component_by_region[region] = component_id
    incoming_components: list[set[int]] = [set() for _ in components]
    outgoing_components: list[set[int]] = [set() for _ in components]
    for source, targets in enumerate(normalized):
        source_component = component_by_region[source]
        for target in targets:
            target_component = component_by_region[target]
            if source_component != target_component:
                incoming_components[target_component].add(source_component)
                outgoing_components[source_component].add(target_component)
    source_component_ids = tuple(
        component_id
        for component_id, incoming in enumerate(incoming_components)
        if not incoming
    )
    remaining_predecessors = [len(incoming) for incoming in incoming_components]
    ready = list(source_component_ids)
    topological_component_ids: list[int] = []
    while ready:
        component_id = min(ready)
        ready.remove(component_id)
        topological_component_ids.append(component_id)
        for successor_id in sorted(outgoing_components[component_id]):
            remaining_predecessors[successor_id] -= 1
            if remaining_predecessors[successor_id] == 0:
                ready.append(successor_id)
    if len(topological_component_ids) != len(components):
        raise AssertionError("SCC condensation graph contains a cycle")
    return StronglyConnectedComponents(
        components=components,
        component_by_region=tuple(component_by_region),
        predecessor_component_ids=tuple(
            tuple(sorted(incoming)) for incoming in incoming_components
        ),
        successor_component_ids=tuple(
            tuple(sorted(outgoing)) for outgoing in outgoing_components
        ),
        source_component_ids=source_component_ids,
        topological_component_ids=tuple(topological_component_ids),
    )


def stable_dataflow_graph(
    successors: Sequence[Iterable[int]],
    *,
    region_ids: Sequence[str],
    transfer_semantics_sha256: Sequence[str],
) -> StableDataflowGraph:
    """Bind an SCC DAG to stable region and local-transfer identities."""
    region_count = len(successors)
    if (
        len(region_ids) != region_count
        or len(transfer_semantics_sha256) != region_count
    ):
        raise ValueError("dataflow identity inventories do not match the region count")
    if any(
        not isinstance(region_id, str) or not region_id
        for region_id in region_ids
    ):
        raise ValueError("dataflow region identities must be non-empty strings")
    if len(set(region_ids)) != region_count:
        raise ValueError("dataflow region identities must be unique")
    if any(
        not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None
        for digest in transfer_semantics_sha256
    ):
        raise ValueError("dataflow transfer identities must be SHA-256 digests")

    normalized = tuple(
        tuple(sorted(set(int(target) for target in targets)))
        for targets in successors
    )
    partition = strongly_connected_components(normalized)
    component_stable_ids = tuple(
        "register-scc-" + _canonical_sha256({
            "profile": "stage-a-register-dataflow-scc-v1",
            "region_ids": sorted(region_ids[index] for index in component),
        })
        for component in partition.components
    )
    remaining_predecessors = [
        len(predecessors)
        for predecessors in partition.predecessor_component_ids
    ]
    ready_components = list(partition.source_component_ids)
    stable_topological_component_indices: list[int] = []
    while ready_components:
        component_index = min(
            ready_components, key=lambda index: component_stable_ids[index]
        )
        ready_components.remove(component_index)
        stable_topological_component_indices.append(component_index)
        for successor_index in partition.successor_component_ids[component_index]:
            remaining_predecessors[successor_index] -= 1
            if remaining_predecessors[successor_index] == 0:
                ready_components.append(successor_index)
    rows: list[StableDataflowComponent] = []
    for component_index, component in enumerate(partition.components):
        component_members = set(component)
        internal_edges = sorted(
            (region_ids[source], region_ids[target])
            for source in component
            for target in normalized[source]
            if target in component_members
        )
        incoming_edges = sorted(
            (region_ids[source], region_ids[target])
            for source, targets in enumerate(normalized)
            if source not in component_members
            for target in targets
            if target in component_members
        )
        outgoing_edges = sorted(
            (region_ids[source], region_ids[target])
            for source in component
            for target in normalized[source]
            if target not in component_members
        )
        member_transfers = sorted(
            (region_ids[index], transfer_semantics_sha256[index])
            for index in component
        )
        member_count = len(component)
        rows.append(StableDataflowComponent(
            id=component_stable_ids[component_index],
            region_ids=tuple(sorted(region_ids[index] for index in component)),
            region_indices=component,
            predecessor_ids=tuple(
                sorted(
                    component_stable_ids[index]
                    for index in partition.predecessor_component_ids[
                        component_index
                    ]
                )
            ),
            successor_ids=tuple(
                sorted(
                    component_stable_ids[index]
                    for index in partition.successor_component_ids[
                        component_index
                    ]
                )
            ),
            local_semantics_sha256=_canonical_sha256({
                "profile": "stage-a-register-dataflow-local-semantics-v1",
                "transfers": member_transfers,
                "internal_edges": internal_edges,
            }),
            boundary_sha256=_canonical_sha256({
                "profile": "stage-a-register-dataflow-boundary-v1",
                "incoming_edges": incoming_edges,
                "outgoing_edges": outgoing_edges,
            }),
            resource_class=(
                "small" if member_count <= 8
                else "medium" if member_count <= 64
                else "large"
            ),
        ))
    component_depths = [0] * len(rows)
    for component_index in stable_topological_component_indices:
        component_depths[component_index] = max(
            (
                component_depths[predecessor_index] + 1
                for predecessor_index in partition.predecessor_component_ids[
                    component_index
                ]
            ),
            default=0,
        )
    grouped_components: dict[tuple[int, str, int], list[int]] = {}
    for component_index, row in enumerate(rows):
        if row.resource_class == "large":
            group = (component_depths[component_index], "large", component_index)
        else:
            bucket = (
                int(row.id.removeprefix("register-scc-")[:8], 16)
                % _PACK_HASH_BUCKET_COUNT
            )
            group = (component_depths[component_index], row.resource_class, bucket)
        grouped_components.setdefault(group, []).append(component_index)
    pack_component_indices: list[tuple[int, ...]] = []
    for (_depth, resource_class, _bucket), component_indices in sorted(
        grouped_components.items()
    ):
        ordered = sorted(
            component_indices, key=lambda index: rows[index].id
        )
        maximum_components = 1 if resource_class == "large" else (
            8 if resource_class == "medium" else 64
        )
        pack_component_indices.extend(
            tuple(ordered[offset : offset + maximum_components])
            for offset in range(0, len(ordered), maximum_components)
        )
    pack_ids = tuple(
        "register-pack-" + _canonical_sha256({
            "profile": "stage-a-register-dataflow-pack-v1",
            "component_ids": sorted(rows[index].id for index in indices),
        })
        for indices in pack_component_indices
    )
    pack_by_component = {
        component_index: pack_index
        for pack_index, indices in enumerate(pack_component_indices)
        for component_index in indices
    }
    packs: list[StableDataflowPack] = []
    for pack_index, indices in enumerate(pack_component_indices):
        predecessor_pack_indices = sorted({
            pack_by_component[predecessor_index]
            for component_index in indices
            for predecessor_index in partition.predecessor_component_ids[
                component_index
            ]
            if pack_by_component[predecessor_index] != pack_index
        })
        pack_region_count = sum(
            len(rows[index].region_indices) for index in indices
        )
        packs.append(StableDataflowPack(
            id=pack_ids[pack_index],
            component_ids=tuple(sorted(rows[index].id for index in indices)),
            predecessor_ids=tuple(
                sorted(pack_ids[index] for index in predecessor_pack_indices)
            ),
            topological_depth=max(component_depths[index] for index in indices),
            region_count=pack_region_count,
            local_semantics_sha256=_canonical_sha256({
                "profile": "stage-a-register-dataflow-pack-semantics-v1",
                "components": sorted(
                    (
                        rows[index].id,
                        rows[index].local_semantics_sha256,
                        rows[index].boundary_sha256,
                    )
                    for index in indices
                ),
            }),
            resource_class=_resource_class(pack_region_count),
        ))
    topological_pack_ids = tuple(
        pack.id
        for pack in sorted(
            packs, key=lambda pack: (pack.topological_depth, pack.id)
        )
    )
    component_hash_rows = []
    for row in sorted(rows, key=lambda component: component.id):
        payload = row.to_payload()
        del payload["region_indices"]
        component_hash_rows.append(payload)
    stable_topological_component_ids = tuple(
        component_stable_ids[index]
        for index in stable_topological_component_indices
    )
    graph_without_digest = {
        "profile": "stage-a-register-dataflow-graph-v1",
        "region_ids": sorted(region_ids),
        "topological_component_ids": list(stable_topological_component_ids),
        "components": component_hash_rows,
        "topological_pack_ids": list(topological_pack_ids),
        "packs": [
            pack.to_payload() for pack in sorted(packs, key=lambda pack: pack.id)
        ],
    }
    return StableDataflowGraph(
        region_count=region_count,
        graph_sha256=_canonical_sha256(graph_without_digest),
        topological_component_ids=stable_topological_component_ids,
        components=tuple(rows),
        topological_pack_ids=topological_pack_ids,
        packs=tuple(packs),
    )


__all__ = [
    "StableDataflowComponent",
    "StableDataflowGraph",
    "StableDataflowPack",
    "StronglyConnectedComponents",
    "stable_dataflow_graph",
    "strongly_connected_components",
]
