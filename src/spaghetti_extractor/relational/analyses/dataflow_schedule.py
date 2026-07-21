from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .dataflow import (
    StableDataflowGraph,
    StableDataflowPack,
)


_PACK_REGION_BUDGET = 128
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


@dataclass(frozen=True)
class StableDataflowSchedule:
    topological_pack_ids: tuple[str, ...]
    packs: tuple[StableDataflowPack, ...]


def stable_dataflow_schedule(
    graph: StableDataflowGraph,
    *,
    region_budget: int = _PACK_REGION_BUDGET,
) -> StableDataflowSchedule:
    """Derive bounded solver packs without changing the semantic graph."""
    if region_budget <= 0:
        raise ValueError("dataflow schedule region budget must be positive")
    components = graph.components
    component_index_by_id = {
        component.id: index for index, component in enumerate(components)
    }
    component_depth: dict[str, int] = {}
    for component_id in graph.topological_component_ids:
        component = components[component_index_by_id[component_id]]
        component_depth[component_id] = max(
            (
                component_depth[predecessor_id] + 1
                for predecessor_id in component.predecessor_ids
            ),
            default=0,
        )

    # Grow a predecessor pack only when every incoming component is already in
    # that one pack. This contracts lineage without merging independent
    # branches or introducing quotient cycles. Components that cannot extend a
    # lineage retain deterministic same-depth hash buckets, preserving useful
    # solver parallelism and stable cache identities.
    mutable_pack_components: list[list[int]] = []
    pack_region_counts: list[int] = []
    pack_by_component: dict[int, int] = {}
    fallback_packs: dict[tuple[int, str, int], list[int]] = {}

    def new_pack(component_index: int) -> int:
        pack_index = len(mutable_pack_components)
        mutable_pack_components.append([component_index])
        pack_region_counts.append(
            len(components[component_index].region_indices)
        )
        pack_by_component[component_index] = pack_index
        return pack_index

    ordered_component_indices = sorted(
        range(len(components)),
        key=lambda index: (
            component_depth[components[index].id],
            components[index].id,
        ),
    )
    for component_index in ordered_component_indices:
        component = components[component_index]
        member_count = len(component.region_indices)
        predecessor_pack_indices = {
            pack_by_component[component_index_by_id[predecessor_id]]
            for predecessor_id in component.predecessor_ids
        }
        if len(predecessor_pack_indices) == 1:
            predecessor_pack_index = next(iter(predecessor_pack_indices))
            if (
                member_count <= region_budget
                and pack_region_counts[predecessor_pack_index] + member_count
                <= region_budget
            ):
                mutable_pack_components[predecessor_pack_index].append(
                    component_index
                )
                pack_region_counts[predecessor_pack_index] += member_count
                pack_by_component[component_index] = predecessor_pack_index
                continue

        if member_count > region_budget:
            new_pack(component_index)
            continue
        bucket = int(
            component.id.removeprefix("register-scc-")[:8], 16
        ) % _PACK_HASH_BUCKET_COUNT
        fallback_key = (
            component_depth[component.id],
            component.resource_class,
            bucket,
        )
        candidate_pack_index = next(
            (
                pack_index
                for pack_index in reversed(
                    fallback_packs.get(fallback_key, [])
                )
                if pack_region_counts[pack_index] + member_count
                <= region_budget
            ),
            None,
        )
        if candidate_pack_index is None:
            candidate_pack_index = new_pack(component_index)
            fallback_packs.setdefault(fallback_key, []).append(
                candidate_pack_index
            )
        else:
            mutable_pack_components[candidate_pack_index].append(component_index)
            pack_region_counts[candidate_pack_index] += member_count
            pack_by_component[component_index] = candidate_pack_index

    pack_component_indices = tuple(
        tuple(sorted(indices, key=lambda index: components[index].id))
        for indices in mutable_pack_components
    )
    pack_ids = tuple(
        "register-pack-" + _canonical_sha256({
            "profile": "stage-a-register-dataflow-pack-v1",
            "component_ids": sorted(
                components[index].id for index in indices
            ),
        })
        for indices in pack_component_indices
    )
    pack_by_component = {
        component_index: pack_index
        for pack_index, indices in enumerate(pack_component_indices)
        for component_index in indices
    }
    predecessor_pack_indices = tuple(
        tuple(sorted({
            pack_by_component[component_index_by_id[predecessor_id]]
            for component_index in indices
            for predecessor_id in components[component_index].predecessor_ids
            if (
                pack_by_component[component_index_by_id[predecessor_id]]
                != pack_index
            )
        }))
        for pack_index, indices in enumerate(pack_component_indices)
    )
    successor_pack_indices: list[set[int]] = [
        set() for _ in pack_component_indices
    ]
    for pack_index, predecessor_indices in enumerate(predecessor_pack_indices):
        for predecessor_index in predecessor_indices:
            successor_pack_indices[predecessor_index].add(pack_index)

    remaining_predecessors = [
        len(predecessors) for predecessors in predecessor_pack_indices
    ]
    ready = [
        index
        for index, predecessor_count in enumerate(remaining_predecessors)
        if predecessor_count == 0
    ]
    topological_pack_indices: list[int] = []
    pack_depths = [0] * len(pack_component_indices)
    while ready:
        pack_index = min(ready, key=lambda index: pack_ids[index])
        ready.remove(pack_index)
        topological_pack_indices.append(pack_index)
        pack_depths[pack_index] = max(
            (
                pack_depths[predecessor_index] + 1
                for predecessor_index in predecessor_pack_indices[pack_index]
            ),
            default=0,
        )
        for successor_index in sorted(
            successor_pack_indices[pack_index],
            key=lambda index: pack_ids[index],
        ):
            remaining_predecessors[successor_index] -= 1
            if remaining_predecessors[successor_index] == 0:
                ready.append(successor_index)
    if len(topological_pack_indices) != len(pack_component_indices):
        raise AssertionError("dataflow pack quotient graph contains a cycle")

    packs = tuple(
        StableDataflowPack(
            id=pack_ids[pack_index],
            component_ids=tuple(
                sorted(components[index].id for index in indices)
            ),
            predecessor_ids=tuple(
                sorted(
                    pack_ids[index]
                    for index in predecessor_pack_indices[pack_index]
                )
            ),
            topological_depth=pack_depths[pack_index],
            region_count=sum(
                len(components[index].region_indices) for index in indices
            ),
            local_semantics_sha256=_canonical_sha256({
                "profile": "stage-a-register-dataflow-pack-semantics-v1",
                "components": sorted(
                    (
                        components[index].id,
                        components[index].local_semantics_sha256,
                        components[index].boundary_sha256,
                    )
                    for index in indices
                ),
            }),
            resource_class=_resource_class(sum(
                len(components[index].region_indices) for index in indices
            )),
        )
        for pack_index, indices in enumerate(pack_component_indices)
    )
    return StableDataflowSchedule(
        topological_pack_ids=tuple(
            pack_ids[index] for index in topological_pack_indices
        ),
        packs=packs,
    )


__all__ = [
    "StableDataflowSchedule",
    "stable_dataflow_schedule",
]
