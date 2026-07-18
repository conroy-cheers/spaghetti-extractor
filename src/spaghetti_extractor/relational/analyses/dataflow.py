from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True)
class StronglyConnectedComponents:
    components: tuple[tuple[int, ...], ...]
    component_by_region: tuple[int, ...]
    source_component_ids: tuple[int, ...]


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
    for source, targets in enumerate(normalized):
        source_component = component_by_region[source]
        for target in targets:
            target_component = component_by_region[target]
            if source_component != target_component:
                incoming_components[target_component].add(source_component)
    return StronglyConnectedComponents(
        components=components,
        component_by_region=tuple(component_by_region),
        source_component_ids=tuple(
            component_id
            for component_id, incoming in enumerate(incoming_components)
            if not incoming
        ),
    )


__all__ = ["StronglyConnectedComponents", "strongly_connected_components"]
