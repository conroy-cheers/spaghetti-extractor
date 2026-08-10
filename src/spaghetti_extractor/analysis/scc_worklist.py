"""Deterministic strongly connected components and dependency scheduling.

Edges accepted by :class:`SCCWorklist` are oriented from a dependency to its
dependent.  This makes the canonical topological component order directly
usable as an evaluation order.
"""

from __future__ import annotations

import dataclasses
import enum
import math
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar


NodeT = TypeVar("NodeT", bound=Hashable)
NodeKey = Callable[[NodeT], object]
Edge = tuple[NodeT, NodeT]


def _stable_token(value: object) -> tuple[object, ...]:
    """Return a totally ordered structural token or reject unstable values."""

    if value is None:
        return ("none",)
    if isinstance(value, bool):
        return ("bool", int(value))
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        if math.isnan(value):
            return ("float", "nan")
        if math.isinf(value):
            return ("float", "inf" if value > 0 else "-inf")
        return ("float", value.hex())
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, enum.Enum):
        return (
            "enum",
            type(value).__module__,
            type(value).__qualname__,
            _stable_token(value.value),
        )
    if isinstance(value, tuple):
        return ("tuple", *(_stable_token(item) for item in value))
    if isinstance(value, frozenset):
        return ("frozenset", *sorted(_stable_token(item) for item in value))
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            "dataclass",
            type(value).__module__,
            type(value).__qualname__,
            *(
                (field.name, _stable_token(getattr(value, field.name)))
                for field in dataclasses.fields(value)
            ),
        )
    raise TypeError(
        f"no deterministic ordering for {type(value).__qualname__}; "
        "supply a key function"
    )


def deterministic_node_key(node: Hashable) -> tuple[object, ...]:
    """Default structural ordering for common immutable node identifiers."""

    return _stable_token(node)


def _node_order(
    nodes: Iterable[NodeT], key: NodeKey[NodeT] | None
) -> tuple[tuple[NodeT, ...], dict[NodeT, tuple[object, ...]]]:
    key_fn = deterministic_node_key if key is None else key
    tokens = {node: _stable_token(key_fn(node)) for node in nodes}
    by_token: dict[tuple[object, ...], NodeT] = {}
    for node, token in tokens.items():
        previous = by_token.get(token)
        if previous is not None and previous != node:
            raise ValueError("node key function must give every node a unique key")
        by_token[token] = node
    return tuple(sorted(tokens, key=tokens.__getitem__)), tokens


def _materialize_graph(
    nodes: Iterable[NodeT] | Mapping[NodeT, Iterable[NodeT]],
    edges: Iterable[Edge[NodeT]],
) -> tuple[set[NodeT], set[Edge[NodeT]]]:
    materialized_edges = set(edges)
    if isinstance(nodes, Mapping):
        materialized_nodes = set(nodes)
        for source, targets in nodes.items():
            for target in targets:
                materialized_edges.add((source, target))
    else:
        materialized_nodes = set(nodes)
    for source, target in materialized_edges:
        materialized_nodes.add(source)
        materialized_nodes.add(target)
    return materialized_nodes, materialized_edges


@dataclass(frozen=True)
class SCCDecomposition(Generic[NodeT]):
    """An immutable SCC partition and its canonical condensation DAG."""

    components: tuple[tuple[NodeT, ...], ...]
    condensation_edges: tuple[tuple[int, int], ...]

    def component_index(self, node: NodeT) -> int:
        for index, component in enumerate(self.components):
            if node in component:
                return index
        raise KeyError(node)

    def component(self, node: NodeT) -> tuple[NodeT, ...]:
        return self.components[self.component_index(node)]

    def successors(self, component_index: int) -> tuple[int, ...]:
        self._check_component_index(component_index)
        return tuple(
            target
            for source, target in self.condensation_edges
            if source == component_index
        )

    def predecessors(self, component_index: int) -> tuple[int, ...]:
        self._check_component_index(component_index)
        return tuple(
            source
            for source, target in self.condensation_edges
            if target == component_index
        )

    def project(
        self, project_node: Callable[[NodeT], Any] | None = None
    ) -> dict[str, Any]:
        projector = (lambda node: node) if project_node is None else project_node
        return {
            "components": [
                [projector(node) for node in component]
                for component in self.components
            ],
            "edges": [list(edge) for edge in self.condensation_edges],
        }

    def _check_component_index(self, component_index: int) -> None:
        if not 0 <= component_index < len(self.components):
            raise IndexError(component_index)


def decompose_scc(
    nodes: Iterable[NodeT] | Mapping[NodeT, Iterable[NodeT]],
    edges: Iterable[Edge[NodeT]] = (),
    *,
    key: NodeKey[NodeT] | None = None,
) -> SCCDecomposition[NodeT]:
    """Compute SCCs with deterministic members and topological component IDs."""

    node_set, edge_set = _materialize_graph(nodes, edges)
    ordered_nodes, tokens = _node_order(node_set, key)
    target_sets: dict[NodeT, set[NodeT]] = {
        node: set() for node in ordered_nodes
    }
    for source, target in edge_set:
        target_sets[source].add(target)
    outgoing = {
        node: tuple(sorted(target_sets[node], key=tokens.__getitem__))
        for node in ordered_nodes
    }

    next_index = 0
    indices: dict[NodeT, int] = {}
    lowlinks: dict[NodeT, int] = {}
    stack: list[NodeT] = []
    on_stack: set[NodeT] = set()
    raw_components: list[tuple[NodeT, ...]] = []

    def visit(node: NodeT) -> None:
        nonlocal next_index
        indices[node] = next_index
        lowlinks[node] = next_index
        next_index += 1
        stack.append(node)
        on_stack.add(node)

        for target in outgoing[node]:
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])

        if lowlinks[node] != indices[node]:
            return
        members: list[NodeT] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            members.append(member)
            if member == node:
                break
        raw_components.append(tuple(sorted(members, key=tokens.__getitem__)))

    for node in ordered_nodes:
        if node not in indices:
            visit(node)

    raw_index = {
        node: component_index
        for component_index, component in enumerate(raw_components)
        for node in component
    }
    raw_edges = {
        (raw_index[source], raw_index[target])
        for source, target in edge_set
        if raw_index[source] != raw_index[target]
    }
    component_tokens = {
        index: tuple(tokens[node] for node in component)
        for index, component in enumerate(raw_components)
    }
    indegree = {index: 0 for index in range(len(raw_components))}
    raw_successors: dict[int, set[int]] = {
        index: set() for index in range(len(raw_components))
    }
    for source, target in raw_edges:
        raw_successors[source].add(target)
        indegree[target] += 1

    ready = {index for index, degree in indegree.items() if degree == 0}
    topological: list[int] = []
    while ready:
        component_index = min(ready, key=component_tokens.__getitem__)
        ready.remove(component_index)
        topological.append(component_index)
        for target in sorted(
            raw_successors[component_index], key=component_tokens.__getitem__
        ):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.add(target)

    canonical_index = {
        raw_component: index
        for index, raw_component in enumerate(topological)
    }
    components = tuple(raw_components[index] for index in topological)
    condensation_edges = tuple(
        sorted(
            (
                canonical_index[source],
                canonical_index[target],
            )
            for source, target in raw_edges
        )
    )
    return SCCDecomposition(components, condensation_edges)


def strongly_connected_components(
    nodes: Iterable[NodeT] | Mapping[NodeT, Iterable[NodeT]],
    edges: Iterable[Edge[NodeT]] = (),
    *,
    key: NodeKey[NodeT] | None = None,
) -> tuple[tuple[NodeT, ...], ...]:
    """Return only the canonical SCC partition."""

    return decompose_scc(nodes, edges, key=key).components


def condensation_graph(
    nodes: Iterable[NodeT] | Mapping[NodeT, Iterable[NodeT]],
    edges: Iterable[Edge[NodeT]] = (),
    *,
    key: NodeKey[NodeT] | None = None,
) -> SCCDecomposition[NodeT]:
    """Return the SCC partition together with its condensation edges."""

    return decompose_scc(nodes, edges, key=key)


class SCCWorklist(Generic[NodeT]):
    """A deterministic component worklist for a growing dependency graph.

    Each edge is ``(dependency, dependent)``.  A new edge invalidates the new
    dependent's SCC and every transitively dependent SCC.  If the edge closes
    a cycle, the complete newly merged SCC is invalidated.
    """

    def __init__(
        self,
        nodes: Iterable[NodeT] = (),
        edges: Iterable[Edge[NodeT]] = (),
        *,
        key: NodeKey[NodeT] | None = None,
        schedule_all: bool = True,
    ) -> None:
        self._key = key
        self._nodes, self._edges = _materialize_graph(nodes, edges)
        self._decomposition = decompose_scc(
            self._nodes, self._edges, key=self._key
        )
        self._pending: set[NodeT] = set(self._nodes) if schedule_all else set()

    @property
    def decomposition(self) -> SCCDecomposition[NodeT]:
        return self._decomposition

    @property
    def edges(self) -> frozenset[Edge[NodeT]]:
        return frozenset(self._edges)

    @property
    def pending_components(self) -> tuple[tuple[NodeT, ...], ...]:
        return tuple(
            component
            for component in self._decomposition.components
            if any(node in self._pending for node in component)
        )

    def __bool__(self) -> bool:
        return bool(self._pending)

    def __len__(self) -> int:
        return len(self.pending_components)

    def pop(self) -> tuple[NodeT, ...]:
        """Pop the first pending SCC in dependency-first canonical order."""

        for component in self._decomposition.components:
            if any(node in self._pending for node in component):
                self._pending.difference_update(component)
                return component
        raise IndexError("pop from empty SCC worklist")

    def add_dependency(self, *, dependent: NodeT, dependency: NodeT) -> bool:
        """Add one dependency relation and invalidate facts affected by it."""

        return bool(self.add_edges(((dependency, dependent),)))

    def add_edge(self, dependency: NodeT, dependent: NodeT) -> bool:
        """Positional form of :meth:`add_dependency`."""

        return bool(self.add_edges(((dependency, dependent),)))

    def add_edges(
        self, edges: Iterable[Edge[NodeT]]
    ) -> tuple[tuple[NodeT, ...], ...]:
        """Grow the graph and return the components invalidated by new edges."""

        additions = set(edges) - self._edges
        if not additions:
            return ()
        old_nodes = set(self._nodes)
        self._edges.update(additions)
        for dependency, dependent in additions:
            self._nodes.add(dependency)
            self._nodes.add(dependent)
        self._decomposition = decompose_scc(
            self._nodes, self._edges, key=self._key
        )

        affected_components: set[int] = set()
        for node in self._nodes - old_nodes:
            affected_components.add(self._decomposition.component_index(node))
        for _dependency, dependent in additions:
            affected_components.add(
                self._decomposition.component_index(dependent)
            )
        affected_components = self._dependent_closure(affected_components)
        invalidated = tuple(
            component
            for index, component in enumerate(self._decomposition.components)
            if index in affected_components
        )
        self._pending.update(
            node for component in invalidated for node in component
        )
        return invalidated

    def invalidate(
        self,
        nodes: NodeT | Iterable[NodeT],
        *,
        include_dependents: bool = True,
    ) -> tuple[tuple[NodeT, ...], ...]:
        """Schedule complete SCCs containing ``nodes`` and optionally users."""

        materialized = self._as_nodes(nodes)
        component_indices = {
            self._decomposition.component_index(node) for node in materialized
        }
        if include_dependents:
            component_indices = self._dependent_closure(component_indices)
        invalidated = tuple(
            component
            for index, component in enumerate(self._decomposition.components)
            if index in component_indices
        )
        self._pending.update(
            node for component in invalidated for node in component
        )
        return invalidated

    def notify_changed(
        self, nodes: NodeT | Iterable[NodeT]
    ) -> tuple[tuple[NodeT, ...], ...]:
        """Schedule SCC peers and transitive dependents of changed facts."""

        materialized = self._as_nodes(nodes)
        changed_components = {
            self._decomposition.component_index(node) for node in materialized
        }
        affected = self._dependent_closure(changed_components)
        for component_index in tuple(changed_components):
            component = self._decomposition.components[component_index]
            if not component:
                raise RuntimeError("SCC decomposition produced an empty component")
            first = next(iter(component))
            cyclic = len(component) > 1 or any(
                source == first and target == first
                for source, target in self._edges
            )
            if not cyclic:
                affected.discard(component_index)
        invalidated = tuple(
            component
            for index, component in enumerate(self._decomposition.components)
            if index in affected
        )
        self._pending.update(
            node for component in invalidated for node in component
        )
        return invalidated

    def _dependent_closure(self, roots: set[int]) -> set[int]:
        successors: dict[int, set[int]] = {
            index: set() for index in range(len(self._decomposition.components))
        }
        for source, target in self._decomposition.condensation_edges:
            successors[source].add(target)
        reached = set(roots)
        work = list(roots)
        while work:
            source = work.pop()
            for target in successors[source]:
                if target not in reached:
                    reached.add(target)
                    work.append(target)
        return reached

    def _as_nodes(self, nodes: NodeT | Iterable[NodeT]) -> tuple[NodeT, ...]:
        try:
            if nodes in self._nodes:  # type: ignore[operator]
                return (nodes,)  # type: ignore[return-value]
        except TypeError:
            pass
        materialized = tuple(nodes)  # type: ignore[arg-type]
        unknown = set(materialized) - self._nodes
        if unknown:
            raise KeyError(next(iter(unknown)))
        return materialized


DependencyWorklist = SCCWorklist


__all__ = [
    "DependencyWorklist",
    "SCCDecomposition",
    "SCCWorklist",
    "condensation_graph",
    "decompose_scc",
    "deterministic_node_key",
    "strongly_connected_components",
]
