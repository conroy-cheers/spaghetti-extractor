"""Graph and boundary checks used by component discovery."""

from __future__ import annotations

from collections import deque
from typing import Any, Iterable, Mapping, Sequence

from .discovery_model import (
    _Edge,
    _Graph,
    _Inputs,
    _canonical_sha256,
    _issue,
    _mapping,
    _ordered_unit_ids,
    _unit_key,
)


def _straight_closure(
    inputs: _Inputs, graph: _Graph, seed: str, max_units: int
) -> frozenset[str]:
    members = {seed}
    current = seed
    while len(members) < max_units:
        unit = inputs.by_id[current]
        semantics = _mapping(unit.get("semantics"), "semantics")
        outcome = semantics.get("outcome")
        if not isinstance(outcome, Mapping) or outcome.get("kind") != "fallthrough":
            break
        if semantics.get("external_events"):
            break
        edges = graph.control_outgoing.get(current, ())
        if len(edges) != 1 or edges[0].target is None:
            break
        target = edges[0].target
        if target in members or len(graph.incoming.get(target, ())) != 1:
            break
        members.add(target)
        current = target
    current = seed
    while len(members) < max_units:
        predecessors = [
            edge
            for edge in graph.incoming.get(current, ())
            if edge.kind == "fallthrough" and edge.source not in members
        ]
        if len(predecessors) != 1:
            break
        predecessor = predecessors[0].source
        semantics = _mapping(inputs.by_id[predecessor].get("semantics"), "semantics")
        if semantics.get("external_events") or len(graph.control_outgoing.get(predecessor, ())) != 1:
            break
        members.add(predecessor)
        current = predecessor
    return frozenset(members)


def _single_entry_closure(
    inputs: _Inputs, graph: _Graph, seed: str, max_units: int
) -> frozenset[str]:
    """Return the seed-reachable region cut at every alternate entry.

    A loop SCC may have more than one incoming edge from the surrounding
    program.  Treating that entire SCC as one component would require a
    multi-entry replacement ABI.  Instead, first find the bounded forward
    closure, identify nodes with predecessors outside that closure, and stop
    traversal at those alternate entries.  The seed itself is always admitted
    because its outside predecessors are precisely its activation sites.
    """

    reachable: set[str] = set()
    queue = deque([seed])
    while queue:
        unit_id = queue.popleft()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        if len(reachable) > max_units:
            return frozenset({seed})
        outcome = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics").get(
            "outcome"
        )
        if isinstance(outcome, Mapping) and outcome.get("kind") in {
            "return",
            "fault",
            "termination",
        }:
            continue
        for edge in graph.control_outgoing.get(unit_id, ()):
            if edge.target is not None and edge.target not in reachable:
                queue.append(edge.target)

    alternate_entries = {
        unit_id
        for unit_id in reachable
        if unit_id != seed
        and (
            unit_id in graph.roots
            or any(
                edge.source not in reachable
                for edge in graph.incoming.get(unit_id, ())
            )
        )
    }
    members: set[str] = set()
    queue = deque([seed])
    while queue:
        unit_id = queue.popleft()
        if unit_id in members:
            continue
        members.add(unit_id)
        for edge in graph.control_outgoing.get(unit_id, ()):
            if (
                edge.target is not None
                and edge.target in reachable
                and edge.target not in alternate_entries
                and edge.target not in members
            ):
                queue.append(edge.target)

    # Cutting one alternate entry can expose a second entry that was reachable
    # only through the removed portion of a cycle.  Prune to a fixed point so
    # the proposal's checked boundary, rather than the initial reachability
    # approximation, is guaranteed to have one activation entry.
    while True:
        extra_entries = {
            unit_id
            for unit_id in members
            if unit_id != seed
            and (
                unit_id in graph.roots
                or any(
                    edge.source not in members
                    for edge in graph.incoming.get(unit_id, ())
                )
            )
        }
        if not extra_entries:
            break
        remove: set[str] = set()
        queue = deque(extra_entries)
        while queue:
            unit_id = queue.popleft()
            if unit_id == seed or unit_id in remove or unit_id not in members:
                continue
            remove.add(unit_id)
            for edge in graph.control_outgoing.get(unit_id, ()):
                if edge.target in members and edge.target != seed:
                    queue.append(str(edge.target))
        if not remove:
            break
        members.difference_update(remove)
    return frozenset(members)


def _callee_closure(
    inputs: _Inputs, graph: _Graph, entry: str, max_units: int
) -> frozenset[str]:
    members: set[str] = set()
    queue = deque([entry])
    while queue and len(members) < max_units:
        unit_id = queue.popleft()
        if unit_id in members:
            continue
        members.add(unit_id)
        outcome = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics").get(
            "outcome"
        )
        if isinstance(outcome, Mapping) and outcome.get("kind") in {
            "return",
            "fault",
            "termination",
        }:
            continue
        for edge in graph.control_outgoing.get(unit_id, ()):
            if edge.target is not None and edge.target not in members:
                queue.append(edge.target)
    return frozenset(members)


def _external_branch_closure(
    inputs: _Inputs, graph: _Graph, unit_id: str
) -> tuple[frozenset[str], str] | None:
    outcome = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics").get(
        "outcome"
    )
    if not isinstance(outcome, Mapping) or outcome.get("kind") != "branch":
        return None
    targets = [
        inputs.by_rva.get(outcome.get(name))
        for name in ("true_target_rva", "false_target_rva")
        if isinstance(outcome.get(name), int)
    ]
    if len(targets) != 2 or any(target is None for target in targets):
        return None
    paths = [_shortest_paths(graph, str(target), 64) for target in targets]
    common = set(paths[0]) & set(paths[1])
    if not common:
        return None
    join = min(
        common,
        key=lambda item: (
            len(paths[0][item]) + len(paths[1][item]),
            max(len(paths[0][item]), len(paths[1][item])),
            _unit_key(inputs.by_id[item]),
        ),
    )
    members = {unit_id}
    for path_map in paths:
        members.update(path_map[join][:-1])
    if not any(_has_external_event(inputs.by_id[item]) for item in members):
        return None
    return frozenset(members), join


def _finite_dispatch_closure(
    inputs: _Inputs, graph: _Graph, unit_id: str
) -> tuple[frozenset[str], str | None, dict[str, Any] | None] | None:
    certificate = graph.indirect.get(unit_id)
    if not _complete_indirect_certificate(certificate):
        return None
    assert certificate is not None
    targets = [str(value) for value in certificate.get("target_unit_ids", [])]
    if len(targets) < 2:
        return None
    path_maps = [_shortest_paths(graph, target, 64) for target in targets]
    common = set(path_maps[0])
    for path_map in path_maps[1:]:
        common.intersection_update(path_map)
    blocker = None
    members = {unit_id}
    join: str | None = None
    if common:
        join = min(
            common,
            key=lambda item: (
                max(len(path_map[item]) for path_map in path_maps),
                sum(len(path_map[item]) for path_map in path_maps),
                _unit_key(inputs.by_id[item]),
            ),
        )
        for path_map in path_maps:
            members.update(path_map[join][:-1])
    else:
        members.update(targets)
        blocker = _issue(
            inputs,
            unit_id,
            category="dispatch_arms_no_common_continuation",
            message="finite dispatch arms have no bounded common continuation",
            remediation=(
                "Provide an operator boundary for terminal arms or increase the checked path "
                "model before selecting this dispatch component."
            ),
            field="semantics.outcome.target",
            observed=len(targets),
            expected="bounded common continuation",
        )
    return frozenset(members), join, blocker


def _complete_indirect_certificate(
    certificate: Mapping[str, Any] | None,
) -> bool:
    if certificate is None:
        return False
    targets = certificate.get("target_unit_ids")
    return (
        certificate.get("status") == "recovered"
        and certificate.get("closure") == "checked_finite_target_inventory"
        and isinstance(targets, list)
        and bool(targets)
        and all(isinstance(target, str) and target for target in targets)
    )


def _object_closure(
    inputs: _Inputs, unit_id: str
) -> tuple[frozenset[str], list[str]]:
    seed_origins = _unit_object_origins(inputs.by_id[unit_id])
    if not seed_origins:
        return frozenset({unit_id}), []
    members = {unit_id}
    common: set[str] = set()
    for cluster_id in inputs.cluster_by_unit.get(unit_id, ()):
        for other in inputs.clusters[cluster_id]:
            shared = seed_origins & _unit_object_origins(inputs.by_id[other])
            if shared:
                members.add(other)
                common.update(shared)
    return frozenset(members), sorted(common)


def _epilogue_closure(
    inputs: _Inputs, graph: _Graph, unit_id: str, max_units: int
) -> frozenset[str]:
    members = {unit_id}
    current = unit_id
    while len(members) < max_units:
        predecessors = [
            edge
            for edge in graph.incoming.get(current, ())
            if edge.kind != "internal_call" and edge.source not in members
        ]
        if len(predecessors) != 1:
            break
        predecessor = predecessors[0].source
        if _has_external_event(inputs.by_id[predecessor]):
            break
        members.add(predecessor)
        current = predecessor
        if len(graph.incoming.get(current, ())) > 1:
            break
    for cluster_id in inputs.cluster_by_unit.get(unit_id, ()):
        cluster = inputs.clusters[cluster_id]
        if len(cluster) <= max_units and set(members).issubset(cluster):
            members.update(cluster)
            break
    return frozenset(members)


def _shortest_paths(graph: _Graph, start: str, limit: int) -> dict[str, tuple[str, ...]]:
    paths = {start: (start,)}
    queue = deque([start])
    while queue:
        source = queue.popleft()
        path = paths[source]
        if len(path) >= limit:
            continue
        for edge in graph.control_outgoing.get(source, ()):
            target = edge.target
            if target is None or target in paths:
                continue
            paths[target] = path + (target,)
            queue.append(target)
    return paths


def _strong_components(
    inputs: _Inputs, outgoing: Mapping[str, Sequence[_Edge]]
) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[tuple[str, ...]] = []

    def visit(unit_id: str) -> None:
        nonlocal index
        indices[unit_id] = index
        lowlinks[unit_id] = index
        index += 1
        stack.append(unit_id)
        on_stack.add(unit_id)
        for edge in outgoing.get(unit_id, ()):
            target = edge.target
            if target is None:
                continue
            if target not in indices:
                visit(target)
                lowlinks[unit_id] = min(lowlinks[unit_id], lowlinks[target])
            elif target in on_stack:
                lowlinks[unit_id] = min(lowlinks[unit_id], indices[target])
        if lowlinks[unit_id] == indices[unit_id]:
            members: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                members.append(member)
                if member == unit_id:
                    break
            components.append(
                tuple(sorted(members, key=lambda value: _unit_key(inputs.by_id[value])))
            )

    for unit_id in _ordered_unit_ids(inputs):
        if unit_id not in indices:
            visit(unit_id)
    components.sort(key=lambda members: _unit_key(inputs.by_id[members[0]]))
    sccs: dict[str, tuple[str, ...]] = {}
    by_unit: dict[str, str] = {}
    for members in components:
        identity = "scc:" + _canonical_sha256(list(members))[:20]
        sccs[identity] = members
        for member in members:
            by_unit[member] = identity
    return sccs, by_unit


def _outcome_targets(outcome: Mapping[str, Any]) -> list[tuple[str, int]]:
    kind = outcome.get("kind")
    fields = {
        "fallthrough": (("fallthrough", "target_rva"),),
        "jump": (("jump", "target_rva"),),
        "branch": (
            ("branch_true", "true_target_rva"),
            ("branch_false", "false_target_rva"),
        ),
    }.get(kind, ())
    return [
        (edge_kind, int(outcome[field]))
        for edge_kind, field in fields
        if isinstance(outcome.get(field), int)
    ]


def _suggested_control_form(
    inputs: _Inputs, graph: _Graph, members: frozenset[str]
) -> str:
    kinds = {
        str(
            _mapping(inputs.by_id[unit_id].get("semantics"), "semantics")
            .get("outcome", {})
            .get("kind", "")
        )
        for unit_id in members
    }
    if any(
        unit_id in graph.indirect
        and len(graph.indirect[unit_id].get("target_unit_ids", [])) > 1
        for unit_id in members
    ):
        return "finite_switch"
    if any(_has_external_event(inputs.by_id[unit_id]) for unit_id in members) and "branch" in kinds:
        return "conditional_external_service"
    if any(len(graph.sccs[graph.scc_by_unit[unit_id]]) > 1 for unit_id in members):
        return "structured_loop"
    if "branch" in kinds:
        return "conditional"
    if "return" in kinds:
        return "procedure"
    return "straight_line_operation"


def _semantic_expressions(semantics: Mapping[str, Any]) -> Iterable[Any]:
    outcome = semantics.get("outcome")
    if isinstance(outcome, Mapping):
        yield outcome.get("condition")
        yield outcome.get("target")
        yield outcome.get("value")
    for name in ("memory_events", "register_writes", "flag_writes", "external_events"):
        values = semantics.get(name, [])
        if isinstance(values, list):
            for value in values:
                yield value


def _expression_origins(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if isinstance(value, Mapping):
        if value.get("op") == "reg" and isinstance(value.get("name"), str):
            name = str(value["name"]).lower()
            result.add(("stack" if name in {"esp", "ebp"} else "register", name))
        elif value.get("op") == "flag" and isinstance(value.get("name"), str):
            result.add(("flag", str(value["name"]).lower()))
        for nested in value.values():
            result.update(_expression_origins(nested))
    elif isinstance(value, list):
        for nested in value:
            result.update(_expression_origins(nested))
    return result


def _address_origin(value: Any) -> str:
    origins = _expression_origins(value)
    stack = sorted(name for kind, name in origins if kind == "stack")
    registers = sorted(name for kind, name in origins if kind == "register")
    if stack:
        return "stack:" + "+".join(stack)
    if len(registers) == 1:
        return "register:" + registers[0]
    if len(registers) > 1:
        return "register-alternatives:" + "+".join(registers)
    constants = sorted(_expression_constants(value))
    if constants:
        return "static:" + "+".join(f"0x{item:x}" for item in constants[:3])
    return "unknown"


def _expression_constants(value: Any) -> set[int]:
    result: set[int] = set()
    if isinstance(value, Mapping):
        if value.get("op") == "const" and isinstance(value.get("value"), int):
            result.add(int(value["value"]))
        for nested in value.values():
            result.update(_expression_constants(nested))
    elif isinstance(value, list):
        for nested in value:
            result.update(_expression_constants(nested))
    return result


def _unit_object_origins(unit: Mapping[str, Any]) -> set[str]:
    semantics = _mapping(unit.get("semantics"), "semantics")
    origins = {
        _address_origin(event.get("address"))
        for event in semantics.get("memory_events", [])
        if isinstance(event, Mapping)
    }
    return {origin for origin in origins if not origin.startswith("stack:") and origin != "unknown"}


def _looks_like_epilogue(unit: Mapping[str, Any]) -> bool:
    semantics = _mapping(unit.get("semantics"), "semantics")
    outcome = semantics.get("outcome", {})
    if isinstance(outcome, Mapping) and outcome.get("kind") == "return":
        return True
    stack_references = sum(
        1
        for expression in _semantic_expressions(semantics)
        if any(kind == "stack" for kind, _name in _expression_origins(expression))
    )
    restored = {
        str(write.get("register", "")).lower()
        for write in semantics.get("register_writes", [])
        if isinstance(write, Mapping)
    }
    return stack_references >= 2 and bool(restored & {"ebx", "esi", "edi", "ebp", "esp"})


def _has_external_event(unit: Mapping[str, Any]) -> bool:
    semantics = _mapping(unit.get("semantics"), "semantics")
    return any(
        isinstance(event, Mapping) and event.get("kind") != "internal_call"
        for event in semantics.get("external_events", [])
    )


def _stack_event_consumed_by_external(
    semantics: Mapping[str, Any], event: Mapping[str, Any]
) -> bool:
    """Recognize stack argument setup that is internal to a checked call event."""

    if event.get("kind") != "write" or "value" not in event:
        return False
    value_hash = _canonical_sha256(event["value"])
    for external in semantics.get("external_events", []):
        if not isinstance(external, Mapping) or external.get("kind") == "internal_call":
            continue
        expressions: list[Any] = []
        arguments = external.get("arguments", [])
        if isinstance(arguments, list):
            expressions.extend(arguments)
        stack_inputs = external.get("stack_inputs", [])
        if isinstance(stack_inputs, list):
            expressions.extend(
                item.get("value")
                for item in stack_inputs
                if isinstance(item, Mapping) and "value" in item
            )
        if any(_canonical_sha256(expression) == value_hash for expression in expressions):
            return True
    return False


def _internal_call_return(unit: Mapping[str, Any], event_index: int | None) -> int | None:
    if event_index is None:
        return None
    events = _mapping(unit.get("semantics"), "semantics").get("external_events", [])
    if isinstance(events, list) and event_index < len(events):
        value = events[event_index].get("return_rva")
        return int(value) if isinstance(value, int) else None
    return None
