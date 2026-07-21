"""Untrusted x87 invariant proposals replayed by the Lean proof kernel."""

from __future__ import annotations

import json
from typing import Any


_X87_FORMAT_BYTES = {
    "float32": 4,
    "float64": 8,
    "float80": 10,
    "int32": 4,
}


def _register_offset(expression: object) -> tuple[str, int] | None:
    if not isinstance(expression, dict):
        return None
    if expression.get("op") == "input_reg" and isinstance(
        expression.get("reg"), str
    ):
        return str(expression["reg"]), 0
    if expression.get("op") != "add":
        return None
    left = expression.get("left")
    right = expression.get("right")
    if not isinstance(left, dict) or not isinstance(right, dict):
        return None
    if left.get("op") != "input_reg" or right.get("op") != "constant":
        return None
    register = left.get("reg")
    offset = right.get("value")
    if (
        not isinstance(register, str)
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or not 0 <= offset < 2**32
    ):
        return None
    return register, offset


def _load_read(behavior: object) -> dict[str, Any] | None:
    if not isinstance(behavior, dict) or behavior.get("writes") != []:
        return None
    x87 = behavior.get("x87")
    if not isinstance(x87, dict):
        return None
    stack = x87.get("stack")
    if not isinstance(stack, list) or not stack:
        return None
    load = stack[0]
    if not isinstance(load, dict) or load.get("op") != "load":
        return None
    width = _X87_FORMAT_BYTES.get(load.get("format"))
    address = load.get("address")
    register_offset = _register_offset(address)
    if width is None or register_offset is None:
        return None
    return {
        "address": address,
        "bytes": width,
        "register": register_offset[0],
        "offset": register_offset[1],
    }


def _matching_window(
    region: dict[str, Any], original_read: dict[str, Any],
    candidate_read: dict[str, Any],
) -> dict[str, Any] | None:
    if original_read["offset"] % 4 or candidate_read["offset"] % 4:
        return None
    for window in region.get("stack_windows", []):
        if not isinstance(window, dict):
            continue
        if (
            window.get("original_register") == original_read["register"]
            and window.get("candidate_register") == candidate_read["register"]
            and original_read["offset"] + original_read["bytes"]
                <= int(window.get("bytes_above", -1))
            and candidate_read["offset"] + candidate_read["bytes"]
                <= int(window.get("bytes_above", -1))
        ):
            return window
    return None


def _true_expression() -> dict[str, Any]:
    return {"op": "bool_constant", "value": True}


def attach_x87_exact_stack_read_invariants(
    contract: dict[str, Any], behaviors: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Propose exact byte relations for paired x87 loads inside stack windows.

    Sources in a connected load-only chain receive the same predicate inventory
    so each load can preserve the facts needed by later loads. A terminal target
    does not retain facts after their last use. These facts are assumptions only
    at the proposal layer: roots and predecessors still have to establish them,
    and Lean re-decodes the instruction and proves every use.
    """
    regions = contract.get("regions", [])
    target_to_index = {
        int(region["numeric_id"]): index
        for index, region in enumerate(regions)
        if isinstance(region, dict) and isinstance(region.get("numeric_id"), int)
    }
    load_edges: list[dict[str, Any]] = []
    for source_index, (region, pair) in enumerate(zip(regions, behaviors)):
        if not isinstance(region, dict) or not isinstance(pair, dict):
            continue
        original = pair.get("original_ir")
        candidate = pair.get("candidate_ir")
        original_read = _load_read(original)
        candidate_read = _load_read(candidate)
        if original_read is None or candidate_read is None:
            continue
        if original_read["bytes"] != candidate_read["bytes"]:
            continue
        original_outcome = original.get("outcome") if isinstance(original, dict) else None
        candidate_outcome = candidate.get("outcome") if isinstance(candidate, dict) else None
        if (
            not isinstance(original_outcome, dict)
            or not isinstance(candidate_outcome, dict)
            or original_outcome.get("op") != "jump"
            or candidate_outcome.get("op") != "jump"
            or original_outcome.get("target") != candidate_outcome.get("target")
        ):
            continue
        target_index = target_to_index.get(original_outcome.get("target"))
        if target_index is None:
            continue
        source_window = _matching_window(region, original_read, candidate_read)
        if source_window is None:
            continue
        load_edges.append({
            "source": source_index,
            "target": target_index,
            "window": source_window,
            "read": {
                "original_address": original_read["address"],
                "candidate_address": candidate_read["address"],
                "bytes": original_read["bytes"],
            },
            "offset": original_read["offset"],
        })

    adjacency: dict[int, set[int]] = {}
    for edge in load_edges:
        adjacency.setdefault(edge["source"], set()).add(edge["target"])
        adjacency.setdefault(edge["target"], set()).add(edge["source"])

    components: list[list[int]] = []
    unseen = set(adjacency)
    while unseen:
        pending = [min(unseen)]
        component: set[int] = set()
        while pending:
            node = pending.pop()
            if node in component:
                continue
            component.add(node)
            pending.extend(sorted(adjacency.get(node, ()), reverse=True))
        unseen -= component
        components.append(sorted(component))

    attached = 0
    claims: list[dict[str, Any]] = []
    for component in components:
        component_set = set(component)
        component_edges = [
            edge for edge in load_edges
            if edge["source"] in component_set and edge["target"] in component_set
        ]
        reads = sorted(
            {(
                json.dumps(edge["read"]["original_address"], sort_keys=True,
                    separators=(",", ":")),
                json.dumps(edge["read"]["candidate_address"], sort_keys=True,
                    separators=(",", ":")),
                int(edge["read"]["bytes"]),
            ): edge["read"] for edge in component_edges}.values(),
            key=lambda read: (
                json.dumps(read["original_address"], sort_keys=True,
                    separators=(",", ":")),
                json.dumps(read["candidate_address"], sort_keys=True,
                    separators=(",", ":")),
                int(read["bytes"]),
            ),
        )
        predicate = {
            "original": _true_expression(),
            "candidate": _true_expression(),
            "exact_memory_reads": reads,
            "source": "x87_exact_stack_load_component",
        }
        source_nodes = {edge["source"] for edge in component_edges}
        for region_index in sorted(source_nodes):
            predicates = regions[region_index].setdefault("state_predicates", [])
            if predicate not in predicates:
                predicates.append(predicate)
                attached += 1
        for edge in component_edges:
            claims.append({
                "source_region_index": edge["source"],
                "target_region_index": edge["target"],
                "window": edge["window"],
                "read": edge["read"],
                "offset": edge["offset"],
                "predicate": predicate,
            })

    return contract, {
        "format": "stage-a-x87-exact-stack-read-proposals-v1",
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "component_count": len(components),
        "attached_predicate_count": attached,
        "claims": claims,
    }


__all__ = ["attach_x87_exact_stack_read_invariants"]
