"""Shared source-level reachability helpers for Stage B artifacts."""

from __future__ import annotations

from typing import Any, Iterable, Mapping


def source_function_closure(
    roots: Iterable[str],
    calls: Iterable[Mapping[str, Any]],
    function_references: Iterable[Mapping[str, Any]] = (),
) -> set[str]:
    """Return functions reachable through local calls or function values."""

    edges: list[tuple[str, str]] = []
    for call in calls:
        caller = call.get("enclosing_function")
        callee = call.get("callee")
        if (
            call.get("callee_scope") == "source_local"
            and isinstance(caller, str)
            and isinstance(callee, str)
        ):
            edges.append((caller, callee))
    for reference in function_references:
        caller = reference.get("enclosing_function")
        target = reference.get("target_symbol")
        if (
            reference.get("target_scope") == "source_local"
            and isinstance(caller, str)
            and isinstance(target, str)
        ):
            edges.append((caller, target))

    closure = {str(root) for root in roots}
    changed = True
    while changed:
        changed = False
        for caller, target in edges:
            if caller in closure and target not in closure:
                closure.add(target)
                changed = True
    return closure
