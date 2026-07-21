from __future__ import annotations

from typing import Any


def _semantic_edges(behavior: dict[str, Any]) -> list[dict[str, Any]]:
    outcome = behavior["outcome"]
    operation = outcome.get("op")
    truth = {"op": "bool_constant", "value": True}
    if operation in {"jump", "call", "call_unmapped_return"}:
        return [{
            "target": int(outcome["target"]),
            "guard": truth,
            "kind": "call" if operation == "call_unmapped_return" else operation,
        }]
    if operation == "branch":
        if int(outcome["taken"]) == int(outcome["fallthrough"]):
            return [{
                "target": int(outcome["taken"]),
                "guard": truth,
                "kind": "branch_converged",
            }]
        return [
            {
                "target": int(outcome["taken"]),
                "guard": outcome["condition"],
                "kind": "branch_taken",
            },
            {
                "target": int(outcome["fallthrough"]),
                "guard": {"op": "not", "value": outcome["condition"]},
                "kind": "branch_fallthrough",
            },
        ]
    if operation in {"bulk_copy", "atomic_compare_exchange"}:
        return [{
            "target": int(outcome["continuation"]),
            "guard": truth,
            "kind": operation,
        }]
    if operation == "checked_continue":
        return [{
            "target": int(outcome["continuation"]),
            "guard": outcome["valid"],
            "kind": operation,
        }]
    if operation == "external_call":
        return [{
            "target": int(outcome["continuation"]),
            "guard": truth,
            "kind": operation,
            "environment_barrier": True,
        }]
    return []
