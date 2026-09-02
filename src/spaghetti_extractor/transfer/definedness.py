"""Veto-only definedness interpretation over canonical transfer v2."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..artifacts.artifact_set import canonical_sha256_v3
from .model import TransferPlanError, _Action, _Call, _Transfer
from .interpretation import (
    DomainOperationCoverageV2,
    total_domain_coverage_v2,
)


TRANSFER_DEFINEDNESS_FORMAT_V2 = (
    "spaghetti-extractor-transfer-definedness-analysis-v2"
)


def definedness_operation_coverage_v2() -> DomainOperationCoverageV2:
    return total_domain_coverage_v2("definedness")


def _effect_references(action: _Action) -> tuple[int, ...]:
    if action.op in {"call", "typed_x87"}:
        return ()
    return action.args


def _terminator_references(action: _Action) -> tuple[int, ...]:
    if action.op == "outcome_branch":
        return action.args[:1]
    if action.op in {
        "outcome_return", "outcome_indirect", "outcome_nonlocal",
    }:
        return action.args
    return ()


def _call_references(call: _Call) -> tuple[int, ...]:
    return (
        *(() if call.target_node is None else (call.target_node,)),
        *call.register_nodes,
        *call.flag_nodes,
        *call.argument_nodes,
        *(row[2] for row in call.stack_inputs),
    )


def analyze_transfer_definedness_v2(
    transfers: Iterable[_Transfer],
) -> dict[str, Any]:
    """Trace stable undefined identities through the serialized SSA graph.

    This result is diagnostic and can veto an unsafe runtime policy. It never
    proves semantic noninterference or grants authority.
    """

    slots: dict[tuple[int, str], dict[str, Any]] = {}
    transfer_count = 0
    expression_count = 0
    for transfer in transfers:
        transfer_count += 1
        dependencies: list[frozenset[tuple[int, str]]] = []
        occurrences: dict[tuple[int, str], list[int]] = {}
        for index, node in enumerate(transfer.nodes):
            expression_count += 1
            dependency = frozenset().union(
                *(dependencies[operand] for operand in node.args)
            )
            if node.op in {"undefined_bv", "undefined_flag"}:
                if node.identity is None:
                    raise TransferPlanError(
                        f"{transfer.identity}: undefined node lacks a stable identity",
                        code="malformed_transfer_undefined_identity",
                    )
                key = (node.immediate, node.identity)
                dependency |= {key}
                occurrences.setdefault(key, []).append(index)
            dependencies.append(frozenset(dependency))
        observed_references = {
            *(
                reference
                for action in transfer.actions[:-1]
                for reference in _effect_references(action)
            ),
            *(
                reference
                for call in transfer.calls
                for reference in _call_references(call)
            ),
            *_terminator_references(transfer.actions[-1]),
        }
        if any(reference >= len(dependencies) for reference in observed_references):
            raise TransferPlanError(
                f"{transfer.identity}: definedness observes an unknown expression",
                code="malformed_transfer_node_reference",
            )
        observed_slots = frozenset().union(
            *(dependencies[reference] for reference in observed_references)
        )
        for key, node_ids in occurrences.items():
            row = slots.setdefault(key, {
                "slot": key[0],
                "undefined_id": key[1],
                "classification": "noninterfering",
                "occurrences": [],
            })
            if key in observed_slots:
                row["classification"] = "behavior_relevant"
            row["occurrences"].append({
                "transfer_id": transfer.identity,
                "rva_start": transfer.rva_start,
                "expression_ids": node_ids,
                "observed": key in observed_slots,
            })
    by_numeric_slot: dict[int, set[str]] = {}
    for numeric, identity in slots:
        by_numeric_slot.setdefault(numeric, set()).add(identity)
    collisions = [
        {"slot": numeric, "undefined_ids": sorted(identities)}
        for numeric, identities in sorted(by_numeric_slot.items())
        if len(identities) != 1
    ]
    rows = [slots[key] for key in sorted(slots)]
    core: dict[str, Any] = {
        "format": TRANSFER_DEFINEDNESS_FORMAT_V2,
        "status": "complete" if not collisions else "incomplete",
        "authority": "none; veto-only transfer interpretation",
        "slots": rows,
        "stable_slot_collisions": collisions,
        "counts": {
            "transfers": transfer_count,
            "expressions": expression_count,
            "undefined_nodes": sum(
                len(occurrence["expression_ids"])
                for row in rows
                for occurrence in row["occurrences"]
            ),
            "undefined_slots": len(rows),
            "behavior_relevant_slots": sum(
                row["classification"] == "behavior_relevant" for row in rows
            ),
            "collisions": len(collisions),
        },
    }
    core["analysis_sha256"] = canonical_sha256_v3(core)
    return core


__all__ = [
    "TRANSFER_DEFINEDNESS_FORMAT_V2",
    "analyze_transfer_definedness_v2",
    "definedness_operation_coverage_v2",
]
