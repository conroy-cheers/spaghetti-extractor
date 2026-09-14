"""Fail-closed function/control planning for behavioral-C generation."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from .behavioral_c_model import (
    BehavioralCFunction,
    BehavioralCLayoutIntent,
    BehavioralCPlan,
)
from .model import TransferPlanError, _Transfer


def build_behavioral_c_plan(
    transfers: Iterable[_Transfer],
    *,
    entry_rvas: Iterable[int] = (),
    intent: BehavioralCLayoutIntent | None = None,
) -> BehavioralCPlan:
    """Partition checked transfers into direct C functions.

    The partition is derived entirely from checked control edges.  Sparse
    operator intent may add roots, names, or label preferences, but cannot add,
    remove, or redirect machine behavior.
    """

    rows = tuple(sorted(transfers, key=lambda row: row.rva_start))
    by_rva = {row.rva_start: row for row in rows}
    if len(by_rva) != len(rows):
        raise TransferPlanError(
            "behavioral-C layout received duplicate transfer RVAs",
            code="behavioral_c_layout_ambiguous",
        )
    if not rows:
        raise TransferPlanError(
            "behavioral-C layout requires at least one checked transfer",
            code="behavioral_c_layout_empty",
        )
    intent = intent or BehavioralCLayoutIntent()
    requested_roots = set(entry_rvas) | set(intent.roots)
    unknown_roots = sorted(requested_roots - set(by_rva))
    unknown_labels = sorted(set(intent.forced_labels) - set(by_rva))
    unknown_names = sorted(set(dict(intent.names)) - set(by_rva))
    if unknown_roots or unknown_labels or unknown_names:
        fields = []
        if unknown_roots:
            fields.append("roots=" + _rva_text(unknown_roots))
        if unknown_labels:
            fields.append("forced_labels=" + _rva_text(unknown_labels))
        if unknown_names:
            fields.append("names=" + _rva_text(unknown_names))
        raise TransferPlanError(
            "behavioral-C layout intent references unknown units: " + "; ".join(fields),
            code="behavioral_c_layout_unknown_rva",
            next_action="anchor layout intent only to stable checked machine-unit RVAs",
        )

    outgoing = {rva: _internal_successors(row, by_rva) for rva, row in by_rva.items()}
    incoming: dict[int, set[int]] = defaultdict(set)
    adjacency: dict[int, set[int]] = {rva: set(targets) for rva, targets in outgoing.items()}
    for source, targets in outgoing.items():
        for target in targets:
            incoming[target].add(source)
            adjacency[target].add(source)

    call_roots = {
        call.target_rva
        for row in rows
        for call in row.calls
        if call.kind == "internal_call" and call.target_rva in by_rva
    }
    inferred_roots = {rva for rva in by_rva if not incoming[rva]} | call_roots
    roots = requested_roots | inferred_roots

    components: list[tuple[int, ...]] = []
    unseen = set(by_rva)
    while unseen:
        first = min(unseen)
        pending = [first]
        component: set[int] = set()
        while pending:
            rva = pending.pop()
            if rva in component:
                continue
            component.add(rva)
            pending.extend(sorted(adjacency[rva] - component, reverse=True))
        unseen -= component
        components.append(tuple(sorted(component)))

    functions: list[BehavioralCFunction] = []
    used_symbols: set[str] = set()
    for units in sorted(components, key=lambda values: values[0]):
        entries = tuple(sorted(set(units) & roots))
        if not entries:
            entries = (units[0],)
            roots.add(units[0])
        primary = entries[0]
        authored_name = intent.name_for(primary)
        stem = authored_name or f"sub_{primary:08x}"
        symbol = _unique_symbol(f"spx_{_c_identifier(stem)}", used_symbols)
        functions.append(
            BehavioralCFunction(
                identity=f"behavioral-c-function:{primary:08x}",
                symbol=symbol,
                entries=entries,
                unit_rvas=units,
            )
        )

    plan = BehavioralCPlan(
        functions=tuple(functions),
        roots=tuple(sorted(roots)),
        forced_labels=intent.forced_labels,
    )
    if sorted(plan.unit_rvas) != sorted(by_rva):
        raise TransferPlanError(
            "behavioral-C function ownership is not an exact transfer partition",
            code="behavioral_c_layout_coverage_mismatch",
        )
    return plan


def _internal_successors(
    transfer: _Transfer, by_rva: dict[int, _Transfer]
) -> tuple[int, ...]:
    if not transfer.actions:
        raise TransferPlanError(
            f"{transfer.identity}: checked transfer has no terminal action",
            code="behavioral_c_layout_missing_outcome",
        )
    outcome = transfer.actions[-1]
    targets: tuple[int, ...]
    if outcome.op in {"outcome_fallthrough", "outcome_jump"}:
        targets = outcome.args[:1]
    elif outcome.op == "outcome_branch":
        targets = outcome.args[1:3]
    elif outcome.op in {
        "outcome_return",
        "outcome_indirect",
        "outcome_nonlocal",
        "outcome_external",
    }:
        targets = ()
    else:
        raise TransferPlanError(
            f"{transfer.identity}: final action {outcome.op!r} is not an outcome",
            code="behavioral_c_layout_missing_outcome",
        )
    return tuple(sorted({target for target in targets if target in by_rva}))


def _c_identifier(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not result or result[0].isdigit():
        result = "fn_" + result
    return result


def _unique_symbol(stem: str, used: set[str]) -> str:
    symbol = stem
    suffix = 2
    while symbol in used:
        symbol = f"{stem}_{suffix}"
        suffix += 1
    used.add(symbol)
    return symbol


def _rva_text(values: Iterable[int]) -> str:
    return ",".join(f"0x{value:x}" for value in values)


__all__ = ["build_behavioral_c_plan"]
