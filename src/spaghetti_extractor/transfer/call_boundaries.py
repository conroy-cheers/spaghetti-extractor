"""Instruction-local external-call boundary normalization for transfer-v2."""

from __future__ import annotations

from typing import Any, Mapping

from .model import TransferPlanError
from .values import _nonnegative, _object, _optional_list, _width


def bind_instruction_call_boundary(
    *,
    row: Mapping[str, Any],
    identity: str,
    event: Mapping[str, Any],
    event_index: int,
) -> Mapping[str, Any]:
    """Join one exact instruction call to its transfer-level ABI inventory."""

    if event.get("kind") not in {
        "external_call",
        "internal_call",
        "indirect_call",
    }:
        return event
    aggregate_events = _optional_list(row.get("external_events"))
    if event_index >= len(aggregate_events):
        return event
    aggregate = _object(
        aggregate_events[event_index],
        f"{identity} aggregate external event {event_index}",
    )
    identity_fields = (
        "kind",
        "dll",
        "symbol",
        "ordinal",
        "target_rva",
        "return_rva",
    )
    if any(event.get(field) != aggregate.get(field) for field in identity_fields):
        raise TransferPlanError(
            f"{identity}: instruction and aggregate call identities differ",
            code="instruction_call_boundary_mismatch",
        )
    merged = dict(event)
    for field in ("arguments", "stack_inputs"):
        local = _optional_list(event.get(field))
        boundary = _optional_list(aggregate.get(field))
        # Instruction-local inventories already describe the exact call state.
        # The aggregate inventory is a required fallback for values prepared by
        # preceding instructions in the same transfer unit.
        selected = local or boundary
        if field == "stack_inputs" and not local:
            selected = [_instruction_local_stack_input(raw, identity) for raw in selected]
        merged[field] = selected
    return merged


def _instruction_local_stack_input(raw: Any, identity: str) -> Mapping[str, Any]:
    """Sample one aggregate ABI slot from current ESP at the call."""

    item = _object(raw, f"{identity} aggregate stack input")
    offset = _nonnegative(item.get("offset"), "stack input offset")
    width = _width(item.get("width"))
    return {
        "offset": offset,
        "width": width,
        "value": {
            "op": "load",
            "width": width,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "esp", "width": 32},
                    {"op": "const", "value": offset, "width": 32},
                ],
            },
        },
    }


__all__ = ["bind_instruction_call_boundary"]
