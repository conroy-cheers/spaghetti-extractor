"""Exact, content-addressed authority bindings for byte-free machine IR.

This module is intentionally small and stable.  Exact extraction can emit unit
and event bindings without importing the interprocedural authority builder.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import (
    BinaryBinding,
    EventBinding,
    IndirectExitBinding,
    UnitBinding,
    canonical_json_bytes,
)


MACHINE_IR_AUTHORITY_BINDINGS_FORMAT = (
    "spaghetti-extractor-machine-ir-authority-bindings-v2"
)


class MachineIRAuthorityV2Error(ValueError):
    """Machine-IR data cannot be represented by exact v2 bindings."""


def canonical_unit_sha256(row: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(row)).hexdigest()


def canonical_event_sha256(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(event)).hexdigest()


def machine_ir_sha256(rows: Sequence[Mapping[str, Any]]) -> str:
    payload = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    return hashlib.sha256(payload).hexdigest()


def recompute_unit_binding(
    row: Mapping[str, Any], *, binary: BinaryBinding
) -> UnitBinding:
    try:
        source = _mapping(row.get("source"), "machine-IR unit source")
        original = _mapping(source.get("original"), "machine-IR unit span")
        return UnitBinding(
            binary=binary,
            unit_id=_string(row.get("id"), "machine-IR unit ID"),
            rva_start=_uint(original.get("rva_start"), "unit start RVA"),
            rva_end=_uint(original.get("rva_end"), "unit end RVA"),
            unit_sha256=canonical_unit_sha256(row),
            instruction_bytes_sha256=_string(
                source.get("instruction_bytes_sha256"),
                "machine-IR instruction-byte SHA-256",
            ),
        )
    except (TypeError, ValueError) as exc:
        raise MachineIRAuthorityV2Error(str(exc)) from exc


def recompute_event_binding(
    unit: UnitBinding,
    event: Mapping[str, Any],
    *,
    event_index: int,
    event_kind: str | None = None,
) -> EventBinding:
    kind = event_kind if event_kind is not None else event.get("kind")
    try:
        return EventBinding(
            unit=unit,
            event_index=_uint(event_index, "event index"),
            event_kind=_string(kind, "event kind"),
            instruction_rva=_uint(
                event.get("instruction_rva", unit.rva_start),
                "event instruction RVA",
            ),
            event_sha256=canonical_event_sha256(event),
        )
    except (TypeError, ValueError) as exc:
        raise MachineIRAuthorityV2Error(str(exc)) from exc


def machine_events(
    rows: Sequence[Mapping[str, Any]], by_id: Mapping[str, UnitBinding]
) -> tuple[dict[str, Any], ...]:
    result: list[dict[str, Any]] = []
    for row in rows:
        unit = by_id[str(row["id"])]
        semantics = row.get("semantics")
        semantics = semantics if isinstance(semantics, Mapping) else {}
        for family, kind_override in (("external_events", None), ("faults", "fault")):
            values = semantics.get(family, [])
            if not isinstance(values, list):
                continue
            for index, raw in enumerate(values):
                event = _mapping(raw, f"{family} event")
                binding = recompute_event_binding(
                    unit, event, event_index=index, event_kind=kind_override
                )
                indirect_exit = (
                    _indirect_exit_binding(
                        unit=unit,
                        unit_row=row,
                        event=event,
                        source_event_index=index,
                        transfer_kind=binding.event_kind,
                    )
                    if binding.event_kind in {"indirect_call", "indirect_jump"}
                    else None
                )
                result.append({
                    "binding": binding,
                    "row": event,
                    "indirect_exit": indirect_exit,
                })
        outcome = semantics.get("outcome")
        if not isinstance(outcome, Mapping) or outcome.get("kind") not in {
            "indirect_call",
            "indirect_jump",
        }:
            continue
        instruction_rva = _indirect_instruction_rva(row, outcome, unit=unit)
        identity = (outcome.get("kind"), instruction_rva)
        existing = {
            (item["binding"].event_kind, item["binding"].instruction_rva)
            for item in result
            if item["binding"].unit == unit
        }
        if identity not in existing:
            event = dict(outcome)
            event["instruction_rva"] = _indirect_instruction_rva(
                row, event, unit=unit
            )
            result.append({
                "binding": recompute_event_binding(unit, event, event_index=0),
                "row": event,
                "indirect_exit": _indirect_exit_binding(
                    unit=unit,
                    unit_row=row,
                    event=event,
                    source_event_index=None,
                    transfer_kind=str(event["kind"]),
                ),
            })
    return tuple(result)


def _indirect_instruction_rva(
    unit_row: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    unit: UnitBinding,
) -> int:
    instruction_rva = event.get("instruction_rva")
    if isinstance(instruction_rva, int) and not isinstance(instruction_rva, bool):
        return instruction_rva
    control = unit_row.get("control")
    reconciliation = (
        control.get("decoded_reconciliation")
        if isinstance(control, Mapping)
        else None
    )
    terminal = (
        reconciliation.get("terminal_instruction")
        if isinstance(reconciliation, Mapping)
        else None
    )
    terminal_rva = terminal.get("rva") if isinstance(terminal, Mapping) else None
    return (
        terminal_rva
        if isinstance(terminal_rva, int) and not isinstance(terminal_rva, bool)
        else unit.rva_start
    )


def _indirect_exit_binding(
    *,
    unit: UnitBinding,
    unit_row: Mapping[str, Any],
    event: Mapping[str, Any],
    source_event_index: int | None,
    transfer_kind: str,
) -> IndirectExitBinding:
    return IndirectExitBinding.from_exact(
        unit=unit,
        source_event_index=source_event_index,
        transfer_kind=transfer_kind,
        instruction_rva=_indirect_instruction_rva(unit_row, event, unit=unit),
        target_expression=event.get("target"),
    )


def build_machine_ir_authority_bindings(
    rows: Sequence[Mapping[str, Any]], *, pe_sha256: str
) -> dict[str, Any]:
    binary = BinaryBinding(
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256(rows),
    )
    units = tuple(recompute_unit_binding(row, binary=binary) for row in rows)
    by_id = {unit.unit_id: unit for unit in units}
    if len(by_id) != len(units):
        raise MachineIRAuthorityV2Error("machine-IR unit IDs are duplicated")
    events = machine_events(rows, by_id)
    indirect_exits = tuple(
        item["indirect_exit"]
        for item in events
        if isinstance(item.get("indirect_exit"), IndirectExitBinding)
    )
    if len({row.exit_id for row in indirect_exits}) != len(indirect_exits):
        raise MachineIRAuthorityV2Error("machine-IR indirect-exit IDs are duplicated")
    return {
        "format": MACHINE_IR_AUTHORITY_BINDINGS_FORMAT,
        "binary": binary.to_payload(),
        "units": [unit.to_payload() for unit in units],
        "events": [item["binding"].to_payload() for item in events],
        "indirect_exits": [row.to_payload() for row in indirect_exits],
    }


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineIRAuthorityV2Error(f"{context} must be an object")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise MachineIRAuthorityV2Error(f"{context} must be nonempty text")
    return value


def _uint(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFFFFFF
    ):
        raise MachineIRAuthorityV2Error(f"{context} must be an unsigned integer")
    return value


__all__ = [
    "MACHINE_IR_AUTHORITY_BINDINGS_FORMAT",
    "MachineIRAuthorityV2Error",
    "build_machine_ir_authority_bindings",
    "canonical_event_sha256",
    "canonical_unit_sha256",
    "machine_events",
    "machine_ir_sha256",
    "recompute_event_binding",
    "recompute_unit_binding",
]
