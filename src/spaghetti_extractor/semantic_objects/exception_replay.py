"""Independent reconstruction of semantic exceptional-transition rows."""

from __future__ import annotations

from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer.exception_semantics import CheckedExceptionTransitionV1


def _function_id(unit_id: str) -> str:
    return f"original:function:{unit_id}"


def _exception_id(transition: CheckedExceptionTransitionV1) -> str:
    identity = {
        "unit_id": transition.unit_id,
        "source_rva": transition.source_rva,
        "effect_index": transition.effect_index,
        "fault_index": transition.fault_index,
        "fault_sha256": transition.fault_sha256,
        "occurrence_kind": transition.occurrence_kind,
        "operation": transition.operation,
        "call_index": transition.call_index,
    }
    return f"semantic:exception-transition:{canonical_sha256_v3(identity)[:24]}"


def replay_exception_projection(
    checked: tuple[CheckedExceptionTransitionV1, ...],
    plan: Mapping[str, Any],
) -> tuple[
    dict[str, dict[str, Any]], dict[str, dict[str, Any]],
    list[dict[str, Any]],
]:
    transfer_by_id = {
        str(row["identity"]): row for row in plan["transfers"]
    }
    symbols: dict[str, dict[str, Any]] = {}
    definitions: dict[str, dict[str, Any]] = {}
    relocations: list[dict[str, Any]] = []
    for transition in checked:
        symbol_id = _exception_id(transition)
        activation_id = f"exception:{symbol_id}:activation"
        symbols[symbol_id] = {
            "symbol_id": symbol_id,
            "kind": "exception_transition",
            "linkage": "module_local",
            "visibility": "semantic_link",
            "storage_class": "checked_exception_transition",
            "logical_type": {
                "kind": "native_exception",
                "operation": transition.operation,
                "code": transition.native_exception_code,
                "flags": transition.native_exception_flags,
                "parameter_count": transition.native_exception_parameter_count,
                "continuable": transition.native_exception_continuable,
                "access_violation": (
                    None
                    if transition.native_exception_access_violation is None
                    else list(transition.native_exception_access_violation)
                ),
            },
            "physical_frame": None,
            "lifetime": "invocation",
            "permissions": None,
            "original_rva": transition.source_rva,
            "declaration": {
                "namespace": "checked_exception_transition",
                **transition.payload(),
            },
        }
        if transition.authorizing:
            definitions[symbol_id] = {
                "symbol_id": symbol_id,
                "definition_kind": "checked_exception_transition",
                "transition": {
                    "transition_id": transition.transition_id,
                    "transition_sha256": transition.transition_sha256,
                    "disposition": transition.disposition,
                    "guard": transition.guard,
                    "state_projection": transition.state_projection,
                },
            }
        source_exists = transition.unit_id in transfer_by_id
        relocations.append({
            "relocation_id": activation_id,
            "kind": "exception_transition_activation",
            "source_symbol": _function_id(transition.unit_id),
            "source_rva": transition.source_rva,
            "offset": None,
            "site": {
                "kind": "exception_transition_activation",
                "transition_symbol": symbol_id,
                "effect_index": transition.effect_index,
                "fault_index": transition.fault_index,
                "order": None,
            },
            "target_symbol": symbol_id if source_exists else None,
            "target_rva": transition.source_rva,
            "selector_value": None,
            "addend": 0,
            "required_view": {
                "kind": "checked_exception_transition",
                "role": "exception_dispatch",
            },
            "status": (
                "resolved_local"
                if source_exists and transition.authorizing else "unresolved"
            ),
        })
        if not transition.authorizing:
            continue
        targets: list[tuple[str, str, int, str, int | None]] = []
        if transition.handler_unit_id is not None:
            assert transition.handler_rva is not None
            targets.append((
                "exception_handler_target", transition.handler_unit_id,
                transition.handler_rva, "exception_handler", None,
            ))
        if transition.resumption_unit_id is not None:
            assert transition.resumption_rva is not None
            targets.append((
                "exception_resumption_target", transition.resumption_unit_id,
                transition.resumption_rva, "exception_continuation", None,
            ))
        for order, unit_id in enumerate(transition.unwind_unit_ids):
            target = transfer_by_id[unit_id]
            targets.append((
                "exception_unwind_target", unit_id,
                int(target["source"]["rva_start"]),
                "exception_unwind", order,
            ))
        for kind, unit_id, target_rva, role, order in targets:
            suffix = "" if order is None else f":{order}"
            relocations.append({
                "relocation_id": f"exception:{symbol_id}:{kind}{suffix}",
                "kind": kind,
                "source_symbol": symbol_id,
                "source_rva": transition.source_rva,
                "offset": None,
                "site": {
                    "kind": "exception_transition",
                    "transition_symbol": symbol_id,
                    "effect_index": transition.effect_index,
                    "fault_index": transition.fault_index,
                    "order": order,
                },
                "target_symbol": _function_id(unit_id),
                "target_rva": target_rva,
                "selector_value": order,
                "addend": 0,
                "required_view": {
                    "kind": "code_capability", "role": role,
                },
                "status": "resolved_local",
            })
    return symbols, definitions, sorted(
        relocations, key=lambda row: str(row["relocation_id"])
    )


__all__ = ["replay_exception_projection"]
