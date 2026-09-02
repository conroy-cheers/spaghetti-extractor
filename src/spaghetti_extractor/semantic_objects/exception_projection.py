"""Relocatable projection of checked exceptional transfer semantics."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer.exception_semantics import (
    CheckedExceptionTransitionV1,
    derive_checked_exception_transitions_v1,
)
from ..external.resolved import ResolvedExternalEnvironmentV1
from ..transfer.model import _Transfer


def load_exception_projection_inputs(
    *,
    transfers: Sequence[_Transfer] = (),
    resolved_environment: ResolvedExternalEnvironmentV1 | None = None,
) -> tuple[CheckedExceptionTransitionV1, ...]:
    """Derive the sole exception relation from transfer-v2 and environment."""

    return (
        ()
        if resolved_environment is None
        else derive_checked_exception_transitions_v1(
            transfers=transfers,
            environment=resolved_environment,
        )
    )


def exception_transition_symbol_id(
    transition: CheckedExceptionTransitionV1,
) -> str:
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
    return (
        "semantic:exception-transition:"
        f"{canonical_sha256_v3(identity)[:24]}"
    )


def _function_symbol_id(unit_id: str) -> str:
    return f"original:function:{unit_id}"


def project_exception_transitions(
    checked: Sequence[CheckedExceptionTransitionV1],
    transfer_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]],
    list[dict[str, Any]], list[dict[str, Any]],
]:
    """Project exact checked occurrences; unresolved authority stays a hole."""

    symbols: list[dict[str, Any]] = []
    definitions: list[dict[str, Any]] = []
    relocations: list[dict[str, Any]] = []
    holes: list[dict[str, Any]] = []
    for transition in checked:
        symbol_id = exception_transition_symbol_id(transition)
        payload = transition.payload()
        source_symbol = _function_symbol_id(transition.unit_id)
        activation_id = f"exception:{symbol_id}:activation"
        symbols.append({
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
                **payload,
            },
        })
        if not transition.authorizing:
            holes.append({
                "kind": "exception_transition_not_authoritative",
                "subject": activation_id,
                "detail": transition.blocker_code or (
                    "exception_transition_not_authoritative"
                ),
            })
        else:
            definitions.append({
                "symbol_id": symbol_id,
                "definition_kind": "checked_exception_transition",
                "transition": {
                    "transition_id": transition.transition_id,
                    "transition_sha256": transition.transition_sha256,
                    "disposition": transition.disposition,
                    "guard": transition.guard,
                    "state_projection": transition.state_projection,
                },
            })
        source_exists = transition.unit_id in transfer_by_id
        relocations.append({
            "relocation_id": activation_id,
            "kind": "exception_transition_activation",
            "source_symbol": source_symbol,
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

        def add_target(
            *, kind: str, unit_id: str, target_rva: int,
            role: str, order: int | None,
        ) -> None:
            target_symbol = _function_symbol_id(unit_id)
            resolved = (
                transition.unit_id in transfer_by_id
                and unit_id in transfer_by_id
            )
            suffix = "" if order is None else f":{order}"
            relocation_id = f"exception:{symbol_id}:{kind}{suffix}"
            relocations.append({
                "relocation_id": relocation_id,
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
                "target_symbol": target_symbol if resolved else None,
                "target_rva": target_rva,
                "selector_value": order,
                "addend": 0,
                "required_view": {
                    "kind": "code_capability", "role": role,
                },
                "status": "resolved_local" if resolved else "unresolved",
            })
            if not resolved:
                holes.append({
                    "kind": "exception_code_relocation_unresolved",
                    "subject": relocation_id,
                    "detail": (
                        f"checked {role} unit {unit_id!r} has no exact "
                        "transfer-v2 definition"
                    ),
                })

        if transition.handler_unit_id is not None:
            assert transition.handler_rva is not None
            add_target(
                kind="exception_handler_target",
                unit_id=transition.handler_unit_id,
                target_rva=transition.handler_rva,
                role="exception_handler", order=None,
            )
        if transition.resumption_unit_id is not None:
            assert transition.resumption_rva is not None
            add_target(
                kind="exception_resumption_target",
                unit_id=transition.resumption_unit_id,
                target_rva=transition.resumption_rva,
                role="exception_continuation", order=None,
            )
        for order, unit_id in enumerate(transition.unwind_unit_ids):
            target = transfer_by_id.get(unit_id)
            target_rva = (
                0 if target is None else int(target["source"]["rva_start"])
            )
            add_target(
                kind="exception_unwind_target", unit_id=unit_id,
                target_rva=target_rva,
                role="exception_unwind", order=order,
            )
    return (
        sorted(symbols, key=lambda row: str(row["symbol_id"])),
        sorted(definitions, key=lambda row: str(row["symbol_id"])),
        sorted(relocations, key=lambda row: str(row["relocation_id"])),
        sorted(holes, key=lambda row: (
            str(row["kind"]), str(row["subject"]), str(row["detail"])
        )),
    )


__all__ = [
    "exception_transition_symbol_id", "load_exception_projection_inputs",
    "project_exception_transitions",
]
