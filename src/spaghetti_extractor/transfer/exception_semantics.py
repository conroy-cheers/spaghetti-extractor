"""Canonical exception semantics derived from transfer-v2 and its environment.

This module owns the neutral checked transition model.  It derives the generic
process-root policy directly from the sole executable IR and the content-bound
launch policy.  It does not read authority-v3 artifacts, machine IR, or target
configuration side channels.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import LAUNCH_ASSUMPTION_TEMPLATE_FORMAT
from ..external.resolved import ResolvedExternalEnvironmentV1
from .model import TransferPlanError, _Node, _Transfer
from .operations import EFFECT_OPERATIONS_V2


_LAUNCH_ASSUMPTIONS = frozenset({
    "argv", "environment", "fs", "iat", "initial_stack", "relocations",
})
_LAUNCH_FEATURES = frozenset({
    "direct_syscalls", "executable_writes", "threads",
    "unknown_async_callbacks", "unmodelled_seh",
})

X87_EXCEPTION_PROJECTION_FIELDS_V1 = frozenset({
    "all",
    "code_selector",
    "control",
    "control_word",
    "data_offset",
    "data_pointer",
    "data_selector",
    "environment",
    "error_offset",
    "error_selector",
    "instruction_pointer",
    "registers",
    "stack",
    "status",
    "status_word",
    "tag_word",
    "tags",
})


@dataclass(frozen=True, order=True, slots=True)
class CheckedExceptionTransitionV1:
    unit_id: str
    source_rva: int
    effect_index: int
    fault_index: int
    fault_sha256: str
    transition_id: str | None
    transition_sha256: str | None
    authorizing: bool
    disposition: str | None
    handler_unit_id: str | None
    handler_rva: int | None
    guard: Any
    blocker_code: str | None
    resumption_unit_id: str | None = None
    resumption_rva: int | None = None
    unwind_unit_ids: tuple[str, ...] = ()
    state_projection: Any = None
    native_exception_code: int | None = None
    native_exception_flags: int | None = None
    native_exception_parameter_count: int | None = None
    native_exception_continuable: bool | None = None
    native_exception_access_violation: tuple[int, int] | None = None
    occurrence_kind: str = "effect"
    operation: str | None = None
    call_index: int | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "source_rva": self.source_rva,
            "effect_index": self.effect_index,
            "fault_index": self.fault_index,
            "fault_sha256": self.fault_sha256,
            "transition_id": self.transition_id,
            "transition_sha256": self.transition_sha256,
            "authorizing": self.authorizing,
            "disposition": self.disposition,
            "handler_unit_id": self.handler_unit_id,
            "handler_rva": self.handler_rva,
            "resumption_unit_id": self.resumption_unit_id,
            "resumption_rva": self.resumption_rva,
            "guard": self.guard,
            "blocker_code": self.blocker_code,
            "unwind_unit_ids": list(self.unwind_unit_ids),
            "state_projection": self.state_projection,
            "native_exception_code": self.native_exception_code,
            "native_exception_flags": self.native_exception_flags,
            "native_exception_parameter_count": (
                self.native_exception_parameter_count
            ),
            "native_exception_continuable": self.native_exception_continuable,
            "native_exception_access_violation": (
                None
                if self.native_exception_access_violation is None
                else list(self.native_exception_access_violation)
            ),
            "occurrence_kind": self.occurrence_kind,
            "operation": self.operation,
            "call_index": self.call_index,
        }


def exceptional_transition_id_v1(
    unit_id: str, fault_index: int, fault_sha256: str
) -> str:
    return "exceptional-transition-v3:" + canonical_sha256_v3({
        "unit_id": unit_id,
        "fault_index": fault_index,
        "fault_sha256": fault_sha256,
    })


def _static_bv(
    nodes: Sequence[_Node], node_id: int, active: frozenset[int] = frozenset()
) -> int | None:
    if node_id in active or not 0 <= node_id < len(nodes):
        return None
    node = nodes[node_id]
    nested = active | {node_id}
    if node.op == "const":
        return node.immediate & 0xFFFF_FFFF
    if node.op == "ite" and len(node.args) == 3:
        condition = _static_bool(nodes, node.args[0], nested)
        return (
            None
            if condition is None
            else _static_bv(nodes, node.args[1 if condition else 2], nested)
        )
    values = tuple(_static_bv(nodes, item, nested) for item in node.args)
    if any(value is None for value in values):
        return None
    operands = tuple(int(value) for value in values if value is not None)
    if node.op == "not32" and len(operands) == 1:
        return (~operands[0]) & 0xFFFF_FFFF
    if node.op in {"add32", "and32", "or32", "sub32", "xor32"} and len(
        operands
    ) == 2:
        left, right = operands
        result = {
            "add32": left + right,
            "and32": left & right,
            "or32": left | right,
            "sub32": left - right,
            "xor32": left ^ right,
        }[node.op]
        return result & 0xFFFF_FFFF
    if node.op in {"udiv_quot32", "udiv_rem32"} and len(operands) == 3:
        high, low, divisor = operands
        if divisor == 0 or high >= divisor:
            return None
        dividend = (high << 32) | low
        return (
            dividend // divisor
            if node.op == "udiv_quot32" else dividend % divisor
        ) & 0xFFFF_FFFF
    return None


def _static_bool(
    nodes: Sequence[_Node], node_id: int, active: frozenset[int] = frozenset()
) -> bool | None:
    if node_id in active or not 0 <= node_id < len(nodes):
        return None
    node = nodes[node_id]
    nested = active | {node_id}
    if node.op == "true":
        return True
    if node.op == "false":
        return False
    if node.op == "not" and len(node.args) == 1:
        value = _static_bool(nodes, node.args[0], nested)
        return None if value is None else not value
    if node.op in {"and_bool", "or_bool", "xor_bool"} and len(node.args) == 2:
        left = _static_bool(nodes, node.args[0], nested)
        right = _static_bool(nodes, node.args[1], nested)
        if left is None or right is None:
            return None
        if node.op == "and_bool":
            return left and right
        if node.op == "or_bool":
            return left or right
        return left != right
    if node.op in {"eq", "eq_bool"} and len(node.args) == 2:
        left_bv = _static_bv(nodes, node.args[0], nested)
        right_bv = _static_bv(nodes, node.args[1], nested)
        if left_bv is not None and right_bv is not None:
            return left_bv == right_bv
        left_bool = _static_bool(nodes, node.args[0], nested)
        right_bool = _static_bool(nodes, node.args[1], nested)
        return (
            None
            if left_bool is None or right_bool is None
            else left_bool == right_bool
        )
    if node.op == "ult32" and len(node.args) == 2:
        left = _static_bv(nodes, node.args[0], nested)
        right = _static_bv(nodes, node.args[1], nested)
        return None if left is None or right is None else left < right
    if node.op == "msb" and len(node.args) in {1, 2}:
        if len(node.args) == 1:
            width = 32
            operand_id = node.args[0]
        else:
            width = _static_bv(nodes, node.args[0], nested)
            operand_id = node.args[1]
        operand = _static_bv(nodes, operand_id, nested)
        if width is None or operand is None or not 1 <= width <= 32:
            return None
        return bool(operand & (1 << (width - 1)))
    return None


def _launch_profile_status(
    environment: ResolvedExternalEnvironmentV1,
) -> tuple[bool, str | None]:
    launch = environment.payload.get("launch_policy")
    payload = launch.get("payload") if isinstance(launch, Mapping) else None
    if (
        not isinstance(payload, Mapping)
        or set(payload) != {
            "assumptions", "feature_inventory", "format", "schema_version",
        }
        or payload.get("format") != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT
        or payload.get("schema_version") != 1
    ):
        return False, "exception_terminal_profile_violated"
    assumptions = payload.get("assumptions")
    features = payload.get("feature_inventory")
    if (
        not isinstance(assumptions, Mapping)
        or set(assumptions) != _LAUNCH_ASSUMPTIONS
        or any(not isinstance(value, Mapping) or not value for value in assumptions.values())
        or not isinstance(features, Mapping)
        or set(features) != _LAUNCH_FEATURES
        or any(not isinstance(value, list) for value in features.values())
    ):
        return False, "exception_terminal_profile_violated"
    if any(features.values()):
        return False, "exception_terminal_profile_unsupported_features"
    return True, None


def derive_checked_exception_transitions_v1(
    *,
    transfers: Sequence[_Transfer],
    environment: ResolvedExternalEnvironmentV1,
) -> tuple[CheckedExceptionTransitionV1, ...]:
    """Derive the generic checked exception relation without authority-v3."""

    profile_complete, profile_blocker = _launch_profile_status(environment)
    transfer_by_id = {transfer.identity: transfer for transfer in transfers}
    protocols: dict[tuple[Any, ...], Mapping[str, Any]] = {}
    for protocol in environment.payload["checked_exception_protocols"]:
        occurrence = protocol["occurrence"]
        key = (
            occurrence["unit_id"], occurrence["source_rva"],
            occurrence["effect_index"], occurrence["fault_index"],
            occurrence["fault_sha256"], occurrence["occurrence_kind"],
            occurrence["operation"], occurrence["call_index"],
        )
        if key in protocols:
            raise TransferPlanError(
                "resolved environment duplicates a checked exception occurrence",
                code="duplicate_checked_exception_protocol",
            )
        for field in ("handler", "resumption"):
            target = protocol[field]
            if target is None:
                continue
            target_transfer = transfer_by_id.get(target["unit_id"])
            if (
                target_transfer is None
                or target_transfer.rva_start != target["rva"]
            ):
                raise TransferPlanError(
                    "checked exception protocol target is absent or stale",
                    code="stale_checked_exception_protocol_target",
                )
        if any(unit_id not in transfer_by_id for unit_id in protocol["unwind_unit_ids"]):
            raise TransferPlanError(
                "checked exception protocol unwind target is absent",
                code="stale_checked_exception_protocol_target",
            )
        protocols[key] = protocol
    consumed_protocols: set[tuple[Any, ...]] = set()
    checked: list[CheckedExceptionTransitionV1] = []
    for transfer in transfers:
        for occurrence in transfer.exception_occurrences:
            if not 0 <= occurrence.effect_index < len(transfer.actions) - 1:
                raise TransferPlanError(
                    "exception occurrence references no executable effect",
                    code="malformed_exception_occurrence_inventory",
                )
            effect = transfer.actions[occurrence.effect_index]
            native_exception = EFFECT_OPERATIONS_V2[
                occurrence.operation
            ].native_exception
            if native_exception is None:
                raise TransferPlanError(
                    "exception occurrence has no canonical native metadata",
                    code="malformed_exception_occurrence_inventory",
                )
            guard_node = (
                effect.args[0]
                if occurrence.occurrence_kind == "effect" and effect.args
                else None
            )
            static_guard = (
                None
                if guard_node is None
                else _static_bool(transfer.nodes, guard_node)
            )
            occurrence_key = (
                transfer.identity, transfer.rva_start,
                occurrence.effect_index, occurrence.fault_index,
                occurrence.fault_sha256, occurrence.occurrence_kind,
                occurrence.operation, occurrence.call_event_index,
            )
            protocol = protocols.get(occurrence_key)
            if protocol is not None and static_guard is False:
                raise TransferPlanError(
                    "checked exception protocol selects an infeasible occurrence",
                    code="infeasible_checked_exception_protocol",
                )
            if protocol is not None:
                consumed_protocols.add(occurrence_key)
                authorizing = True
                disposition = (
                    "handled"
                    if protocol["handler"] is not None
                    else "terminates"
                )
                blocker = None
            elif static_guard is False:
                authorizing = True
                disposition = "infeasible"
                blocker = None
            elif occurrence.occurrence_kind == "call":
                authorizing = False
                disposition = None
                blocker = "exception_fault_kind_unsupported"
            elif profile_complete:
                authorizing = True
                disposition = "terminates"
                blocker = None
            else:
                authorizing = False
                disposition = None
                blocker = profile_blocker
            transition_id = exceptional_transition_id_v1(
                transfer.identity,
                occurrence.fault_index,
                occurrence.fault_sha256,
            )
            guard: dict[str, Any] = (
                {
                    "kind": "transfer_expression_v2",
                    "node_id": guard_node,
                }
                if guard_node is not None
                else {"kind": "constant", "value": True}
            )
            transition_core = {
                "schema": "spaghetti-extractor-checked-exception-transition-v1",
                "unit_id": transfer.identity,
                "source_rva": transfer.rva_start,
                "effect_index": occurrence.effect_index,
                "fault_index": occurrence.fault_index,
                "fault_sha256": occurrence.fault_sha256,
                "transition_id": transition_id,
                "authorizing": authorizing,
                "disposition": disposition,
                "guard": guard if authorizing else None,
                "blocker_code": blocker,
                "occurrence_kind": occurrence.occurrence_kind,
                "operation": occurrence.operation,
                "call_index": occurrence.call_event_index,
                "launch_policy_payload_sha256": environment.payload[
                    "launch_policy"
                ]["payload_sha256"],
                "checked_exception_protocol_sha256": (
                    None if protocol is None
                    else protocol["protocol_sha256"]
                ),
            }
            handler = None if protocol is None else protocol["handler"]
            resumption = None if protocol is None else protocol["resumption"]
            checked.append(CheckedExceptionTransitionV1(
                unit_id=transfer.identity,
                source_rva=transfer.rva_start,
                effect_index=occurrence.effect_index,
                fault_index=occurrence.fault_index,
                fault_sha256=occurrence.fault_sha256,
                transition_id=transition_id,
                transition_sha256=canonical_sha256_v3(transition_core),
                authorizing=authorizing,
                disposition=disposition,
                handler_unit_id=(
                    None if handler is None else str(handler["unit_id"])
                ),
                handler_rva=(None if handler is None else int(handler["rva"])),
                guard=guard if authorizing else None,
                blocker_code=blocker,
                resumption_unit_id=(
                    None if resumption is None
                    else str(resumption["unit_id"])
                ),
                resumption_rva=(
                    None if resumption is None else int(resumption["rva"])
                ),
                unwind_unit_ids=(
                    () if protocol is None
                    else tuple(protocol["unwind_unit_ids"])
                ),
                state_projection=(
                    None if protocol is None
                    else protocol["state_projection"]
                ),
                native_exception_code=native_exception.code,
                native_exception_flags=(
                    0 if native_exception.continuable else 1
                ),
                native_exception_parameter_count=(
                    native_exception.parameter_count
                ),
                native_exception_continuable=native_exception.continuable,
                native_exception_access_violation=(
                    native_exception.access_violation
                ),
                occurrence_kind=occurrence.occurrence_kind,
                operation=occurrence.operation,
                call_index=occurrence.call_event_index,
            ))
    if consumed_protocols != set(protocols):
        raise TransferPlanError(
            "resolved environment names no exact transfer exception occurrence",
            code="stale_checked_exception_protocol_occurrence",
        )
    return tuple(sorted(checked))


def checked_exception_transition_from_payload_v1(
    value: object,
) -> CheckedExceptionTransitionV1:
    """Decode one closed semantic-object exception projection row."""

    if not isinstance(value, Mapping):
        raise TransferPlanError(
            "checked exception transition must be an object",
            code="malformed_checked_exception_transition",
        )
    fields = {
        "unit_id", "source_rva", "effect_index", "fault_index",
        "fault_sha256", "transition_id", "transition_sha256", "authorizing",
        "disposition", "handler_unit_id", "handler_rva",
        "resumption_unit_id", "resumption_rva", "guard", "blocker_code",
        "unwind_unit_ids", "state_projection", "native_exception_code",
        "native_exception_flags", "native_exception_parameter_count",
        "native_exception_continuable", "native_exception_access_violation",
        "occurrence_kind", "operation", "call_index",
    }
    if set(value) != fields:
        raise TransferPlanError(
            "checked exception transition fields are incomplete",
            code="malformed_checked_exception_transition",
        )

    def integer(name: str, *, optional: bool = False) -> int | None:
        item = value.get(name)
        if optional and item is None:
            return None
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise TransferPlanError(
                f"checked exception transition {name} is malformed",
                code="malformed_checked_exception_transition",
            )
        return item

    def text(name: str, *, optional: bool = False) -> str | None:
        item = value.get(name)
        if optional and item is None:
            return None
        if not isinstance(item, str) or not item:
            raise TransferPlanError(
                f"checked exception transition {name} is malformed",
                code="malformed_checked_exception_transition",
            )
        return item

    unit_id = text("unit_id")
    fault_sha256 = text("fault_sha256")
    if (
        fault_sha256 is None
        or len(fault_sha256) != 64
        or any(character not in "0123456789abcdef" for character in fault_sha256)
    ):
        raise TransferPlanError(
            "checked exception transition fault digest is malformed",
            code="malformed_checked_exception_transition",
        )
    transition_id = text("transition_id", optional=True)
    transition_sha256 = text("transition_sha256", optional=True)
    if transition_sha256 is not None and (
        len(transition_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in transition_sha256
        )
    ):
        raise TransferPlanError(
            "checked exception transition digest is malformed",
            code="malformed_checked_exception_transition",
        )
    authorizing = value.get("authorizing")
    if not isinstance(authorizing, bool):
        raise TransferPlanError(
            "checked exception transition authority is malformed",
            code="malformed_checked_exception_transition",
        )
    disposition = text("disposition", optional=True)
    blocker_code = text("blocker_code", optional=True)
    occurrence_kind = text("occurrence_kind")
    operation = text("operation", optional=True)
    if (
        occurrence_kind not in {"effect", "call"}
        or (authorizing and disposition not in {"handled", "infeasible", "terminates"})
        or (not authorizing and (disposition is not None or blocker_code is None))
        or (authorizing and blocker_code is not None)
    ):
        raise TransferPlanError(
            "checked exception transition state is inconsistent",
            code="malformed_checked_exception_transition",
        )
    unwind = value.get("unwind_unit_ids")
    if (
        not isinstance(unwind, list)
        or any(not isinstance(item, str) or not item for item in unwind)
        or len(set(unwind)) != len(unwind)
    ):
        raise TransferPlanError(
            "checked exception transition unwind inventory is malformed",
            code="malformed_checked_exception_transition",
        )
    access = value.get("native_exception_access_violation")
    if access is not None and (
        not isinstance(access, list)
        or len(access) != 2
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in access)
    ):
        raise TransferPlanError(
            "checked exception access-violation metadata is malformed",
            code="malformed_checked_exception_transition",
        )
    continuable = value.get("native_exception_continuable")
    if continuable is not None and not isinstance(continuable, bool):
        raise TransferPlanError(
            "checked exception continuability is malformed",
            code="malformed_checked_exception_transition",
        )
    handler_unit_id = text("handler_unit_id", optional=True)
    handler_rva = integer("handler_rva", optional=True)
    resumption_unit_id = text("resumption_unit_id", optional=True)
    resumption_rva = integer("resumption_rva", optional=True)
    if (
        (handler_unit_id is None) != (handler_rva is None)
        or (resumption_unit_id is None) != (resumption_rva is None)
        or (disposition == "handled") != (handler_unit_id is not None)
        or (
            disposition in {"infeasible", "terminates"}
            and handler_unit_id is not None
        )
    ):
        raise TransferPlanError(
            "checked exception transition targets are inconsistent",
            code="malformed_checked_exception_transition",
        )
    return CheckedExceptionTransitionV1(
        unit_id=str(unit_id),
        source_rva=int(integer("source_rva")),
        effect_index=int(integer("effect_index")),
        fault_index=int(integer("fault_index")),
        fault_sha256=fault_sha256,
        transition_id=transition_id,
        transition_sha256=transition_sha256,
        authorizing=authorizing,
        disposition=disposition,
        handler_unit_id=handler_unit_id,
        handler_rva=handler_rva,
        resumption_unit_id=resumption_unit_id,
        resumption_rva=resumption_rva,
        guard=value.get("guard"),
        blocker_code=blocker_code,
        unwind_unit_ids=tuple(unwind),
        state_projection=value.get("state_projection"),
        native_exception_code=integer("native_exception_code", optional=True),
        native_exception_flags=integer("native_exception_flags", optional=True),
        native_exception_parameter_count=integer(
            "native_exception_parameter_count", optional=True
        ),
        native_exception_continuable=continuable,
        native_exception_access_violation=(
            None if access is None else (int(access[0]), int(access[1]))
        ),
        occurrence_kind=str(occurrence_kind),
        operation=operation,
        call_index=integer("call_index", optional=True),
    )


__all__ = [
    "CheckedExceptionTransitionV1",
    "X87_EXCEPTION_PROJECTION_FIELDS_V1",
    "checked_exception_transition_from_payload_v1",
    "derive_checked_exception_transitions_v1",
    "exceptional_transition_id_v1",
]
