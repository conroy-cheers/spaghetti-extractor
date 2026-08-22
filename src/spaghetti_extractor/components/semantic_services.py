"""Exact service-event bindings consumed by semantic path exploration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .machine_binding import MachineProjectionV1, MachineServiceEventV1
from .semantic_path_errors import SemanticPathError


@dataclass(frozen=True)
class BoundServiceEvent:
    service_id: str
    unit_id: str
    event_index: int
    event_sha256: str
    argument_projections: tuple[MachineProjectionV1, ...]
    argument_expressions: tuple[Mapping[str, object], ...]
    result: MachineProjectionV1 | None
    preserved_registers: tuple[str, ...]
    stack_pointer_adjustment: int | None


def service_event_index(
    values: object,
    services: Mapping[str, object],
) -> dict[tuple[str, int], BoundServiceEvent]:
    result: dict[tuple[str, int], BoundServiceEvent] = {}
    for raw in _rows(values, "service bindings"):
        service_id = _text(raw.get("service_id"), "service binding id")
        if service_id not in services:
            raise SemanticPathError(f"service binding {service_id} is unknown")
        provider = _object(raw.get("provider"), "service provider")
        provider_kind = provider.get("kind")
        if provider_kind not in {
            "machine_events",
            "component_operation",
            "checked_external_site_events",
        }:
            raise SemanticPathError(
                f"service {service_id} is not bound to exact machine events"
            )
        call_boundary = provider.get("call_boundary")
        preserved_registers: tuple[str, ...] = ()
        stack_pointer_adjustment: int | None = None
        if provider_kind == "component_operation":
            boundary = _object(call_boundary, "component-operation call boundary")
            expected_boundary = {
                "contract_id",
                "target_unit_id",
                "target_unit_sha256",
                "preserved_registers",
                "stack_pointer_relation",
            }
            if set(boundary) != expected_boundary:
                raise SemanticPathError(
                    f"service {service_id} call-boundary fields differ"
                )
            preserved_registers = tuple(
                _text(item, "preserved register")
                for item in _array(
                    boundary.get("preserved_registers"), "preserved registers"
                )
            )
            if list(preserved_registers) != sorted(set(preserved_registers)):
                raise SemanticPathError(
                    f"service {service_id} preserved registers are noncanonical"
                )
            stack_pointer_relation = _text(
                boundary.get("stack_pointer_relation"), "stack-pointer relation"
            )
            if stack_pointer_relation != "same_call_frame":
                raise SemanticPathError(
                    f"service {service_id} stack-pointer relation is unsupported"
                )
            stack_pointer_adjustment = 0
        elif provider_kind == "checked_external_site_events":
            boundary = _object(call_boundary, "external-site call boundary")
            expected_boundary = {
                "contract_id",
                "abi_template",
                "preserved_registers",
                "stack_pointer_adjustment",
            }
            if set(boundary) != expected_boundary:
                raise SemanticPathError(
                    f"service {service_id} external call-boundary fields differ"
                )
            _text(boundary.get("contract_id"), "external contract id")
            _text(boundary.get("abi_template"), "external ABI template")
            preserved_registers = tuple(
                _text(item, "preserved register")
                for item in _array(
                    boundary.get("preserved_registers"), "preserved registers"
                )
            )
            if list(preserved_registers) != sorted(set(preserved_registers)):
                raise SemanticPathError(
                    f"service {service_id} preserved registers are noncanonical"
                )
            stack_pointer_adjustment = _uint(
                boundary.get("stack_pointer_adjustment"),
                "external stack-pointer adjustment",
            )
        for index, value in enumerate(
            _rows(provider.get("events"), "machine service events")
        ):
            if provider_kind in {"machine_events", "component_operation"}:
                event = MachineServiceEventV1.parse(
                    value, f"service {service_id} event {index}"
                )
                bound = BoundServiceEvent(
                    service_id=service_id,
                    unit_id=event.unit_id,
                    event_index=event.event_index,
                    event_sha256=event.event_sha256,
                    argument_projections=event.arguments,
                    argument_expressions=(),
                    result=event.result,
                    preserved_registers=preserved_registers,
                    stack_pointer_adjustment=stack_pointer_adjustment,
                )
            else:
                event_row = _object(
                    value, f"service {service_id} external-site event {index}"
                )
                expected = {
                    "site_id",
                    "site_event_sha256",
                    "unit_id",
                    "event_index",
                    "event_sha256",
                    "arguments",
                    "result",
                }
                if set(event_row) != expected:
                    raise SemanticPathError(
                        f"service {service_id} external-site event fields differ"
                    )
                result_projection = event_row.get("result")
                bound = BoundServiceEvent(
                    service_id=service_id,
                    unit_id=_text(
                        event_row.get("unit_id"), "external-site unit id"
                    ),
                    event_index=_uint(
                        event_row.get("event_index"), "external-site event index"
                    ),
                    event_sha256=_text(
                        event_row.get("event_sha256"), "external-site event digest"
                    ),
                    argument_projections=(),
                    argument_expressions=tuple(
                        _object(argument, "external-site argument expression")
                        for argument in _array(
                            event_row.get("arguments"),
                            "external-site argument expressions",
                        )
                    ),
                    result=(
                        None
                        if result_projection is None
                        else MachineProjectionV1.parse(
                            result_projection,
                            "external-site result projection",
                        )
                    ),
                    preserved_registers=preserved_registers,
                    stack_pointer_adjustment=stack_pointer_adjustment,
                )
            key = (bound.unit_id, bound.event_index)
            if key in result:
                raise SemanticPathError(
                    "machine service event is bound more than once"
                )
            result[key] = bound
    return result


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticPathError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    return [_object(item, context) for item in _array(value, context)]


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise SemanticPathError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticPathError(f"{context} must be a nonempty string")
    return value


def _uint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SemanticPathError(f"{context} must be an unsigned integer")
    return value


__all__ = ["BoundServiceEvent", "service_event_index"]
