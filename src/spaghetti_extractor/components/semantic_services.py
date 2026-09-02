"""Exact service-event bindings consumed by semantic path exploration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .machine_binding import MachineProjectionV1, MachineServiceEventV1
from .semantic_path_errors import SemanticPathError


@dataclass(frozen=True)
class BoundServiceWriteback:
    parameter_index: int
    profile_sha256: str
    interface_id: str
    relation_sha256: str
    nullable: bool
    success_condition: str
    projection: MachineProjectionV1


@dataclass(frozen=True)
class BoundServiceEvent:
    service_id: str
    unit_id: str
    event_index: int
    event_sha256: str
    argument_projections: tuple[MachineProjectionV1, ...]
    argument_expressions: tuple[Mapping[str, object], ...]
    physical_argument_expressions: tuple[Mapping[str, object], ...]
    argument_guards: tuple[Mapping[str, object], ...]
    writebacks: tuple[BoundServiceWriteback, ...]
    result: MachineProjectionV1 | None
    result_rule: Mapping[str, object] | None
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
            "checked_external_call_events",
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
        elif provider_kind == "checked_external_call_events":
            boundary = _object(call_boundary, "external-call boundary")
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
                    physical_argument_expressions=(),
                    argument_guards=(),
                    writebacks=(),
                    result=event.result,
                    result_rule=None,
                    preserved_registers=preserved_registers,
                    stack_pointer_adjustment=stack_pointer_adjustment,
                )
            else:
                event_row = _object(
                    value, f"service {service_id} external-call event {index}"
                )
                expected = {
                    "unit_id",
                    "event_index",
                    "event_sha256",
                    "identity",
                    "arguments",
                    "result",
                }
                extended = expected | {
                    "physical_arguments",
                    "argument_guards",
                    "writebacks",
                }
                extended_with_result_rule = extended | {"result_rule"}
                if frozenset(event_row) not in {
                    frozenset(expected),
                    frozenset(extended),
                    frozenset(extended_with_result_rule),
                }:
                    raise SemanticPathError(
                        f"service {service_id} external-call event fields differ"
                    )
                identity = _object(event_row.get("identity"), "external-call identity")
                if set(identity) == {"dll", "symbol", "ordinal"}:
                    pass
                elif (
                    set(identity)
                    == {
                        "kind",
                        "method_contract_sha256",
                        "profile_sha256",
                        "interface_id",
                        "method",
                        "slot",
                        "receiver_resource",
                    }
                    and identity.get("kind") == "interface_method"
                ):
                    _text(
                        identity.get("method_contract_sha256"),
                        "interface-method contract digest",
                    )
                    _text(
                        identity.get("profile_sha256"),
                        "interface-method profile digest",
                    )
                    _text(
                        identity.get("interface_id"),
                        "interface-method interface id",
                    )
                    _text(identity.get("method"), "interface-method name")
                    _uint(identity.get("slot"), "interface-method slot")
                    receiver = _object(
                        identity.get("receiver_resource"),
                        "interface-method receiver resource",
                    )
                    if (
                        set(receiver)
                        != {
                            "argument_index",
                            "view_id",
                            "required_state",
                            "dispatch_slot",
                            "lifecycle_effect",
                        }
                        or receiver.get("required_state") != "live"
                        or receiver.get("lifecycle_effect")
                        not in {
                            "preserve",
                            "may_release",
                            "release",
                        }
                    ):
                        raise SemanticPathError(
                            f"service {service_id} interface receiver is not live"
                        )
                    _uint(
                        receiver.get("argument_index"),
                        "interface-method receiver argument",
                    )
                    _uint(
                        receiver.get("dispatch_slot"),
                        "interface-method receiver slot",
                    )
                    _text(
                        receiver.get("view_id"),
                        "interface-method receiver view",
                    )
                else:
                    raise SemanticPathError(
                        f"service {service_id} external-call identity fields differ"
                    )
                result_projection = event_row.get("result")
                physical_arguments: tuple[Mapping[str, object], ...] = ()
                argument_guards: tuple[Mapping[str, object], ...] = ()
                writebacks: tuple[BoundServiceWriteback, ...] = ()
                if (
                    set(event_row) == extended
                    or set(event_row) == extended_with_result_rule
                ):
                    physical_rows = _array(
                        event_row.get("physical_arguments"),
                        "external-call physical arguments",
                    )
                    parsed_physical = []
                    for physical_index, raw_physical in enumerate(physical_rows):
                        physical = _object(
                            raw_physical,
                            f"external-call physical argument {physical_index}",
                        )
                        if (
                            set(physical) != {"index", "machine", "transducer"}
                            or physical.get("index") != physical_index
                        ):
                            raise SemanticPathError(
                                "external-call physical arguments are noncanonical"
                            )
                        _object(
                            physical.get("transducer"),
                            "external-call physical argument transducer",
                        )
                        parsed_physical.append(
                            _object(
                                physical.get("machine"),
                                "external-call physical argument expression",
                            )
                        )
                    physical_arguments = tuple(parsed_physical)
                    argument_guards = tuple(
                        _object(guard, "external-call argument guard")
                        for guard in _array(
                            event_row.get("argument_guards"),
                            "external-call argument guards",
                        )
                    )
                    parsed_writebacks = []
                    for writeback_index, raw_writeback in enumerate(
                        _array(
                            event_row.get("writebacks"),
                            "external-call writebacks",
                        )
                    ):
                        writeback = _object(
                            raw_writeback,
                            f"external-call writeback {writeback_index}",
                        )
                        if set(writeback) != {
                            "parameter_index",
                            "profile_sha256",
                            "interface_id",
                            "relation_sha256",
                            "nullable",
                            "success_condition",
                            "projection",
                        }:
                            raise SemanticPathError(
                                "external-call writeback fields differ"
                            )
                        nullable = writeback.get("nullable")
                        if not isinstance(nullable, bool):
                            raise SemanticPathError(
                                "external-call writeback nullability is invalid"
                            )
                        parsed_writebacks.append(
                            BoundServiceWriteback(
                                _uint(
                                    writeback.get("parameter_index"),
                                    "external-call writeback parameter",
                                ),
                                _text(
                                    writeback.get("profile_sha256"),
                                    "external-call writeback profile",
                                ),
                                _text(
                                    writeback.get("interface_id"),
                                    "external-call writeback interface",
                                ),
                                _text(
                                    writeback.get("relation_sha256"),
                                    "external-call writeback relation",
                                ),
                                nullable,
                                _text(
                                    writeback.get("success_condition"),
                                    "external-call writeback success condition",
                                ),
                                MachineProjectionV1.parse(
                                    writeback.get("projection"),
                                    "external-call writeback projection",
                                ),
                            )
                        )
                    writebacks = tuple(parsed_writebacks)
                result_rule = None
                if "result_rule" in event_row:
                    rule = _object(
                        event_row.get("result_rule"),
                        "external-call result rule",
                    )
                    if (
                        set(rule)
                        != {
                            "kind",
                            "relation_sha256",
                            "variant_id",
                            "word_index",
                            "failure_value",
                        }
                        or rule.get("kind") != "hresult_success_or_preserved_initial"
                    ):
                        raise SemanticPathError(
                            "external-call result rule fields differ"
                        )
                    _text(
                        rule.get("relation_sha256"),
                        "external-call result relation digest",
                    )
                    _text(
                        rule.get("variant_id"),
                        "external-call result variant",
                    )
                    _uint(
                        rule.get("word_index"),
                        "external-call result word",
                    )
                    _object(
                        rule.get("failure_value"),
                        "external-call failure-preserved value",
                    )
                    result_rule = dict(rule)
                bound = BoundServiceEvent(
                    service_id=service_id,
                    unit_id=_text(event_row.get("unit_id"), "external-call unit id"),
                    event_index=_uint(
                        event_row.get("event_index"), "external-call event index"
                    ),
                    event_sha256=_text(
                        event_row.get("event_sha256"), "external-call event digest"
                    ),
                    argument_projections=(),
                    argument_expressions=tuple(
                        _object(argument, "external-call argument expression")
                        for argument in _array(
                            event_row.get("arguments"),
                            "external-site argument expressions",
                        )
                    ),
                    physical_argument_expressions=physical_arguments,
                    argument_guards=argument_guards,
                    writebacks=writebacks,
                    result=(
                        None
                        if result_projection is None
                        else MachineProjectionV1.parse(
                            result_projection,
                            "external-call result projection",
                        )
                    ),
                    result_rule=result_rule,
                    preserved_registers=preserved_registers,
                    stack_pointer_adjustment=stack_pointer_adjustment,
                )
            key = (bound.unit_id, bound.event_index)
            if key in result:
                raise SemanticPathError("machine service event is bound more than once")
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


__all__ = ["BoundServiceEvent", "BoundServiceWriteback", "service_event_index"]
