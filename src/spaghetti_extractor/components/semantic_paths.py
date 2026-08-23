"""Machine-derived finite path models for portable component refinement.

This module contains no target knowledge and accepts no expected behavior.  It
symbolically executes exact machine-IR summaries, replacing only explicitly
bound service events with shared symbolic responses.  The resulting path set
is consumed by CBMC to compare portable C against every represented machine
path.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .inductive_receipts import CheckedInductiveMachineReceiptV1
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import PortableComponentInterfaceV2
from .machine_binding import MachineProjectionV1
from .semantic_arithmetic import (
    byte_view_offset as _byte_view_offset,
    simplify_logical_arithmetic as _simplify_logical_arithmetic,
)
from .semantic_path_errors import SemanticPathError, SemanticPathViolation
from .semantic_services import (
    BoundServiceEvent as _BoundServiceEvent,
    service_event_index as _service_event_index,
)

@dataclass
class _State:
    env: dict[str, dict[str, object]]
    flags: dict[str, dict[str, object]]
    memory: dict[str, dict[str, object]]
    guards: list[dict[str, object]]
    trace: list[dict[str, object]]
    visited: set[str]
    private_stack_writes: set[tuple[int, int]]
    pending_service_stack_writes: set[tuple[int, int]]
    service_argument_stack_writes: set[tuple[int, int]]

    def clone(self) -> "_State":
        return _State(
            copy.deepcopy(self.env),
            copy.deepcopy(self.flags),
            copy.deepcopy(self.memory),
            copy.deepcopy(self.guards),
            copy.deepcopy(self.trace),
            set(self.visited),
            set(self.private_stack_writes),
            set(self.pending_service_stack_writes),
            set(self.service_argument_stack_writes),
        )


@dataclass(frozen=True)
class _ExecutedUnit:
    semantics: Mapping[str, object]
    call_results: dict[tuple[int, str], dict[str, object]]
    edge_guards: dict[int, dict[str, object]]
    outcome: dict[str, object]


def build_operation_path_model(
    operation: Mapping[str, object],
    interface: PortableComponentInterfaceV2,
    service_bindings: object,
    *,
    boundary_operation: object | None = None,
    max_paths: int = 256,
    max_events_per_path: int = 64,
) -> dict[str, object]:
    """Return every finite machine path and its logical service trace."""

    operation_id = _text(operation.get("operation_id"), "operation id")
    logical = interface.operation_index()[operation_id]
    types = interface.type_index()
    interaction_references = _checked_interaction_reference_constraints(
        boundary_operation, operation_id
    )
    if operation.get("callback_operation_ids"):
        raise SemanticPathError(
            "legacy callback-operation inventories are unsupported; bind callback effects"
        )
    for value in logical.parameters:
        logical_type = types[value.type_id]
        if logical_type.kind not in {
            "scalar", "enum", "resource", "bytes", "callback", "reference", "view"
        }:
            raise SemanticPathError(
                "finite path refinement currently requires scalar, resource, or byte-view parameters"
            )
        if logical_type.kind == "bytes" and logical_type.nul_terminated:
            raise SemanticPathError(
                "NUL-terminated byte views require an inductive extent contract"
            )
    for value in (*logical.results, *interface.state):
        if types[value.type_id].kind not in {
            "scalar", "enum", "resource", "callback", "reference"
        }:
            raise SemanticPathError(
                "finite path refinement currently requires scalar or resource results and state"
            )

    parameters = {
        str(row["id"]): _projection(row.get("projection"), "parameter projection")
        for row in _rows(operation.get("parameters"), "operation parameters")
    }
    results = {
        str(row["id"]): _result_binding(row, "operation result")
        for row in _rows(operation.get("results"), "operation results")
    }
    if set(parameters) != {row.identity for row in logical.parameters}:
        raise SemanticPathError("parameter projection inventory differs")
    if set(results) != {row.identity for row in logical.results}:
        raise SemanticPathError("result projection inventory differs")
    state_bindings = {
        str(row["id"]): {
            "entry": _projection(row.get("entry"), "state entry projection"),
            "exit": _projection(row.get("exit"), "state exit projection"),
        }
        for row in _rows(operation.get("state"), "operation state")
    }
    preserved_state_ids = set(
        _strings(operation.get("preserved_state_ids"), "preserved state")
    )
    logical_state_ids = {row.identity for row in interface.state}
    if set(state_bindings) != logical_state_ids:
        raise SemanticPathError("state projection inventory differs")
    if not preserved_state_ids <= logical_state_ids:
        raise SemanticPathError("preserved state inventory differs")

    env = {
        name: {"op": "symbol", "name": f"machine_{name}", "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "symbol", "name": f"machine_{name}", "width": 1}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    memory: dict[str, dict[str, object]] = {}
    state_inputs: dict[str, dict[str, object]] = {}
    state_write_locations: dict[str, tuple[str, int]] = {}
    for field in interface.state:
        value = {"op": "state_input", "name": field.identity}
        state_inputs[field.identity] = value
        entry = state_bindings[field.identity]["entry"]
        location = _projection_memory_location(entry, env)
        if location is not None:
            key, width = location
            if key in state_write_locations:
                raise SemanticPathError("component state projections alias")
            state_write_locations[key] = (field.identity, width)
        _write_projection(entry, value, env, memory)
    for parameter in logical.parameters:
        logical_type = types[parameter.type_id]
        projection = parameters[parameter.identity]
        if (
            logical_type.kind == "resource"
            and logical_type.resource_kind == "atomic_object"
        ):
            if projection.kind != "atomic_object":
                raise SemanticPathError(
                    "atomic resource requires an exact atomic-object projection"
                )
            location = _projection_memory_location(projection, env)
            if location is None:
                raise SemanticPathError("atomic-object projection has no memory cell")
            key, width = location
            if key in state_write_locations:
                raise SemanticPathError("atomic-object projection aliases component state")
            state_write_locations[key] = (f"atomic:{parameter.identity}", width)
            memory[key] = {
                "op": "atomic_observed",
                "name": parameter.identity,
                "width": width * 8,
            }
            continue
        value = (
            {
                "op": "bytes_address",
                "name": parameter.identity,
                "width": 32,
            }
            if logical_type.kind == "bytes"
            else {"op": "parameter", "name": parameter.identity}
        )
        _write_projection(projection, value, env, memory)

    parameter_machine_words = {
        parameter.identity: _parameter_machine_word(
            parameter.identity, parameters[parameter.identity]
        )
        for parameter in logical.parameters
    }

    units = {
        _text(row.get("id"), "semantic unit id"): row
        for row in _rows(operation.get("units"), "semantic operation units")
    }
    entries = _strings(operation.get("entry_unit_ids"), "operation entries")
    exits = set(_strings(operation.get("exit_unit_ids"), "operation exits"))
    if len(entries) != 1:
        raise SemanticPathError("finite path refinement requires one entry")
    if not exits or set(entries) - set(units) or exits - set(units):
        raise SemanticPathError("operation entry/exit inventory is stale")
    by_rva = {_unit_rva(row): unit_id for unit_id, row in units.items()}
    if len(by_rva) != len(units):
        raise SemanticPathError("operation units have duplicate RVAs")

    atomic_actions = _atomic_action_models(
        operation=operation,
        interface=interface,
        logical=logical,
        parameter_projections=parameters,
        units=units,
        env=env,
        flags=flags,
        memory=memory,
    )

    service_index = {row.identity: row for row in interface.services}
    for service_id in logical.allowed_service_ids:
        service = service_index[service_id]
        parameter_types = [types[type_id] for type_id in service.parameter_type_ids]
        if any(
            logical_type.kind not in {
                "scalar", "enum", "resource", "bytes", "callback", "reference", "view"
            }
            for logical_type in parameter_types
        ) or any(
            logical_type.kind == "bytes" and logical_type.nul_terminated
            for logical_type in parameter_types
        ) or (
            service.result_type_id is not None
            and types[service.result_type_id].kind
            not in {"scalar", "enum", "resource", "callback", "reference"}
        ):
            raise SemanticPathError(
                f"service {service_id} requires an unsupported world value"
            )
    event_index = _service_event_index(service_bindings, service_index)
    if set(logical.allowed_service_ids) != {
        binding.service_id
        for binding in event_index.values()
        if binding.unit_id in units
    }:
        raise SemanticPathError(
            "operation service inventory differs from exact machine-event bindings"
        )

    initial = _State(env, flags, memory, [], [], set(), set(), set(), set())
    pending: list[tuple[str, _State]] = [(entries[0], initial)]
    paths: list[dict[str, object]] = []
    entry_preconditions: list[dict[str, object]] = []
    while pending:
        unit_id, state = pending.pop()
        if unit_id in state.visited:
            raise SemanticPathError(
                f"operation contains a cycle at {unit_id}; use an inductive component contract"
            )
        state.visited.add(unit_id)
        unit = units[unit_id]
        execution = _execute_semantic_unit(
            unit_id=unit_id,
            unit=unit,
            state=state,
            event_index=event_index,
            state_write_locations=state_write_locations,
            max_events=max_events_per_path,
        )
        call_results = execution.call_results

        if unit_id in exits:
            if state.pending_service_stack_writes:
                raise SemanticPathError(
                    "machine stack write is not consumed by a checked service argument"
                )
            finite_results = [
                result
                for result in logical.results
                if results[result.identity]["projection"].kind
                == "finite_control_target"
            ]
            if finite_results:
                if len(logical.results) != 1 or len(finite_results) != 1:
                    raise SemanticPathError(
                        "finite control target must be the operation's only result"
                    )
                result = finite_results[0]
                binding = results[result.identity]
                if binding.get("decoding") is not None:
                    raise SemanticPathError(
                        "finite control target does not support result decoding"
                    )
                projection = binding["projection"]
                projection_payload = projection.payload
                if (
                    projection_payload.get("unit_id") != unit_id
                    or execution.outcome.get("kind") != "indirect_jump"
                ):
                    raise SemanticPathViolation(
                        "finite control target does not project this machine exit"
                    )
                selector_id = _text(
                    projection_payload.get("selector_parameter_id"),
                    "finite control selector parameter",
                )
                if selector_id not in parameters:
                    raise SemanticPathError(
                        "finite control selector is not an operation parameter"
                    )
                variants = []
                for raw_route in _rows(
                    projection_payload.get("routes"), "finite control routes"
                ):
                    route = _object(raw_route, "finite control route")
                    guard = {
                        "op": "eq",
                        "args": [
                            {
                                "op": "parameter",
                                "name": selector_id,
                                "width": 32,
                            },
                            {
                                "op": "const",
                                "value": int(route["selector_value"]),
                                "width": 32,
                            },
                        ],
                    }
                    entry_preconditions.append(copy.deepcopy(guard))
                    variants.append(
                        (
                            {result.identity: {
                                "op": "const",
                                "value": int(route["logical_value"]),
                                "width": 32,
                            }},
                            guard,
                            {
                                "kind": "indirect_jump",
                                "target": {
                                    "op": "const",
                                    "value": int(route["target_address"]),
                                    "width": 32,
                                },
                            },
                        )
                    )
            else:
                expected_results = {
                    result.identity: _decode_result_value(
                        results[result.identity],
                        _read_result_projection(
                            results[result.identity]["projection"],
                            execution,
                            state.env,
                            state.flags,
                            state.memory,
                            call_results,
                        ),
                    )
                    for result in logical.results
                }
                variants = [
                    (
                        expected_results,
                        None,
                        copy.deepcopy(execution.outcome),
                    )
                ]
            reference_constraints = _trace_reference_constraints(
                state.trace, interaction_references
            )
            reference_origins = {
                index: int(constraint["input_argument_index"])
                for index, constraint in reference_constraints.items()
            }
            logical_memory_authority = {
                "parameters": sorted(
                    parameter.identity
                    for parameter in logical.parameters
                    if types[parameter.type_id].kind in {"reference", "view"}
                ),
                "service_results": sorted(reference_origins),
            }
            for guard in state.guards:
                _require_logical_expression(
                    guard, "path guard", memory_authority=logical_memory_authority
                )
            for event in state.trace:
                for argument in event["arguments"]:
                    _require_logical_expression(
                        argument,
                        "service argument",
                        memory_authority=logical_memory_authority,
                    )
            state_outputs = {
                field.identity: _read_projection(
                    state_bindings[field.identity]["exit"],
                    state.env,
                    state.memory,
                    state.flags,
                )
                for field in interface.state
            }
            for state_id, expected_state in state_outputs.items():
                _require_logical_expression(
                    expected_state,
                    f"component state {state_id}",
                    memory_authority=logical_memory_authority,
                )
                if (
                    state_id in preserved_state_ids
                    and canonical_sha256_v3(expected_state)
                    != canonical_sha256_v3(state_inputs[state_id])
                ):
                    raise SemanticPathViolation(
                        f"preserved component state {state_id} is modified by the machine path"
                    )
            for expected_results, route_guard, completion_outcome in variants:
                for result_id, expected_result in expected_results.items():
                    _require_logical_expression(
                        expected_result,
                        f"operation result {result_id}",
                        memory_authority=logical_memory_authority,
                    )
                path_guards = copy.deepcopy(state.guards)
                if route_guard is not None:
                    path_guards.append(copy.deepcopy(route_guard))
                paths.append(
                    {
                        "guards": path_guards,
                        "results": expected_results,
                        "state": state_outputs,
                        "trace": state.trace,
                        "reference_origins": [
                            {"trace_index": index, **copy.deepcopy(constraint)}
                            for index, constraint in sorted(
                                reference_constraints.items()
                            )
                        ],
                        "exit_unit_id": unit_id,
                        "completion": {
                            "registers": copy.deepcopy(state.env),
                            "flags": copy.deepcopy(state.flags),
                            "outcome": completion_outcome,
                        },
                        "private_stack_writes": [
                            {"offset": offset, "width": width}
                            for offset, width in sorted(state.private_stack_writes)
                        ],
                        "service_argument_stack_writes": [
                            {"offset": offset, "width": width}
                            for offset, width in sorted(
                                state.service_argument_stack_writes
                            )
                        ],
                    }
                )
            if len(paths) > max_paths:
                raise SemanticPathError("finite operation path budget exceeded")
            continue

        for target, guard in reversed(tuple(execution.edge_guards.items())):
            if target not in by_rva:
                raise SemanticPathError(
                    f"operation edge from {unit_id} leaves the selected unit set"
                )
            successor = state.clone()
            successor.guards.append(copy.deepcopy(guard))
            pending.append((by_rva[target], successor))
    if not paths:
        raise SemanticPathError("operation has no path to a declared exit")
    return {
        "entry_preconditions": sorted(
            {
                canonical_sha256_v3(item): item
                for item in entry_preconditions
            }.values(),
            key=canonical_sha256_v3,
        ),
        "result_ids": [row.identity for row in logical.results],
        "paths": sorted(paths, key=canonical_sha256_v3),
        "service_ids": list(logical.allowed_service_ids),
        "atomic_actions": atomic_actions,
        "callback_parameters": [
            {
                "parameter_id": parameter.identity,
                "type_id": parameter.type_id,
                "machine_word": _constant_callback_word(
                    parameters[parameter.identity]
                ),
            }
            for parameter in logical.parameters
            if types[parameter.type_id].kind == "callback"
        ],
        "state_ids": [row.identity for row in interface.state],
        "parameter_machine_words": parameter_machine_words,
        "max_events": max(len(path["trace"]) for path in paths),
    }


def _parameter_machine_word(
    parameter_id: str, projection: MachineProjectionV1
) -> dict[str, object]:
    current = projection
    while current.kind in {"view", "bytes_view", "reference", "resource"}:
        field = "base" if current.kind in {"view", "bytes_view"} else "source"
        current = _projection(
            current.payload.get(field), f"{parameter_id} machine-word source"
        )
    if current.kind == "constant":
        return {
            "op": "const",
            "value": int(current.payload.get("value", 0)),
            "width": int(current.payload.get("width", 32)),
        }
    return {"op": "parameter", "name": parameter_id, "width": 32}


def _checked_interaction_reference_constraints(
    boundary_operation: object | None, operation_id: str
) -> dict[tuple[str, int, str], dict[str, object]]:
    """Index checked reference results and their reusable contract constraints."""

    if boundary_operation is None:
        return {}
    operation = _object(boundary_operation, "boundary operation")
    if operation.get("operation_id") != operation_id:
        raise SemanticPathError("boundary operation identity differs")
    result: dict[tuple[str, int, str], dict[str, object]] = {}
    for interaction in _rows(
        operation.get("interactions"), "boundary operation interactions"
    ):
        if interaction.get("contract_id") is None:
            continue
        machine_event = _object(
            interaction.get("machine_event"), "boundary interaction machine event"
        )
        invocation = _object(
            interaction.get("invoke_action"), "boundary interaction invocation"
        )
        clause = _object(invocation.get("clause"), "boundary interaction clause")
        input_index = _nullable_same_origin_input(
            clause.get("ensures"), str(interaction.get("id", ""))
        )
        if input_index is None:
            continue
        constraint: dict[str, object] = {
            "input_argument_index": input_index,
        }
        remaining = _nonnull_minimum_remaining(
            clause.get("ensures"), str(interaction.get("id", ""))
        )
        if remaining is not None:
            argument_index, minimum = remaining
            constraint["nonnull_min_remaining"] = {
                "nonzero_argument_index": argument_index,
                "minimum": minimum,
            }
        key = (
            _text(machine_event.get("unit_id"), "interaction unit id"),
            _uint(machine_event.get("event_index"), "interaction event index"),
            _text(machine_event.get("event_sha256"), "interaction event digest"),
        )
        if key in result:
            raise SemanticPathError("boundary interaction machine event is ambiguous")
        result[key] = constraint
    return result


def _nullable_same_origin_input(value: object, interaction_id: str) -> int | None:
    ensures = _rows(value, "interaction ensures")

    def logical_path(expression: Mapping[str, object]) -> tuple[str, tuple[str, ...]] | None:
        if expression.get("op") != "logical":
            return None
        attributes = expression.get("attributes")
        if not isinstance(attributes, Mapping):
            return None
        path = attributes.get("path")
        if not isinstance(path, Mapping) or path.get("root") != "interaction":
            return None
        if path.get("id") != interaction_id:
            return None
        fields = path.get("fields")
        if not isinstance(fields, list) or any(not isinstance(item, str) for item in fields):
            return None
        return interaction_id, tuple(fields)

    def ref_is_null(expression: Mapping[str, object]) -> bool:
        args = expression.get("args")
        return (
            expression.get("op") == "ref_is_null"
            and isinstance(args, list)
            and len(args) == 1
            and isinstance(args[0], Mapping)
            and logical_path(args[0]) == (interaction_id, ("output", "result"))
        )

    def same_origin_input(expression: Mapping[str, object]) -> int | None:
        args = expression.get("args")
        if expression.get("op") != "same_origin" or not isinstance(args, list) or len(args) != 2:
            return None
        paths = [logical_path(item) if isinstance(item, Mapping) else None for item in args]
        output = (interaction_id, ("output", "result"))
        for left, right in ((paths[0], paths[1]), (paths[1], paths[0])):
            if left != output or right is None:
                continue
            fields = right[1]
            if len(fields) == 2 and fields[0] == "input" and fields[1].startswith("argument."):
                suffix = fields[1].removeprefix("argument.")
                if suffix.isdigit():
                    return int(suffix)
        return None

    def guarantee(expression: Mapping[str, object]) -> int | None:
        direct = same_origin_input(expression)
        if direct is not None:
            return direct
        args = expression.get("args")
        if not isinstance(args, list) or any(not isinstance(item, Mapping) for item in args):
            return None
        if expression.get("op") == "and":
            candidates = [guarantee(item) for item in args]
            return next((item for item in candidates if item is not None), None)
        if expression.get("op") == "or" and len(args) == 2:
            if ref_is_null(args[0]):
                return same_origin_input(args[1])
            if ref_is_null(args[1]):
                return same_origin_input(args[0])
        return None

    candidates = [guarantee(item) for item in ensures]
    selected = {item for item in candidates if item is not None}
    if len(selected) > 1:
        raise SemanticPathError("interaction output has ambiguous origin guarantees")
    return next(iter(selected), None)


def _nonnull_minimum_remaining(
    value: object, interaction_id: str
) -> tuple[int, int] | None:
    """Recognize a checked conditional lower bound on a reference result."""

    ensures = _rows(value, "interaction ensures")

    def path(expression: Mapping[str, object]) -> tuple[str, ...] | None:
        if expression.get("op") != "logical":
            return None
        attributes = expression.get("attributes")
        raw = None if not isinstance(attributes, Mapping) else attributes.get("path")
        if not isinstance(raw, Mapping) or raw.get("root") != "interaction":
            return None
        if raw.get("id") != interaction_id:
            return None
        fields = raw.get("fields")
        if not isinstance(fields, list) or any(not isinstance(item, str) for item in fields):
            return None
        return tuple(fields)

    def arguments(expression: Mapping[str, object], op: str) -> list[Mapping[str, object]] | None:
        raw = expression.get("args")
        if expression.get("op") != op or not isinstance(raw, list):
            return None
        if any(not isinstance(item, Mapping) for item in raw):
            return None
        return list(raw)

    def output_null(expression: Mapping[str, object]) -> bool:
        args = arguments(expression, "ref_is_null")
        return args is not None and len(args) == 1 and path(args[0]) == ("output", "result")

    def zero_input(expression: Mapping[str, object]) -> int | None:
        args = arguments(expression, "eq")
        if args is None or len(args) != 2:
            return None
        for logical, constant in ((args[0], args[1]), (args[1], args[0])):
            fields = path(logical)
            if (
                fields is not None
                and len(fields) == 2
                and fields[0] == "input"
                and fields[1].startswith("argument.")
                and constant.get("op") == "const"
                and constant.get("attributes", {}).get("value") == 0
            ):
                suffix = fields[1].removeprefix("argument.")
                if suffix.isdigit():
                    return int(suffix)
        return None

    def remaining_bound(expression: Mapping[str, object]) -> int | None:
        args = arguments(expression, "ult")
        if args is None or len(args) != 2 or args[0].get("op") != "const":
            return None
        remaining = arguments(args[1], "ref_remaining")
        if remaining is None or len(remaining) != 1:
            return None
        if path(remaining[0]) != ("output", "result"):
            return None
        value = args[0].get("attributes", {}).get("value")
        return value + 1 if isinstance(value, int) and not isinstance(value, bool) else None

    def conditional(expression: Mapping[str, object]) -> tuple[int, int] | None:
        args = arguments(expression, "or")
        if args is None or len(args) != 2:
            return None
        for zero, bound in ((args[0], args[1]), (args[1], args[0])):
            argument_index = zero_input(zero)
            minimum = remaining_bound(bound)
            if argument_index is not None and minimum is not None:
                return argument_index, minimum
        return None

    matches: set[tuple[int, int]] = set()
    for ensure in ensures:
        args = arguments(ensure, "or")
        if args is None or len(args) != 2:
            continue
        for null, condition in ((args[0], args[1]), (args[1], args[0])):
            match = conditional(condition) if output_null(null) else None
            if match is not None:
                matches.add(match)
    if len(matches) > 1:
        raise SemanticPathError("interaction output has ambiguous extent guarantees")
    return next(iter(matches), None)


def _trace_reference_constraints(
    trace: list[dict[str, object]],
    interaction_references: Mapping[
        tuple[str, int, str], Mapping[str, object]
    ],
) -> dict[int, dict[str, object]]:
    result: dict[int, dict[str, object]] = {}
    for trace_index, event in enumerate(trace):
        key = (
            str(event.get("unit_id", "")),
            int(event.get("event_index", -1)),
            str(event.get("event_sha256", "")),
        )
        if key in interaction_references:
            result[trace_index] = copy.deepcopy(
                dict(interaction_references[key])
            )
    return result


def _constant_callback_word(projection: MachineProjectionV1) -> int:
    if projection.kind != "callback_handle":
        raise SemanticPathError(
            "callback parameter is not bound through a callback handle"
        )
    source = _projection(
        projection.payload.get("source"), "callback parameter source"
    )
    if source.kind != "constant":
        raise SemanticPathError(
            "finite callback refinement requires an authority-bound constant word"
        )
    return int(source.payload["value"])


def build_inductive_segment_models(
    operation: Mapping[str, object],
    interface: PortableComponentInterfaceV2,
    source_plan: InductiveSourcePlanV1,
    machine_receipt: CheckedInductiveMachineReceiptV1,
    relation: InductiveCutpointRelationV1,
    service_bindings: object,
    *,
    max_events_per_segment: int = 64,
) -> dict[str, object]:
    """Symbolically execute every exact finite segment between cutpoints."""

    relation.validate_for(interface, source_plan, machine_receipt)
    operation_id = _text(operation.get("operation_id"), "operation id")
    if operation_id != source_plan.operation_id:
        raise SemanticPathError("inductive operation identity differs")
    logical = interface.operation_index()[operation_id]
    types = interface.type_index()
    if any(
        types[value.type_id].kind not in {"scalar", "enum", "resource", "bytes"}
        for value in logical.parameters
    ):
        raise SemanticPathError(
            "inductive segments require scalar, resource, or byte-view parameters"
        )
    if any(
        types[value.type_id].kind not in {"scalar", "enum", "resource"}
        for value in logical.results
    ):
        raise SemanticPathError(
            "inductive segments require scalar or resource results"
        )

    parameters = {
        str(row["id"]): _projection(
            row.get("projection"), "parameter projection"
        )
        for row in _rows(operation.get("parameters"), "operation parameters")
    }
    results = {
        str(row["id"]): _result_binding(row, "inductive result")
        for row in _rows(operation.get("results"), "operation results")
    }
    if set(parameters) != {row.identity for row in logical.parameters}:
        raise SemanticPathError("inductive parameter projection inventory differs")
    if set(results) != {row.identity for row in logical.results}:
        raise SemanticPathError("inductive result projection inventory differs")

    units = {
        _text(row.get("id"), "semantic unit id"): row
        for row in _rows(operation.get("units"), "semantic operation units")
    }
    receipt_shape = machine_receipt.shape.to_value()
    assert isinstance(receipt_shape, dict)
    expected_unit_hashes = {
        str(row["unit_id"]): str(row["semantics_sha256"])
        for row in receipt_shape["semantic_units"]
        if isinstance(row, Mapping)
    }
    observed_unit_hashes = {
        unit_id: canonical_sha256_v3(
            _object(unit.get("semantics"), "semantic unit semantics")
        )
        for unit_id, unit in units.items()
    }
    if observed_unit_hashes != expected_unit_hashes:
        raise SemanticPathError(
            "inductive semantic operation differs from its exact machine receipt"
        )

    service_index = {row.identity: row for row in interface.services}
    event_index = _service_event_index(service_bindings, service_index)
    relation_index = {item.unit_id: item for item in relation.cutpoints}
    completion_index = {
        item.segment_id: item.completion_id
        for item in relation.completion_segments
    }
    inventory = machine_receipt.segment_inventory.to_value()
    assert isinstance(inventory, dict)
    models: list[dict[str, object]] = []
    for raw_segment in _rows(inventory.get("segments"), "inductive segments"):
        segment_id = _text(raw_segment.get("segment_id"), "segment id")
        source = _object(raw_segment.get("source"), "segment source")
        target = _object(raw_segment.get("target"), "segment target")
        env = {
            name: {
                "op": "symbol",
                "name": f"machine_{name}",
                "width": 32,
            }
            for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        flags = {
            name: {
                "op": "symbol",
                "name": f"machine_{name}",
                "width": 1,
            }
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        }
        state = _State(env, flags, {}, [], [], set(), set(), set(), set())
        source_kind = _text(source.get("kind"), "segment source kind")
        source_id = _text(source.get("id"), "segment source id")
        if source_kind == "operation_entry":
            for parameter in logical.parameters:
                _write_projection(
                    parameters[parameter.identity],
                    _logical_input_expression(
                        parameter.identity, types[parameter.type_id].kind
                    ),
                    state.env,
                    state.memory,
                )
            source_phase = None
        elif source_kind == "cutpoint":
            cutpoint = relation_index.get(source_id)
            if cutpoint is None:
                raise SemanticPathError("segment source cutpoint is not related")
            for value in cutpoint.values:
                if value.mode in {"logical_carry", "logical_definition"}:
                    continue
                assert value.projection is not None
                assert value.encoding is not None
                _write_projection(
                    value.projection,
                    copy.deepcopy(dict(value.encoding)),
                    state.env,
                    state.memory,
                )
            for derived in cutpoint.derived:
                _write_projection(
                    derived.projection,
                    copy.deepcopy(dict(derived.expression)),
                    state.env,
                    state.memory,
                )
            source_phase = cutpoint.phase_id
        else:
            raise SemanticPathError("segment source kind is unsupported")

        edges = _rows(raw_segment.get("edges"), "segment edges")
        edge_by_source: dict[str, Mapping[str, object]] = {}
        for edge in edges:
            edge_source = _text(edge.get("source_unit_id"), "segment edge source")
            if edge_source in edge_by_source:
                raise SemanticPathError(
                    "one exact segment contains multiple selected edges from a unit"
                )
            edge_by_source[edge_source] = edge
        last_execution: _ExecutedUnit | None = None
        unit_ids = _strings(raw_segment.get("unit_ids"), "segment units")
        for unit_id in unit_ids:
            if unit_id in state.visited or unit_id not in units:
                raise SemanticPathError("segment unit path is cyclic or stale")
            state.visited.add(unit_id)
            last_execution = _execute_semantic_unit(
                unit_id=unit_id,
                unit=units[unit_id],
                state=state,
                event_index=event_index,
                state_write_locations={},
                max_events=max_events_per_segment,
            )
            selected_edge = edge_by_source.get(unit_id)
            if selected_edge is not None:
                target_unit_id = _text(
                    selected_edge.get("target_unit_id"), "segment edge target"
                )
                if target_unit_id not in units:
                    raise SemanticPathError(
                        "segment edge target is absent from the operation"
                    )
                target_rva = _unit_rva(units[target_unit_id])
                guard = last_execution.edge_guards.get(target_rva)
                if guard is None:
                    raise SemanticPathError(
                        "segment edge is absent from the executed unit control summary"
                    )
                state.guards.append(copy.deepcopy(guard))
        if last_execution is None:
            raise SemanticPathError("exact segment contains no machine units")
        if state.pending_service_stack_writes:
            raise SemanticPathError(
                "machine stack write crosses an inductive cutpoint without a frame relation"
            )
        if set(edge_by_source) - set(unit_ids):
            raise SemanticPathError("segment edge source is absent from its unit path")

        target_kind = _text(target.get("kind"), "segment target kind")
        target_id = _text(target.get("id"), "segment target id")
        target_values: dict[str, dict[str, object]] = {}
        relation_checks: list[dict[str, object]] = []
        target_phase: str | None = None
        expected_results: dict[str, dict[str, object]] = {}
        completion_id: str | None = None
        if target_kind == "cutpoint":
            cutpoint = relation_index.get(target_id)
            if cutpoint is None:
                raise SemanticPathError("segment target cutpoint is not related")
            target_phase = cutpoint.phase_id
            observed_values: dict[tuple[str, str], dict[str, object]] = {}
            for value in cutpoint.values:
                if value.mode == "logical_carry":
                    target_values[f"source_state:{value.identity}"] = {
                        "op": "state_input",
                        "name": value.identity,
                    }
                    continue
                if value.mode == "logical_definition":
                    assert value.encoding is not None
                    target_values[f"source_state:{value.identity}"] = (
                        copy.deepcopy(dict(value.encoding))
                    )
                    continue
                assert value.projection is not None
                try:
                    observed = _read_projection(
                        value.projection,
                        state.env,
                        state.memory,
                        state.flags,
                        last_execution.call_results,
                    )
                except SemanticPathError as exc:
                    raise SemanticPathError(
                        f"segment {segment_id} cannot read target cutpoint "
                        f"value {value.kind}:{value.identity}: {exc}"
                    ) from exc
                observed_values[(value.kind, value.identity)] = observed
                if value.kind == "parameter":
                    logical_type = types[
                        next(
                            item.type_id
                            for item in logical.parameters
                            if item.identity == value.identity
                        )
                    ]
                    target_values[f"parameter:{value.identity}"] = (
                        _logical_input_expression(
                            value.identity, logical_type.kind
                        )
                    )
                else:
                    assert value.decoding is not None
                    target_values[f"source_state:{value.identity}"] = (
                        _simplify_logical_arithmetic(
                            _replace_projected_value(value.decoding, observed)
                        )
                    )
            for value in cutpoint.values:
                if value.mode in {"logical_carry", "logical_definition"}:
                    continue
                assert value.encoding is not None
                expected = _replace_target_state_inputs(
                    value.encoding, target_values
                )
                try:
                    relation_checks.append(
                        _derived_relation_equality(
                            observed_values[(value.kind, value.identity)],
                            expected,
                            f"value:{value.kind}:{value.identity}",
                        )
                    )
                except SemanticPathError as exc:
                    raise SemanticPathError(
                        f"segment {segment_id} target relation failed: {exc}"
                    ) from exc
            for derived in cutpoint.derived:
                observed = _read_projection(
                    derived.projection,
                    state.env,
                    state.memory,
                    state.flags,
                    last_execution.call_results,
                )
                expected = _replace_target_state_inputs(
                    derived.expression, target_values
                )
                relation_checks.append(
                    _derived_relation_equality(observed, expected, derived.identity)
                )
        elif target_kind == "operation_exit":
            completion_id = completion_index.get(segment_id)
            if completion_id is None:
                raise SemanticPathError("operation-exit segment has no completion relation")
            expected_results = {
                result.identity: _decode_result_value(
                    results[result.identity],
                    _read_result_projection(
                        results[result.identity]["projection"],
                        last_execution,
                        state.env,
                        state.flags,
                        state.memory,
                        last_execution.call_results,
                    ),
                )
                for result in logical.results
            }
        else:
            raise SemanticPathError("segment target kind is unsupported")
        for index, expression in enumerate(state.guards):
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} guard {index}",
            )
        for index, expression in enumerate(relation_checks):
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} relation check {index}",
            )
        for value_id, expression in target_values.items():
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} target value {value_id}",
            )
        for result_id, expression in expected_results.items():
            _require_logical_expression(
                expression,
                f"inductive segment {segment_id} result {result_id}",
            )
        models.append(
            {
                "segment_id": segment_id,
                "source": {
                    "kind": source_kind,
                    "id": source_id,
                    "phase_id": source_phase,
                },
                "target": {
                    "kind": target_kind,
                    "id": target_id,
                    "phase_id": target_phase,
                    "completion_id": completion_id,
                },
                "guards": copy.deepcopy(state.guards),
                "relation_checks": relation_checks,
                "target_values": target_values,
                "results": expected_results,
                "trace": copy.deepcopy(state.trace),
                "private_stack_writes": [
                    {"offset": offset, "width": width}
                    for offset, width in sorted(state.private_stack_writes)
                ],
                "service_argument_stack_writes": [
                    {"offset": offset, "width": width}
                    for offset, width in sorted(
                        state.service_argument_stack_writes
                    )
                ],
            }
        )
    return {
        "operation_id": operation_id,
        "machine_receipt_sha256": machine_receipt.receipt_sha256,
        "relation_sha256": relation.relation_sha256,
        "segments": sorted(models, key=lambda item: str(item["segment_id"])),
        "model_sha256": canonical_sha256_v3(
            sorted(models, key=lambda item: str(item["segment_id"]))
        ),
    }


def _logical_input_expression(identity: str, kind: str) -> dict[str, object]:
    if kind == "bytes":
        return {"op": "bytes_address", "name": identity}
    return {"op": "parameter", "name": identity}


def _replace_target_state_inputs(
    value: Mapping[str, object],
    target_values: Mapping[str, dict[str, object]],
) -> dict[str, object]:
    if value.get("op") == "state_input":
        name = _text(value.get("name"), "derived state-input name")
        replacement = target_values.get(f"source_state:{name}")
        if replacement is None:
            raise SemanticPathError(
                f"derived relation references unavailable source state {name!r}"
            )
        return copy.deepcopy(replacement)
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(item, Mapping):
            result[str(key)] = _replace_target_state_inputs(item, target_values)
        elif isinstance(item, list):
            result[str(key)] = [
                _replace_target_state_inputs(child, target_values)
                if isinstance(child, Mapping)
                else copy.deepcopy(child)
                for child in item
            ]
        else:
            result[str(key)] = copy.deepcopy(item)
    return _simplify_logical_arithmetic(result)


def _replace_projected_value(
    value: Mapping[str, object], projected: Mapping[str, object]
) -> dict[str, object]:
    if value.get("op") == "projected_value":
        return copy.deepcopy(dict(projected))
    result: dict[str, object] = {}
    for key, item in value.items():
        if isinstance(item, Mapping):
            result[str(key)] = _replace_projected_value(item, projected)
        elif isinstance(item, list):
            result[str(key)] = [
                _replace_projected_value(child, projected)
                if isinstance(child, Mapping)
                else copy.deepcopy(child)
                for child in item
            ]
        else:
            result[str(key)] = copy.deepcopy(item)
    return result


def _result_binding(
    value: Mapping[str, object], context: str
) -> dict[str, object]:
    if set(value) not in ({"id", "projection"}, {"id", "projection", "decoding"}):
        raise SemanticPathError(f"{context} fields differ")
    decoding = value.get("decoding")
    if decoding is not None and not isinstance(decoding, Mapping):
        raise SemanticPathError(f"{context} decoding is malformed")
    return {
        "projection": _projection(value.get("projection"), f"{context} projection"),
        "decoding": None if decoding is None else copy.deepcopy(dict(decoding)),
    }


def _decode_result_value(
    binding: Mapping[str, object], observed: Mapping[str, object]
) -> dict[str, object]:
    decoding = binding.get("decoding")
    if decoding is None:
        return copy.deepcopy(dict(observed))
    if not isinstance(decoding, Mapping):
        raise SemanticPathError("result decoding is malformed")
    return _simplify_logical_arithmetic(
        _replace_projected_value(decoding, observed)
    )


def _derived_relation_equality(
    observed: Mapping[str, object],
    expected: Mapping[str, object],
    identity: str,
) -> dict[str, object]:
    observed_view = _byte_view_offset(observed)
    expected_view = _byte_view_offset(expected)
    if observed_view is not None or expected_view is not None:
        if (
            observed_view is None
            or expected_view is None
            or observed_view[0] != expected_view[0]
        ):
            raise SemanticPathError(
                f"derived relation {identity!r} compares incompatible byte views"
            )
        left, right = observed_view[1], expected_view[1]
    else:
        left = copy.deepcopy(dict(observed))
        right = copy.deepcopy(dict(expected))
    return {"op": "eq", "args": [left, right]}


def _execute_semantic_unit(
    *,
    unit_id: str,
    unit: Mapping[str, object],
    state: _State,
    event_index: Mapping[tuple[str, int], _BoundServiceEvent],
    state_write_locations: Mapping[str, tuple[str, int]],
    max_events: int,
) -> _ExecutedUnit:
    """Apply one exact unit to symbolic state exactly once."""

    semantics = _object(unit.get("semantics"), "machine unit semantics")
    if semantics.get("faults"):
        raise SemanticPathError("machine faults require explicit operation outcomes")
    old_env = copy.deepcopy(state.env)
    old_flags = copy.deepcopy(state.flags)
    old_memory = copy.deepcopy(state.memory)
    call_results: dict[tuple[int, str], dict[str, object]] = {}
    external_events = _rows(
        semantics.get("external_events", []), "machine external events"
    )
    event_memory = copy.deepcopy(old_memory)
    ordered_service_writes: set[tuple[int, int]] = set()
    consumed_service_writes: set[tuple[int, int]] = set()

    def process_external_event(machine_event_index: int) -> None:
        machine_event = external_events[machine_event_index]
        bound = event_index.get((unit_id, machine_event_index))
        if bound is None:
            raise SemanticPathError(
                f"external event {unit_id}:{machine_event_index} has no logical service binding"
            )
        if len(state.trace) >= max_events:
            raise SemanticPathError("service-event budget exceeded")
        for expression in _service_argument_load_expressions(bound, machine_event):
            for load in _collect_ops(expression, "load"):
                address = _substitute(
                    load.get("address"),
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                width = load.get("width")
                offset = _private_stack_offset(address)
                if (
                    isinstance(width, int)
                    and not isinstance(width, bool)
                    and offset is not None
                    and 0 <= offset <= 65536 - width
                    and (offset, width) in state.pending_service_stack_writes
                ):
                    state.pending_service_stack_writes.remove((offset, width))
                    state.service_argument_stack_writes.add((offset, width))
                    consumed_service_writes.add((offset, width))
        arguments = (
            [
                _substitute(
                    expression,
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                for expression in bound.argument_expressions
            ]
            if bound.argument_expressions
            else [
                _read_call_projection(
                    projection,
                    machine_event,
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                for projection in bound.argument_projections
            ]
        )
        trace_index = len(state.trace)
        normalized_event = _normalize_machine_event(
            machine_event,
            old_env,
            old_flags,
            event_memory,
            call_results,
        )
        if bound.argument_expressions:
            normalized_event["arguments"] = copy.deepcopy(arguments)
        register_inputs = _object(
            machine_event.get("register_inputs"), "external register inputs"
        )
        for register in (
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
        ):
            if register in bound.preserved_registers or (
                register == "esp"
                and bound.stack_pointer_adjustment is not None
            ):
                preserved_value = _substitute(
                    register_inputs[register],
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                if register == "esp" and bound.stack_pointer_adjustment:
                    preserved_value = _simplify_logical_arithmetic({
                        "op": "add32",
                        "args": [
                            preserved_value,
                            {
                                "op": "const",
                                "value": bound.stack_pointer_adjustment,
                                "width": 32,
                            },
                        ],
                    })
                call_results[(machine_event_index, register)] = preserved_value
            else:
                call_results[(machine_event_index, register)] = {
                    "op": "service_machine_result",
                    "index": trace_index,
                    "register": register,
                    "width": 32,
                }
        for flag in ("cf", "zf", "sf", "of", "pf", "df"):
            call_results[(machine_event_index, f"flag:{flag}")] = {
                "op": "service_machine_flag",
                "index": trace_index,
                "flag": flag,
                "width": 1,
            }
        state.trace.append(
            {
                "service_id": bound.service_id,
                "arguments": arguments,
                "guards": copy.deepcopy(state.guards),
                "machine_event": normalized_event,
                "unit_id": unit_id,
                "event_index": machine_event_index,
                "event_sha256": bound.event_sha256,
            }
        )
        if bound.result is not None:
            response = {
                "op": "service_result",
                "index": trace_index,
                "width": 64,
            }
            _bind_call_result(
                bound.result,
                machine_event_index,
                response,
                call_results,
                event_memory,
                old_env,
                old_flags,
                event_memory,
            )

    ordered_events = _rows(
        semantics.get("ordered_events", []), "ordered machine events"
    )
    if ordered_events:
        external_cursor = 0
        for ordered_event in ordered_events:
            family = ordered_event.get("family")
            if family == "memory" and ordered_event.get("kind") == "write":
                address = _substitute(
                    ordered_event.get("address"),
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                value = _substitute(
                    ordered_event.get("value"),
                    old_env,
                    old_flags,
                    event_memory,
                    call_results,
                )
                event_memory[_expression_key(address)] = value
                width = ordered_event.get("width")
                offset = _private_stack_offset(address)
                owner = state_write_locations.get(_expression_key(address))
                if (
                    owner is None
                    and isinstance(width, int)
                    and not isinstance(width, bool)
                    and offset is not None
                    and 0 <= offset <= 65536 - width
                ):
                    state.pending_service_stack_writes.add((offset, width))
                    ordered_service_writes.add((offset, width))
            elif family == "external":
                if external_cursor >= len(external_events):
                    raise SemanticPathError(
                        "ordered external-event inventory exceeds machine events"
                    )
                process_external_event(external_cursor)
                external_cursor += 1
        if external_cursor != len(external_events):
            raise SemanticPathError(
                "ordered external-event inventory differs from machine events"
            )
    else:
        for machine_event_index in range(len(external_events)):
            process_external_event(machine_event_index)

    state.memory.update(event_memory)

    # Every expression in a unit observes the same unit-entry state.  Final
    # writes become visible only to the next unit.
    expression_memory = copy.deepcopy(old_memory)
    for raw in _rows(semantics.get("memory_events", []), "memory events"):
        if raw.get("kind") != "write":
            continue
        address = _substitute(
            raw.get("address"),
            old_env,
            old_flags,
            expression_memory,
            call_results,
        )
        value = _substitute(
            raw.get("value"),
            old_env,
            old_flags,
            expression_memory,
            call_results,
        )
        width = raw.get("width")
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            raise SemanticPathError("machine memory write width is invalid")
        key = _expression_key(address)
        owner = state_write_locations.get(key)
        if owner is not None and owner[1] == width:
            state.memory[key] = value
            continue
        private_offset = _private_stack_offset(address)
        if private_offset is not None and -65536 <= private_offset < 0:
            if private_offset + width > 0:
                raise SemanticPathError(
                    "machine memory write crosses the component stack-frame boundary"
                )
            state.private_stack_writes.add((private_offset, width))
            state.memory[key] = value
            continue
        stack_write = (private_offset, width)
        if (
            private_offset is not None
            and 0 <= private_offset <= 65536 - width
            and stack_write in ordered_service_writes
            and (
                stack_write in state.pending_service_stack_writes
                or stack_write in consumed_service_writes
            )
        ):
            state.memory[key] = value
            continue
        if private_offset is None or private_offset < -65536:
            raise SemanticPathError(
                "machine memory write is outside the checked component-state frame"
            )
        raise SemanticPathError(
            "machine stack write is not ordered as a checked service argument"
        )

    normalized_edge_guards: dict[int, dict[str, object]] = {}
    raw_edges = _rows(semantics.get("edge_conditions", []), "edge conditions")
    if not raw_edges:
        raw_outcome = _object(semantics.get("outcome"), "machine outcome")
        target = raw_outcome.get("target_rva")
        if isinstance(target, int):
            raw_edges = [{"condition": {"op": "true"}, "target_rva": target}]
    for raw_edge in raw_edges:
        target = raw_edge.get("target_rva")
        if not isinstance(target, int) or isinstance(target, bool):
            raise SemanticPathError("machine edge target is invalid")
        guard = _substitute(
            raw_edge.get("condition"),
            old_env,
            old_flags,
            old_memory,
            call_results,
        )
        prior = normalized_edge_guards.get(target)
        normalized_edge_guards[target] = guard if prior is None else {
            "op": "or_bool",
            "args": [prior, guard],
        }
    normalized_outcome = _normalize_outcome(
        semantics.get("outcome"),
        old_env,
        old_flags,
        old_memory,
        call_results,
    )

    state.env.update(
        {
            _text(raw.get("register"), "written register"): _substitute(
                raw.get("value"),
                old_env,
                old_flags,
                expression_memory,
                call_results,
            )
            for raw in _rows(semantics.get("register_writes", []), "register writes")
        }
    )
    state.flags.update(
        {
            _text(raw.get("flag"), "written flag"): _substitute(
                raw.get("value"),
                old_env,
                old_flags,
                expression_memory,
                call_results,
            )
            for raw in _rows(semantics.get("flag_writes", []), "flag writes")
        }
    )
    return _ExecutedUnit(
        semantics=semantics,
        call_results=call_results,
        edge_guards=normalized_edge_guards,
        outcome=normalized_outcome,
    )


def _projection(value: object, context: str) -> MachineProjectionV1:
    return MachineProjectionV1.parse(value, context)


def _write_projection(
    projection: MachineProjectionV1,
    value: dict[str, object],
    env: dict[str, dict[str, object]],
    memory: dict[str, dict[str, object]],
) -> None:
    payload = projection.payload
    if projection.kind == "register":
        register = _text(payload.get("register"), "projection register")
        width = int(payload.get("width", 32))
        if width == 32:
            env[register] = copy.deepcopy(value)
        else:
            mask = (1 << width) - 1
            env[register] = _simplify_logical_arithmetic({
                "op": "or32",
                "args": [
                    {
                        "op": "and32",
                        "args": [
                            env[register],
                            {
                                "op": "const",
                                "value": (~mask) & 0xFFFFFFFF,
                                "width": 32,
                            },
                        ],
                    },
                    {
                        "op": "and32",
                        "args": [
                            value,
                            {"op": "const", "value": mask, "width": 32},
                        ],
                    },
                ],
            })
        return
    if projection.kind == "stack":
        address = _stack_address(env["esp"], int(payload.get("offset", 0)))
        memory[_expression_key(address)] = copy.deepcopy(value)
        return
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        memory[_expression_key(address)] = copy.deepcopy(value)
        return
    if projection.kind == "resource":
        _write_projection(_projection(payload.get("source"), "resource source"), value, env, memory)
        return
    if projection.kind == "atomic_object":
        return
    if projection.kind == "callback_handle":
        _write_projection(
            _projection(payload.get("source"), "callback-handle source"),
            value,
            env,
            memory,
        )
        return
    if projection.kind == "reference":
        _write_projection(
            _projection(payload.get("source"), "reference source"),
            value,
            env,
            memory,
        )
        return
    if projection.kind == "view":
        _write_projection(
            _projection(payload.get("base"), "view base"),
            value,
            env,
            memory,
        )
        return
    if projection.kind == "bytes_view":
        _write_projection(
            _projection(payload.get("base"), "byte-view base"), value, env, memory
        )
        return
    if projection.kind == "constant":
        return
    raise SemanticPathError(f"entry projection {projection.kind!r} is unsupported")


def _projection_memory_location(
    projection: MachineProjectionV1,
    env: Mapping[str, dict[str, object]],
) -> tuple[str, int] | None:
    """Return the exact memory cell owned by a projection, when it has one."""

    payload = projection.payload
    if projection.kind == "stack":
        address = _stack_address(env["esp"], int(payload.get("offset", 0)))
        return _expression_key(address), int(payload.get("width", 32)) // 8
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        return _expression_key(address), int(payload.get("width", 32)) // 8
    if projection.kind == "resource":
        return _projection_memory_location(
            _projection(payload.get("source"), "resource source"), env
        )
    if projection.kind == "atomic_object":
        source = _projection(payload.get("source"), "atomic-object source")
        if source.kind != "constant":
            return None
        address = {
            "op": "const",
            "value": int(source.payload["value"]),
            "width": int(source.payload["width"]),
        }
        return _expression_key(address), int(payload.get("width", 0))
    if projection.kind == "callback_handle":
        return _projection_memory_location(
            _projection(payload.get("source"), "callback-handle source"), env
        )
    if projection.kind == "reference":
        return _projection_memory_location(
            _projection(payload.get("source"), "reference source"), env
        )
    if projection.kind == "view":
        return _projection_memory_location(
            _projection(payload.get("base"), "view base"), env
        )
    return None


def _read_projection(
    projection: MachineProjectionV1,
    env: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]] | None = None,
    call_results: Mapping[tuple[int, str], dict[str, object]] | None = None,
) -> dict[str, object]:
    payload = projection.payload
    if projection.kind == "register":
        register = _text(payload.get("register"), "projection register")
        width = int(payload.get("width", 32))
        value = copy.deepcopy(env[register])
        if width == 32:
            return value
        return _simplify_logical_arithmetic({
            "op": "and32",
            "args": [
                value,
                {"op": "const", "value": (1 << width) - 1, "width": 32},
            ],
        })
    if projection.kind == "stack":
        address = _stack_address(env["esp"], int(payload.get("offset", 0)))
        return _memory_value(memory, address)
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        return _memory_value(memory, address)
    if projection.kind == "constant":
        return {
            "op": "const",
            "value": int(payload.get("value", 0)),
            "width": int(payload.get("width", 32)),
        }
    if projection.kind == "resource":
        return _read_projection(
            _projection(payload.get("source"), "resource source"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "callback_handle":
        return _read_projection(
            _projection(payload.get("source"), "callback-handle source"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "reference":
        return _read_projection(
            _projection(payload.get("source"), "reference source"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "view":
        return _read_projection(
            _projection(payload.get("base"), "view base"),
            env,
            memory,
            flags,
            call_results,
        )
    if projection.kind == "bytes_view":
        return _read_projection(
            _projection(payload.get("base"), "byte-view base"),
            env,
            memory,
            flags,
            call_results,
        )
    raise SemanticPathError(f"exit projection {projection.kind!r} is unsupported")


def _read_call_projection(
    projection: MachineProjectionV1,
    event: Mapping[str, object],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    payload = projection.payload
    if projection.kind == "register":
        register = _text(payload.get("register"), "call projection register")
        inputs = _object(event.get("register_inputs"), "external register inputs")
        if register not in inputs:
            raise SemanticPathError(f"external event has no {register} input")
        return _substitute(inputs[register], env, flags, memory, call_results)
    if projection.kind == "stack":
        offset = int(payload.get("offset", 0))
        matches = [
            row
            for row in _rows(event.get("stack_inputs", []), "external stack inputs")
            if row.get("offset") == offset
        ]
        if len(matches) > 1:
            raise SemanticPathError(
                f"external event stack offset {offset} is ambiguous"
            )
        if matches:
            return _substitute(
                matches[0].get("value"), env, flags, memory, call_results
            )
        # Machine events intentionally carry only the stack words observed by
        # the unit that contains the call.  Call arguments are commonly
        # prepared by preceding units, so a checked service projection may
        # name a call-time stack word that is absent from that local capture.
        # Reconstruct it from the event's exact call-time ESP and the
        # persistent symbolic memory instead of treating unit boundaries as
        # argument-lifetime boundaries.
        inputs = _object(event.get("register_inputs"), "external register inputs")
        if "esp" not in inputs:
            raise SemanticPathError(
                f"external event stack offset {offset} has no call-time ESP"
            )
        call_esp = _substitute(inputs["esp"], env, flags, memory, call_results)
        return _memory_value(memory, _stack_address(call_esp, offset))
    if projection.kind in {
        "constant", "static_slot", "resource", "reference", "view"
    }:
        return _read_projection(projection, env, memory, flags, call_results)
    raise SemanticPathError(
        f"service argument projection {projection.kind!r} is unsupported"
    )


def _service_argument_load_expressions(
    binding: _BoundServiceEvent,
    event: Mapping[str, object],
) -> tuple[Mapping[str, object], ...]:
    """Return exact expressions whose loads supply a bound service argument."""

    if binding.argument_expressions:
        return binding.argument_expressions
    result: list[Mapping[str, object]] = []
    stack_inputs = _rows(event.get("stack_inputs", []), "external stack inputs")
    register_inputs = _object(
        event.get("register_inputs"), "external register inputs"
    )
    for projection in binding.argument_projections:
        if projection.kind != "stack":
            continue
        offset = int(projection.payload.get("offset", 0))
        matches = [row for row in stack_inputs if row.get("offset") == offset]
        if len(matches) > 1:
            raise SemanticPathError(
                f"external event stack offset {offset} is ambiguous"
            )
        if matches:
            result.append(
                _object(matches[0].get("value"), "external stack input")
            )
            continue
        call_esp = register_inputs.get("esp")
        if not isinstance(call_esp, Mapping):
            raise SemanticPathError(
                f"external event stack offset {offset} has no call-time ESP"
            )
        result.append(
            {
                "op": "load",
                "address": _stack_address(
                    _object(call_esp, "external call-time ESP"), offset
                ),
                "width": int(projection.payload.get("width", 32)) // 8,
            }
        )
    return tuple(result)


def _read_result_projection(
    projection: MachineProjectionV1,
    execution: _ExecutedUnit,
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    if projection.kind != "control_condition":
        return _read_projection(projection, env, memory, flags, call_results)
    outcome = execution.outcome
    if outcome.get("kind") != "branch" or not isinstance(
        outcome.get("condition"), Mapping
    ):
        raise SemanticPathViolation(
            "control-condition result does not project a machine branch"
        )
    return copy.deepcopy(dict(outcome["condition"]))


def _bind_call_result(
    projection: MachineProjectionV1,
    event_index: int,
    value: dict[str, object],
    call_results: dict[tuple[int, str], dict[str, object]],
    memory: dict[str, dict[str, object]],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    old_memory: Mapping[str, dict[str, object]],
) -> None:
    payload = projection.payload
    if projection.kind == "register":
        call_results[(event_index, _text(payload.get("register"), "result register"))] = value
        return
    if projection.kind == "static_slot":
        address = {"op": "const", "value": int(payload["rva"]), "width": 32}
        memory[_expression_key(address)] = value
        return
    if projection.kind == "memory":
        address_projection = _projection(payload.get("address"), "result address")
        address = _read_projection(
            address_projection, env, old_memory, flags, call_results
        )
        memory[_expression_key(address)] = value
        return
    if projection.kind == "resource":
        _bind_call_result(
            _projection(payload.get("source"), "resource result source"),
            event_index,
            value,
            call_results,
            memory,
            env,
            flags,
            old_memory,
        )
        return
    if projection.kind in {"callback_handle", "reference", "view"}:
        source_field = "base" if projection.kind == "view" else "source"
        _bind_call_result(
            _projection(payload.get(source_field), f"{projection.kind} result source"),
            event_index,
            value,
            call_results,
            memory,
            env,
            flags,
            old_memory,
        )
        return
    raise SemanticPathError(
        f"service result projection {projection.kind!r} is unsupported"
    )


def _substitute(
    value: object,
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    row = _object(value, "machine expression")
    op = row.get("op")
    if op == "reg":
        return copy.deepcopy(env[_text(row.get("name"), "register expression")])
    if op == "flag":
        return copy.deepcopy(flags[_text(row.get("name"), "flag expression")])
    if op == "load":
        address = _substitute(row.get("address"), env, flags, memory, call_results)
        known = memory.get(_expression_key(address))
        if known is not None:
            return copy.deepcopy(known)
        width = int(row.get("width", 4))
        byte_read = _logical_byte_read(address, width)
        if byte_read is not None:
            return byte_read
        return {
            "op": "load",
            "address": address,
            "width": width,
        }
    if op == "call_response":
        call_index = row.get("call_index")
        register = _text(row.get("register"), "call-response register")
        if not isinstance(call_index, int) or isinstance(call_index, bool):
            raise SemanticPathError("call-response index is invalid")
        return copy.deepcopy(
            call_results.get(
                (call_index, register),
                {
                    "op": "symbol",
                    "name": f"machine_call_{call_index}_{register}",
                    "width": int(row.get("width", 32)),
                },
            )
        )
    if op == "call_flag":
        call_index = row.get("call_index")
        flag = _text(row.get("flag"), "call-response flag")
        if not isinstance(call_index, int) or isinstance(call_index, bool):
            raise SemanticPathError("call-response flag index is invalid")
        return copy.deepcopy(
            call_results.get(
                (call_index, f"flag:{flag}"),
                {
                    "op": "symbol",
                    "name": f"machine_call_{call_index}_{flag}",
                    "width": 1,
                },
            )
        )
    result = {key: copy.deepcopy(item) for key, item in row.items() if key != "args"}
    if "args" in row:
        if not isinstance(row["args"], list):
            raise SemanticPathError("machine expression arguments are malformed")
        result["args"] = [
            _substitute(item, env, flags, memory, call_results)
            if isinstance(item, Mapping)
            else item
            for item in row["args"]
        ]
    return _simplify_logical_arithmetic(result)


def _logical_byte_read(
    address: Mapping[str, object], width: int
) -> dict[str, object] | None:
    if width != 1:
        return None
    resolved = _byte_view_offset(address)
    if resolved is None:
        return None
    name, index = resolved
    return {
        "op": "byte_read",
        "name": name,
        "index": index,
    }


def _memory_value(
    memory: Mapping[str, dict[str, object]], address: dict[str, object]
) -> dict[str, object]:
    known = memory.get(_expression_key(address))
    if known is None:
        raise SemanticPathError("observable expression reads unmapped memory")
    return copy.deepcopy(known)


def _normalize_machine_event(
    event: Mapping[str, object],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {
        key: copy.deepcopy(value)
        for key, value in event.items()
        if key not in {
            "arguments", "stack_inputs", "register_inputs", "flag_inputs", "target"
        }
    }
    for field in ("register_inputs", "flag_inputs"):
        raw = _object(event.get(field, {}), f"external {field}")
        result[field] = {
            str(name): _substitute(value, env, flags, memory, call_results)
            for name, value in raw.items()
        }
    arguments = _rows(event.get("arguments", []), "external arguments")
    result["arguments"] = [
        _substitute(value, env, flags, memory, call_results)
        for value in arguments
    ]
    stack_inputs: list[dict[str, object]] = []
    for raw in _rows(event.get("stack_inputs", []), "external stack inputs"):
        row = dict(raw)
        row["value"] = _substitute(
            raw.get("value"), env, flags, memory, call_results
        )
        stack_inputs.append(row)
    result["stack_inputs"] = stack_inputs
    if isinstance(event.get("target"), Mapping):
        result["target"] = _substitute(
            event.get("target"), env, flags, memory, call_results
        )
    unresolved_responses = [
        row
        for row in _collect_ops(result, "symbol")
        if str(row.get("name", "")).startswith("machine_call_")
    ]
    if unresolved_responses:
        raise SemanticPathError(
            "external event input depends on an unavailable call response"
        )
    return result


def _normalize_outcome(
    value: object,
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
    call_results: Mapping[tuple[int, str], dict[str, object]],
) -> dict[str, object]:
    raw = _object(value, "machine outcome")
    result = copy.deepcopy(dict(raw))
    for field in ("value", "target", "condition"):
        if isinstance(raw.get(field), Mapping):
            result[field] = _substitute(
                raw[field], env, flags, memory, call_results
            )
    return result


def _require_logical_expression(
    value: object,
    context: str,
    *,
    memory_authority: Mapping[str, object] | None = None,
) -> None:
    for unsupported in (
        "symbol",
        "call_response",
        "call_flag",
        "service_machine_result",
        "service_machine_flag",
        "reg",
        "flag",
    ):
        matches = _collect_ops(value, unsupported)
        if matches:
            names = sorted(
                {str(row.get("name") or row.get("register") or unsupported) for row in matches}
            )
            raise SemanticPathError(
                f"{context} depends on unmapped machine values: {', '.join(names)}"
            )
    for load in _collect_ops(value, "load"):
        if not _logical_load_is_authorized(load, memory_authority):
            raise SemanticPathError(
                f"{context} depends on unmapped machine values: load"
            )


def _logical_load_is_authorized(
    load: Mapping[str, object], memory_authority: Mapping[str, object] | None
) -> bool:
    if memory_authority is None:
        return False
    width = load.get("width")
    address = load.get("address")
    if width not in {1, 2, 4, 8} or not isinstance(address, Mapping):
        return False
    if any(
        _collect_ops(address, op)
        for op in (
            "load", "symbol", "call_response", "call_flag",
            "service_machine_result", "service_machine_flag", "reg", "flag",
        )
    ):
        return False
    parameters = {
        str(item) for item in memory_authority.get("parameters", [])
    }
    service_results = {
        int(item) for item in memory_authority.get("service_results", [])
        if isinstance(item, int) and not isinstance(item, bool)
    }
    parameter_anchors = {
        str(item.get("name"))
        for item in _collect_ops(address, "parameter")
        if isinstance(item.get("name"), str)
    }
    service_anchors = {
        int(item.get("index"))
        for item in _collect_ops(address, "service_result")
        if isinstance(item.get("index"), int)
        and not isinstance(item.get("index"), bool)
    }
    return bool(
        (parameter_anchors and parameter_anchors <= parameters)
        or (service_anchors and service_anchors <= service_results)
    )


def _atomic_action_models(
    *,
    operation: Mapping[str, object],
    interface: PortableComponentInterfaceV2,
    logical: object,
    parameter_projections: Mapping[str, MachineProjectionV1],
    units: Mapping[str, Mapping[str, object]],
    env: Mapping[str, dict[str, object]],
    flags: Mapping[str, dict[str, object]],
    memory: Mapping[str, dict[str, object]],
) -> list[dict[str, object]]:
    """Project exact authoritative RMW actions into the logical world model."""

    service_effect_ids = {
        effect_id
        for service in interface.services
        if service.identity in set(getattr(logical, "allowed_service_ids"))
        for effect_id in service.effect_ids
    }
    direct_effect_ids = set(getattr(logical, "effect_ids")) - service_effect_ids
    logical_effects = {
        row.identity: row
        for row in interface.effects
        if row.identity in direct_effect_ids
    }
    bound_effects = _rows(operation.get("effects", []), "operation effects")
    if not logical_effects and not bound_effects:
        if any(item.kind == "atomic_object" for item in parameter_projections.values()):
            raise SemanticPathError("atomic-object parameter has no direct atomic effect")
        return []
    if set(logical_effects) != direct_effect_ids:
        raise SemanticPathError("operation effect inventory is stale")
    by_effect: dict[str, list[Mapping[str, object]]] = {
        effect_id: [] for effect_id in logical_effects
    }
    for row in bound_effects:
        effect_id = _text(row.get("effect_id"), "bound effect id")
        if effect_id not in by_effect:
            raise SemanticPathError("machine binding contains an unknown direct effect")
        by_effect[effect_id].append(row)

    models: list[dict[str, object]] = []
    seen_parameters: set[str] = set()
    for effect_id, effect in logical_effects.items():
        parameter_id = effect.target_id
        if (
            effect.kind != "memory"
            or effect.operation not in {"compare_exchange", "exchange"}
            or parameter_id is None
            or parameter_id not in parameter_projections
        ):
            raise SemanticPathError(
                "direct effects require a checked atomic RMW world model"
            )
        projection = parameter_projections[parameter_id]
        if projection.kind != "atomic_object" or parameter_id in seen_parameters:
            raise SemanticPathError("atomic effect target projection is invalid")
        seen_parameters.add(parameter_id)
        payload = projection.payload
        unit_id = _text(payload.get("unit_id"), "atomic projection unit")
        unit = units.get(unit_id)
        if unit is None:
            raise SemanticPathError("atomic projection unit is outside the operation")
        semantics = _object(unit.get("semantics"), "atomic unit semantics")
        graph = _object(semantics.get("memory_actions"), "memory-action graph")
        authority = _object(graph.get("authority"), "memory-action authority")
        if graph.get("status") != "complete" or authority.get("authoritative") is not True:
            raise SemanticPathError("atomic projection graph is not authoritative")
        matches = [
            row
            for row in _rows(graph.get("actions"), "memory actions")
            if row.get("id") == payload.get("action_id")
        ]
        if len(matches) != 1:
            raise SemanticPathError("atomic projection action is stale")
        action = matches[0]
        operation_kind = action.get("operation")
        if (
            action.get("kind") != "rmw"
            or operation_kind not in {"compare_exchange", "exchange"}
            or action.get("width_bytes") != payload.get("width")
            or graph.get("profile_id") != payload.get("profile_id")
        ):
            raise SemanticPathError("atomic projection action shape is stale")
        raw_source_indices = action.get("source_memory_event_indices")
        if not isinstance(raw_source_indices, list) or any(
            not isinstance(index, int) or isinstance(index, bool) or index < 0
            for index in raw_source_indices
        ):
            raise SemanticPathError("atomic source event indices are malformed")
        expected_refs = {(unit_id, index) for index in raw_source_indices}
        observed_refs = {
            (
                _text(row.get("unit_id"), "atomic effect unit"),
                int(row.get("index", -1)),
            )
            for row in by_effect[effect_id]
            if row.get("family") == "memory_event"
        }
        if observed_refs != expected_refs or len(observed_refs) != len(by_effect[effect_id]):
            raise SemanticPathError("atomic effect does not bind the exact RMW events")
        if operation_kind == "compare_exchange":
            transition = _object(action.get("compare"), "compare/exchange operands")
            expected = _substitute(transition.get("expected"), env, flags, memory, {})
            desired = _substitute(transition.get("desired"), env, flags, memory, {})
            _require_logical_expression(expected, "atomic expected value")
        else:
            transition = _object(action.get("transition"), "exchange transition")
            expected = None
            desired = _substitute(transition.get("written"), env, flags, memory, {})
        _require_logical_expression(desired, "atomic desired value")
        models.append(
            {
                "effect_id": effect_id,
                "parameter_id": parameter_id,
                "action_id": action["id"],
                "profile_id": graph["profile_id"],
                "width": action["width_bytes"],
                "operation": operation_kind,
                "expected": expected,
                "desired": desired,
            }
        )
    return sorted(models, key=canonical_sha256_v3)


def _unit_rva(unit: Mapping[str, object]) -> int:
    source = _object(unit.get("source"), "machine unit source")
    original = _object(source.get("original"), "machine unit original range")
    rva = original.get("rva_start")
    if not isinstance(rva, int) or isinstance(rva, bool):
        raise SemanticPathError("machine unit RVA is invalid")
    return rva


def _stack_address(base: Mapping[str, object], offset: int) -> dict[str, object]:
    if offset == 0:
        return copy.deepcopy(dict(base))
    return {
        "op": "add32",
        "args": [
            copy.deepcopy(dict(base)),
            {"op": "const", "value": offset & 0xFFFFFFFF, "width": 32},
        ],
    }


def _private_stack_offset(value: object) -> int | None:
    """Recognize a bounded constant address below operation-entry ESP."""

    if not isinstance(value, Mapping):
        return None
    if (
        value.get("op") == "symbol"
        and value.get("name") == "machine_esp"
        and value.get("width") == 32
    ):
        return 0
    op = value.get("op")
    args = value.get("args")
    if op not in {"add32", "sub32"} or not isinstance(args, list) or len(args) != 2:
        return None
    left = _private_stack_offset(args[0])
    right = args[1]
    if left is None or not isinstance(right, Mapping) or right.get("op") != "const":
        return None
    constant = right.get("value")
    if (
        right.get("width") != 32
        or not isinstance(constant, int)
        or isinstance(constant, bool)
        or constant < 0
        or constant > 0xFFFFFFFF
    ):
        return None
    signed = constant if constant < 0x80000000 else constant - 0x100000000
    if abs(signed) > 65536:
        return None
    return left + signed if op == "add32" else left - signed


def _expression_key(value: object) -> str:
    def canonical(item: object) -> object:
        if isinstance(item, Mapping):
            result = {str(key): canonical(child) for key, child in item.items()}
            if result.get("op") in {"add32", "and32", "or32", "xor32"} and isinstance(
                result.get("args"), list
            ):
                result["args"] = sorted(result["args"], key=canonical_sha256_v3)
            return result
        if isinstance(item, list):
            return [canonical(child) for child in item]
        return item

    normalized = (
        _simplify_logical_arithmetic(value)
        if isinstance(value, Mapping)
        else value
    )
    return canonical_sha256_v3(canonical(normalized))


def _collect_ops(value: object, operation: str) -> list[Mapping[str, object]]:
    result: list[Mapping[str, object]] = []
    if isinstance(value, Mapping):
        if value.get("op") == operation:
            result.append(value)
        for child in value.values():
            result.extend(_collect_ops(child, operation))
    elif isinstance(value, list):
        for child in value:
            result.extend(_collect_ops(child, operation))
    return result


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticPathError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, Mapping) for row in value):
        raise SemanticPathError(f"{context} must be an array of objects")
    return list(value)


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise SemanticPathError(f"{context} must be an array")
    return value


def _strings(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise SemanticPathError(f"{context} must be an array of nonempty strings")
    return tuple(value)


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticPathError(f"{context} must be a nonempty string")
    return value


def _uint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SemanticPathError(f"{context} must be an unsigned integer")
    return value


__all__ = [
    "SemanticPathError",
    "SemanticPathViolation",
    "build_inductive_segment_models",
    "build_operation_path_model",
]
