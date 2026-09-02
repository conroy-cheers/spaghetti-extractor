# ruff: noqa: F401
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
from .interface_ir import ProofKernelComponentInterface
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


_TRANSFER_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_TRANSFER_FLAGS = ("cf", "zf", "sf", "of", "pf", "df", "af")

from .semantic_path_model import (
    _State,
    _ExecutedUnit,
)
from .semantic_path_values import (
    _unit_rva,
    _stack_address,
    _private_stack_offset,
    _expression_key,
    _collect_ops,
    _object,
    _rows,
    _array,
    _strings,
    _text,
    _uint,
    _uint_rows,
)
from .semantic_path_projection import (
    _result_binding,
    _decode_result_value,
    _derived_relation_equality,
    _projection,
    _write_projection,
    _projection_memory_location,
    _read_projection,
    _read_call_projection,
    _service_argument_load_expressions,
    _read_result_projection,
    _bind_call_result,
    _substitute,
    _logical_byte_read,
    _memory_value,
    _normalize_machine_event,
    _normalize_outcome,
    _require_logical_expression,
    _logical_load_is_authorized,
)
from .semantic_path_atomics import (
    _atomic_action_models,
)
from .semantic_path_execution import (
    _execute_semantic_unit,
    _execute_transfer_v2_unit,
)


def build_operation_path_model(
    operation: Mapping[str, object],
    interface: ProofKernelComponentInterface,
    service_bindings: object,
    *,
    boundary_operation: object | None = None,
    max_paths: int = 256,
    max_events_per_path: int = 64,
) -> dict[str, object]:
    """Return every finite machine path and its logical service trace."""

    operation_id = _text(operation.get("operation_id"), "operation id")
    machine_image = _machine_image_mapping(operation.get("machine_image"))
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
            "scalar",
            "enum",
            "resource",
            "bytes",
            "callback",
            "reference",
            "view",
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
            "scalar",
            "enum",
            "resource",
            "callback",
            "reference",
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
        _add_machine_image_alias(
            projection=entry,
            value=value,
            machine_image=machine_image,
            memory=memory,
            state_write_locations=state_write_locations,
            owner=(field.identity, width) if location is not None else None,
        )
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
                raise SemanticPathError(
                    "atomic-object projection aliases component state"
                )
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
        _add_machine_image_alias(
            projection=projection,
            value=value,
            machine_image=machine_image,
            memory=memory,
            state_write_locations=state_write_locations,
            owner=None,
        )

    # Checked local-cell profiles may import a machine-only entry word to
    # initialize an outgoing native call.  Seed exactly those declared
    # projections so the machine preparation and the service guard share one
    # stable value.  If that value escapes the checked service relation, the
    # logical-expression gate below still rejects the raw machine symbol.
    for entry_projection in _service_entry_projections(service_bindings):
        location = _projection_memory_location(entry_projection, env)
        if location is None:
            if entry_projection.kind not in {"register", "constant"}:
                raise SemanticPathError(
                    "checked service entry projection has no stable machine cell"
                )
            continue
        key, width = location
        value = memory.setdefault(
            key,
            {
                "op": "symbol",
                "name": "service_entry_"
                + canonical_sha256_v3(entry_projection.to_payload())[:16],
                "width": width * 8,
            },
        )
        _add_machine_image_alias(
            projection=entry_projection,
            value=value,
            machine_image=machine_image,
            memory=memory,
            state_write_locations=state_write_locations,
            owner=None,
        )

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
        if (
            any(
                logical_type.kind
                not in {
                    "scalar",
                    "enum",
                    "resource",
                    "resource_cell",
                    "bytes",
                    "callback",
                    "reference",
                    "view",
                }
                for logical_type in parameter_types
            )
            or any(
                logical_type.kind == "bytes" and logical_type.nul_terminated
                for logical_type in parameter_types
            )
            or (
                service.result_type_id is not None
                and types[service.result_type_id].kind
                not in {"scalar", "enum", "resource", "callback", "reference"}
            )
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

    initial = _State(
        env,
        flags,
        memory,
        copy.deepcopy(env),
        copy.deepcopy(flags),
        copy.deepcopy(memory),
        [],
        [],
        set(),
        set(),
        set(),
        set(),
    )
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
                            {
                                result.identity: {
                                    "op": "const",
                                    "value": int(route["logical_value"]),
                                    "width": 32,
                                }
                            },
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
                if state_id in preserved_state_ids and canonical_sha256_v3(
                    expected_state
                ) != canonical_sha256_v3(state_inputs[state_id]):
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
            {canonical_sha256_v3(item): item for item in entry_preconditions}.values(),
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
                "machine_word": _constant_callback_word(parameters[parameter.identity]),
            }
            for parameter in logical.parameters
            if types[parameter.type_id].kind == "callback"
        ],
        "state_ids": [row.identity for row in interface.state],
        "parameter_machine_words": parameter_machine_words,
        "max_events": max(len(path["trace"]) for path in paths),
    }


def _machine_image_mapping(value: object) -> tuple[int, int] | None:
    if value is None:
        return None
    row = _object(value, "operation machine image")
    required = {
        "image_size",
        "module_interface_sha256",
        "pe_sha256",
        "preferred_base",
    }
    preferred_base = row.get("preferred_base")
    image_size = row.get("image_size")
    if (
        set(row) != required
        or not isinstance(preferred_base, int)
        or isinstance(preferred_base, bool)
        or not isinstance(image_size, int)
        or isinstance(image_size, bool)
        or preferred_base < 0
        or image_size <= 0
        or preferred_base + image_size > 0x100000000
    ):
        raise SemanticPathError("operation machine-image mapping is malformed")
    return preferred_base, image_size


def _service_entry_projections(value: object) -> tuple[MachineProjectionV1, ...]:
    rows: dict[str, MachineProjectionV1] = {}

    def visit(item: object) -> None:
        if isinstance(item, Mapping):
            if item.get("op") == "entry_projection":
                if set(item) != {"op", "projection"}:
                    raise SemanticPathError(
                        "checked service entry-projection fields differ"
                    )
                projection = _projection(
                    item.get("projection"), "checked service entry projection"
                )
                rows[canonical_sha256_v3(projection.to_payload())] = projection
                return
            for child in item.values():
                visit(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                visit(child)

    visit(value)
    return tuple(rows[key] for key in sorted(rows))


def _static_slot_extent(
    projection: MachineProjectionV1,
) -> tuple[int, int] | None:
    payload = projection.payload
    if projection.kind == "static_slot":
        return int(payload["rva"]), int(payload["width"]) // 8
    if projection.kind in {"resource", "callback_handle", "reference"}:
        return _static_slot_extent(
            _projection(payload.get("source"), f"{projection.kind} image alias")
        )
    if projection.kind == "view":
        return _static_slot_extent(_projection(payload.get("base"), "view image alias"))
    return None


def _add_machine_image_alias(
    *,
    projection: MachineProjectionV1,
    value: Mapping[str, object],
    machine_image: tuple[int, int] | None,
    memory: dict[str, dict[str, object]],
    state_write_locations: dict[str, tuple[str, int]],
    owner: tuple[str, int] | None,
) -> None:
    if machine_image is None:
        return
    location = _static_slot_extent(projection)
    if location is None:
        return
    image_address, width = location
    preferred_base, image_size = machine_image
    if 0 <= image_address and image_address + width <= image_size:
        alias = preferred_base + image_address
    elif (
        preferred_base <= image_address
        and image_address + width <= preferred_base + image_size
    ):
        alias = image_address - preferred_base
    else:
        raise SemanticPathError(
            "component static-slot projection leaves the checked machine image"
        )
    address = {
        "op": "const",
        "value": alias,
        "width": 32,
    }
    key = _expression_key(address)
    if owner is not None:
        existing = state_write_locations.get(key)
        if existing is not None and existing != owner:
            raise SemanticPathError("component machine-image state aliases")
        state_write_locations[key] = owner
    memory[key] = copy.deepcopy(dict(value))


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

    def logical_path(
        expression: Mapping[str, object],
    ) -> tuple[str, tuple[str, ...]] | None:
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
        if not isinstance(fields, list) or any(
            not isinstance(item, str) for item in fields
        ):
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
        if (
            expression.get("op") != "same_origin"
            or not isinstance(args, list)
            or len(args) != 2
        ):
            return None
        paths = [
            logical_path(item) if isinstance(item, Mapping) else None for item in args
        ]
        output = (interaction_id, ("output", "result"))
        for left, right in ((paths[0], paths[1]), (paths[1], paths[0])):
            if left != output or right is None:
                continue
            fields = right[1]
            if (
                len(fields) == 2
                and fields[0] == "input"
                and fields[1].startswith("argument.")
            ):
                suffix = fields[1].removeprefix("argument.")
                if suffix.isdigit():
                    return int(suffix)
        return None

    def guarantee(expression: Mapping[str, object]) -> int | None:
        direct = same_origin_input(expression)
        if direct is not None:
            return direct
        args = expression.get("args")
        if not isinstance(args, list) or any(
            not isinstance(item, Mapping) for item in args
        ):
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
        if not isinstance(fields, list) or any(
            not isinstance(item, str) for item in fields
        ):
            return None
        return tuple(fields)

    def arguments(
        expression: Mapping[str, object], op: str
    ) -> list[Mapping[str, object]] | None:
        raw = expression.get("args")
        if expression.get("op") != op or not isinstance(raw, list):
            return None
        if any(not isinstance(item, Mapping) for item in raw):
            return None
        return list(raw)

    def output_null(expression: Mapping[str, object]) -> bool:
        args = arguments(expression, "ref_is_null")
        return (
            args is not None
            and len(args) == 1
            and path(args[0]) == ("output", "result")
        )

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
        return (
            value + 1
            if isinstance(value, int) and not isinstance(value, bool)
            else None
        )

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
    interaction_references: Mapping[tuple[str, int, str], Mapping[str, object]],
) -> dict[int, dict[str, object]]:
    result: dict[int, dict[str, object]] = {}
    for trace_index, event in enumerate(trace):
        key = (
            str(event.get("unit_id", "")),
            int(event.get("event_index", -1)),
            str(event.get("event_sha256", "")),
        )
        if key in interaction_references:
            result[trace_index] = copy.deepcopy(dict(interaction_references[key]))
    return result


def _constant_callback_word(projection: MachineProjectionV1) -> int:
    if projection.kind != "callback_handle":
        raise SemanticPathError(
            "callback parameter is not bound through a callback handle"
        )
    source = _projection(projection.payload.get("source"), "callback parameter source")
    if source.kind != "constant":
        raise SemanticPathError(
            "finite callback refinement requires an authority-bound constant word"
        )
    return int(source.payload["value"])
