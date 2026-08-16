"""Executable lowering of checked finite portable-component path models."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .interface_ir import PortableComponentInterfaceV2, PortableOperationV2
from .machine_binding import OperationMachineBindingV1
from .semantic_paths import SemanticPathError


_STATE_FIELDS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAG_FIELDS = ("cf", "zf", "sf", "of", "pf", "df")


def render_finite_path_operation(
    *,
    interface: PortableComponentInterfaceV2,
    operation: PortableOperationV2,
    binding: OperationMachineBindingV1,
    service_bindings: Sequence[object],
    source_symbol: str,
    adapter_symbol: str,
    model: Mapping[str, object],
) -> str:
    """Render one source operation and its exact external-event protocol."""

    if operation.effect_ids or binding.effects or binding.callback_operation_ids:
        raise SemanticPathError(
            "finite runtime lowering requires operations without direct effects or callbacks"
        )
    paths = _rows(model.get("paths"), "finite runtime paths")
    if not paths:
        raise SemanticPathError("finite runtime model has no paths")
    max_events = max(1, int(model.get("max_events", 0)))
    max_arguments = max(
        1,
        max(
            (
                len(_array(event.get("arguments"), "service trace arguments"))
                for path in paths
                for event in _rows(path.get("trace"), "service trace")
            ),
            default=0,
        ),
    )
    prefix = _c_identifier(adapter_symbol)
    type_index = interface.type_index()
    parameter_positions = {
        value.identity: index for index, value in enumerate(operation.parameters)
    }
    byte_parameters = [
        value
        for value in operation.parameters
        if type_index[value.type_id].kind == "bytes"
    ]
    state_positions = {
        value.identity: index for index, value in enumerate(interface.state)
    }
    state_bindings = {value.identity: value for value in binding.state}
    if set(state_bindings) != set(state_positions):
        raise SemanticPathError("runtime state binding inventory differs")
    service_numbers = {
        service.identity: index + 1
        for index, service in enumerate(interface.services)
    }
    renderer = _ExpressionRenderer(
        parameter_positions,
        state_positions=state_positions,
        context="(*service_context)",
    )
    service_binding_index = attach_service_bindings(model, service_bindings)
    candidates = _service_candidates(paths)

    lines = [
        f"typedef struct {prefix}_service_context {{",
        "  spx_runtime *runtime;",
        "  spx_machine_state entry;",
        f"  spx_machine_state call_outputs[{max_events}];",
        f"  uint64_t parameters[{max(1, len(operation.parameters))}];",
        f"  const spx_bytes_view_v2 *byte_views[{max(1, len(operation.parameters))}];",
        f"  uint64_t state_values[{max(1, len(interface.state))}];",
        f"  uint64_t logical_results[{max_events}];",
        f"  uint32_t service_ids[{max_events}];",
        f"  uint32_t argument_counts[{max_events}];",
        f"  uint64_t arguments[{max_events}][{max_arguments}];",
        "  uint32_t count;",
        "  spx_call_status fault;",
        f"}} {prefix}_service_context;",
        "",
    ]
    if byte_parameters:
        lines.extend(
            [
                f"typedef struct {prefix}_bytes_context {{",
                "  spx_runtime *runtime;",
                "  uint32_t base;",
                "  uint32_t extent;",
                f"}} {prefix}_bytes_context;",
                f"static uint32_t {prefix}_read_u8(",
                "    void *opaque, uint32_t index, uint8_t *result) {",
                f"  {prefix}_bytes_context *view = ({prefix}_bytes_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  uint32_t value;",
                "  if (result == 0 || index >= view->extent) return UINT32_C(1);",
                "  value = component_read(view->runtime, view->base + index, UINT32_C(1), &fault);",
                "  if (fault != 0U) return UINT32_C(1);",
                "  *result = (uint8_t)value;",
                "  return UINT32_C(0);",
                "}",
                "",
            ]
        )
    for service in interface.services:
        if service.identity not in set(model.get("service_ids", [])):
            continue
        result_type = (
            "void"
            if service.result_type_id is None
            else _logical_c_type(type_index[service.result_type_id])
        )
        parameters = ["void *opaque"] + [
            f"{_logical_c_type(type_index[type_id])} argument_{index}"
            for index, type_id in enumerate(service.parameter_type_ids)
        ]
        lines.extend(
            [
                f"static {result_type} {prefix}_service_{service.identity}({', '.join(parameters)}) {{",
                f"  {prefix}_service_context *service_context = ({prefix}_service_context *)opaque;",
                "  uint32_t memory_fault = 0U;",
                "  uint32_t event_index = service_context->count;",
                f"  if (event_index >= UINT32_C({max_events}) || service_context->fault != SPX_CALL_OK) {{",
                "    service_context->fault = SPX_CALL_UNIMPLEMENTED;",
            ]
        )
        lines.append("    return;" if result_type == "void" else f"    return ({result_type})0;")
        lines.append("  }")
        for candidate_index, candidate in enumerate(candidates.get(service.identity, ())):
            condition = _candidate_condition(
                candidate,
                renderer=renderer,
                service_numbers=service_numbers,
                parameter_positions=parameter_positions,
                service_parameter_type_ids=service.parameter_type_ids,
                type_index=type_index,
            )
            keyword = "if" if candidate_index == 0 else "else if"
            lines.append(f"  {keyword} ({condition}) {{")
            lines.extend(
                _render_machine_call(
                    candidate=candidate,
                    renderer=renderer,
                    service_number=service_numbers[service.identity],
                    argument_count=len(service.parameter_type_ids),
                    service_parameter_type_ids=service.parameter_type_ids,
                    type_index=type_index,
                    parameter_positions=parameter_positions,
                    result_projection=service_binding_index[service.identity][
                        (
                            str(candidate["unit_id"]),
                            int(candidate["event_index"]),
                        )
                    ],
                    result_type=result_type,
                )
            )
            lines.append("  }")
        lines.extend(
            [
                "  service_context->fault = SPX_CALL_UNIMPLEMENTED;",
                "  return;" if result_type == "void" else f"  return ({result_type})0;",
                "}",
                "",
            ]
        )

    service_type = f"spx_{interface.identity}_services_v2"
    context_type = f"spx_{interface.identity}_context_v2"
    lines.extend(
        [
            f"spx_step_result {adapter_symbol}(spx_runtime *rt, spx_machine_state *state) {{",
            f"  {prefix}_service_context service_context = {{0}};",
            "  uint32_t memory_fault = 0U;",
            f"  {service_type} services = {{0}};",
            f"  {context_type} component_context = {{0}};",
            "  service_context.runtime = rt;",
            "  service_context.entry = *state;",
            "  service_context.fault = SPX_CALL_OK;",
            "  services.context = &service_context;",
        ]
    )
    for service in interface.services:
        if service.identity in set(model.get("service_ids", [])):
            lines.append(
                f"  services.{service.identity} = {prefix}_service_{service.identity};"
            )
    lines.extend(
        [
            "  component_context.services = &services;",
        ]
    )
    pre_states = [
        f"component_context.protocol_state == SPX_{interface.identity.upper()}_PROTOCOL_{state.upper()}"
        for state in operation.pre_states
    ]
    lines.append(
        "  if (!(" + " || ".join(pre_states) + ")) "
        "return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };"
    )
    for state_id, position in state_positions.items():
        state_type = _logical_c_type(
            type_index[next(row.type_id for row in interface.state if row.identity == state_id)]
        )
        projection = state_bindings[state_id].entry.payload
        lines.extend(
            [
                f"  {state_type} logical_state_{position} = ({state_type})"
                f"({_projection_read(projection, state='state')});",
                f"  component_context.state.{state_id} = logical_state_{position};",
                f"  service_context.state_values[{position}] = "
                f"(uint64_t)logical_state_{position};",
            ]
        )
    parameter_bindings = {value.identity: value for value in binding.parameters}
    if set(parameter_bindings) != set(parameter_positions):
        raise SemanticPathError("runtime parameter binding inventory differs")
    arguments_by_id: dict[str, str] = {}
    for logical in operation.parameters:
        logical_type = type_index[logical.type_id]
        if logical_type.kind == "bytes":
            continue
        index = parameter_positions[logical.identity]
        projected = parameter_bindings[logical.identity]
        c_type = _logical_c_type(logical_type)
        value = _projection_read(projected.projection.payload, state="state")
        lines.extend(
            [
                f"  {c_type} argument_{index} = ({c_type})({value});",
                f"  service_context.parameters[{index}] = (uint64_t)argument_{index};",
            ]
        )
        arguments_by_id[logical.identity] = f"argument_{index}"
    for logical in operation.parameters:
        logical_type = type_index[logical.type_id]
        if logical_type.kind != "bytes":
            continue
        index = parameter_positions[logical.identity]
        projected = parameter_bindings[logical.identity].projection.payload
        if projected.get("kind") != "bytes_view":
            raise SemanticPathError("runtime byte parameter requires a byte-view projection")
        extent_id = logical_type.extent_parameter_id
        if extent_id is None or extent_id not in arguments_by_id:
            raise SemanticPathError("runtime byte parameter has no scalar extent")
        base = _projection_read(
            _object(projected.get("base"), "runtime byte-view base"), state="state"
        )
        lines.extend(
            [
                f"  uint32_t argument_{index}_base = (uint32_t)({base});",
                f"  {prefix}_bytes_context argument_{index}_context = "
                f"{{rt, argument_{index}_base, (uint32_t){arguments_by_id[extent_id]}}};",
                f"  spx_bytes_view_v2 argument_{index}_view = "
                f"{{&argument_{index}_context, (uint32_t){arguments_by_id[extent_id]}, "
                f"{prefix}_read_u8, 0}};",
                f"  const spx_bytes_view_v2 *argument_{index} = &argument_{index}_view;",
                f"  service_context.parameters[{index}] = (uint64_t)argument_{index}_base;",
                f"  service_context.byte_views[{index}] = argument_{index};",
            ]
        )
        arguments_by_id[logical.identity] = f"argument_{index}"
    arguments = [arguments_by_id[row.identity] for row in operation.parameters]
    call = f"{source_symbol}(&component_context"
    if arguments:
        call += ", " + ", ".join(arguments)
    call += ")"
    result_type = interface.operation_c_result(operation)
    if operation.results:
        lines.append(f"  {result_type} logical_result = {call};")
    else:
        lines.append(f"  {call};")
    lines.extend(
        [
            "  if (service_context.fault != SPX_CALL_OK) return (spx_step_result){",
            "    service_context.fault == SPX_CALL_DIVIDE_ERROR ? SPX_DIVIDE_ERROR :",
            "    service_context.fault == SPX_CALL_MEMORY_FAULT ? SPX_MEMORY_FAULT :",
            "    service_context.fault == SPX_CALL_EXTERNAL_FAULT ? SPX_EXTERNAL_FAULT :",
            "    SPX_UNIMPLEMENTED, 0U, 0U };",
        ]
    )
    post_states = [
        f"component_context.protocol_state == SPX_{interface.identity.upper()}_PROTOCOL_{state.upper()}"
        for state in operation.post_states
    ]
    lines.append(
        "  if (!(" + " || ".join(post_states) + ")) "
        "return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };"
    )
    completion_renderer = _ExpressionRenderer(
        parameter_positions,
        state_positions=state_positions,
        context="service_context",
    )
    for path_index, path in enumerate(paths):
        condition = _completion_condition(
            path,
            renderer=completion_renderer,
            service_numbers=service_numbers,
            operation=operation,
            type_index=type_index,
        )
        keyword = "if" if path_index == 0 else "else if"
        lines.append(f"  {keyword} ({condition}) {{")
        completion = _object(path.get("completion"), "path completion")
        registers = _object(completion.get("registers"), "completion registers")
        flags = _object(completion.get("flags"), "completion flags")
        for field_index, name in enumerate(_STATE_FIELDS):
            lines.append(
                f"    uint32_t completed_register_{field_index} = "
                f"(uint32_t)({completion_renderer.render(registers[name])});"
            )
        for field_index, name in enumerate(_FLAG_FIELDS):
            lines.append(
                f"    uint32_t completed_flag_{field_index} = "
                f"(uint32_t)({completion_renderer.render(flags[name])});"
            )
        outcome_setup, outcome_return = _render_outcome(
            completion.get("outcome"), completion_renderer
        )
        lines.extend(outcome_setup)
        for state_id, position in state_positions.items():
            lines.extend(
                _projection_write(
                    state_bindings[state_id].exit.payload,
                    f"component_context.state.{state_id}",
                    state="state",
                )
            )
        lines.append(
            "    if (memory_fault != 0U) return (spx_step_result)"
            "{ SPX_MEMORY_FAULT, 0U, 0U };"
        )
        lines.extend(
            f"    state->{name} = completed_register_{field_index};"
            for field_index, name in enumerate(_STATE_FIELDS)
        )
        lines.extend(
            f"    state->{name} = completed_flag_{field_index};"
            for field_index, name in enumerate(_FLAG_FIELDS)
        )
        lines.append(outcome_return)
        lines.append("  }")
    lines.extend(
        [
            "  return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def attach_service_bindings(
    model: Mapping[str, object],
    services: Sequence[object],
) -> dict[str, dict[tuple[str, int], object]]:
    """Return event-result projections indexed by logical service and site."""

    result: dict[str, dict[tuple[str, int], object]] = {}
    for raw in services:
        if isinstance(raw, Mapping):
            service_id = str(raw.get("service_id"))
            provider = raw.get("provider")
        else:
            service_id = str(getattr(raw, "service_id"))
            provider = getattr(raw, "provider")
        if not isinstance(provider, Mapping) or provider.get("kind") not in {
            "machine_events",
            "checked_external_site_events",
        }:
            continue
        events: dict[tuple[str, int], object] = {}
        for event in _rows(provider.get("events"), "machine service events"):
            key = (str(event["unit_id"]), int(event["event_index"]))
            events[key] = event.get("result")
        result[service_id] = events
    required = set(model.get("service_ids", []))
    if set(result) != required:
        raise SemanticPathError("runtime service binding inventory differs")
    return result


def _service_candidates(
    paths: Sequence[Mapping[str, object]],
) -> dict[str, tuple[Mapping[str, object], ...]]:
    grouped: dict[str, dict[str, Mapping[str, object]]] = {}
    authority: dict[tuple[str, str], str] = {}
    for path in paths:
        trace = _rows(path.get("trace"), "service trace")
        for position, event in enumerate(trace):
            row = {
                **json.loads(json.dumps(event)),
                "position": position,
                "prefix_service_ids": [
                    str(previous["service_id"]) for previous in trace[:position]
                ],
            }
            service_id = str(row["service_id"])
            condition_core = {
                "position": position,
                "service_id": service_id,
                "arguments": row.get("arguments"),
                "guards": row.get("guards"),
            }
            condition_id = canonical_sha256_v3(condition_core)
            event_id = canonical_sha256_v3(
                {
                    "unit_id": row.get("unit_id"),
                    "event_index": row.get("event_index"),
                    "event_sha256": row.get("event_sha256"),
                }
            )
            key = (service_id, condition_id)
            if key in authority and authority[key] != event_id:
                raise SemanticPathError(
                    "logical service dispatch is ambiguous under the portable path state"
                )
            authority[key] = event_id
            grouped.setdefault(service_id, {})[
                canonical_sha256_v3(row)
            ] = row
    return {
        service_id: tuple(rows[key] for key in sorted(rows))
        for service_id, rows in grouped.items()
    }


def _candidate_condition(
    candidate: Mapping[str, object],
    *,
    renderer: "_ExpressionRenderer",
    service_numbers: Mapping[str, int],
    parameter_positions: Mapping[str, int],
    service_parameter_type_ids: Sequence[str],
    type_index: Mapping[str, object],
) -> str:
    position = int(candidate["position"])
    conditions = [f"event_index == UINT32_C({position})"]
    trace_guards = _array(candidate.get("guards"), "service candidate guards")
    conditions.extend(renderer.render(value) for value in trace_guards)
    service_id = str(candidate["service_id"])
    prefix = _array(candidate.get("prefix_service_ids"), "service candidate prefix")
    if len(prefix) != position:
        raise SemanticPathError("runtime service candidate prefix is stale")
    for previous, previous_service in enumerate(prefix):
        if previous_service not in service_numbers:
            raise SemanticPathError("runtime service prefix is unknown")
        conditions.append(
            f"service_context->service_ids[{previous}] == "
            f"UINT32_C({service_numbers[str(previous_service)]})"
        )
    arguments = _array(candidate.get("arguments"), "service candidate arguments")
    if len(arguments) != len(service_parameter_type_ids):
        raise SemanticPathError("runtime service argument inventory differs")
    for index, expression in enumerate(
        arguments
    ):
        logical_type = type_index[service_parameter_type_ids[index]]
        if getattr(logical_type, "kind") == "bytes":
            expected = _object(expression, "runtime byte service argument")
            if expected.get("op") != "bytes_address":
                raise SemanticPathError(
                    "runtime byte service argument is not a byte-view origin"
                )
            name = str(expected.get("name"))
            if name not in parameter_positions:
                raise SemanticPathError(
                    "runtime byte service argument references an unknown parameter"
                )
            conditions.append(
                f"argument_{index} == service_context->byte_views["
                f"{parameter_positions[name]}]"
            )
        else:
            conditions.append(
                f"(uint64_t)argument_{index} == "
                f"(uint64_t)({renderer.render(expression)})"
            )
    if service_id not in service_numbers:
        raise SemanticPathError("runtime candidate references an unknown service")
    return " && ".join(f"({value})" for value in conditions)


def _render_machine_call(
    *,
    candidate: Mapping[str, object],
    renderer: "_ExpressionRenderer",
    service_number: int,
    argument_count: int,
    service_parameter_type_ids: Sequence[str],
    type_index: Mapping[str, object],
    parameter_positions: Mapping[str, int],
    result_projection: object,
    result_type: str,
) -> list[str]:
    event = _object(candidate.get("machine_event"), "runtime machine event")
    kind = event.get("kind")
    event_kind = {
        "external_call": "SPX_CALL_EXTERNAL_IMPORT",
        "indirect_call": "SPX_CALL_INDIRECT",
    }.get(kind)
    if event_kind is None:
        raise SemanticPathError(f"logical service event kind {kind!r} is not executable")
    lines = ["    spx_machine_state call_input = service_context->entry;"]
    for name, expression in _object(
        event.get("register_inputs"), "runtime call register inputs"
    ).items():
        if name not in _STATE_FIELDS:
            raise SemanticPathError("runtime call has an unsupported register input")
        lines.append(f"    call_input.{name} = (uint32_t)({renderer.render(expression)});")
    for name, expression in _object(
        event.get("flag_inputs"), "runtime call flag inputs"
    ).items():
        if name not in _FLAG_FIELDS:
            raise SemanticPathError("runtime call has an unsupported flag input")
        lines.append(f"    call_input.{name} = (uint32_t)({renderer.render(expression)});")
    arguments = _array(event.get("arguments"), "runtime call arguments")
    if arguments:
        lines.append(
            "    uint32_t call_arguments[] = { "
            + ", ".join(f"(uint32_t)({renderer.render(value)})" for value in arguments)
            + " };"
        )
    stack_inputs = _rows(event.get("stack_inputs"), "runtime call stack inputs")
    if stack_inputs:
        rendered = []
        for row in stack_inputs:
            rendered.append(
                "{ %dU, %dU, (uint32_t)(%s) }"
                % (
                    int(row["offset"]),
                    int(row["width"]),
                    renderer.render(row["value"]),
                )
            )
        lines.append("    spx_stack_input call_stack_inputs[] = { " + ", ".join(rendered) + " };")
    target = (
        renderer.render(event.get("target"))
        if event_kind == "SPX_CALL_INDIRECT"
        else f"UINT32_C({int(event.get('target_rva') or 0)})"
    )
    dll = _c_string(event.get("dll")) if isinstance(event.get("dll"), str) else "0"
    symbol = _c_string(event.get("symbol")) if isinstance(event.get("symbol"), str) else "0"
    ordinal = event.get("ordinal")
    has_ordinal = isinstance(ordinal, int) and not isinstance(ordinal, bool)
    event_position = int(candidate["event_index"])
    trace_position = int(candidate["position"])
    lines.extend(
        [
            "    spx_call_event call_event = {",
            f"      {event_kind}, UINT32_C({int(event.get('instruction_rva') or 0)}), UINT32_C({event_position}),",
            f"      (uint32_t)({target}), UINT32_C({int(event.get('return_rva') or 0)}),",
            f"      {dll}, {symbol}, UINT32_C({int(ordinal) if has_ordinal else 0}), UINT32_C({1 if has_ordinal else 0}),",
            f"      {'call_arguments' if arguments else '0'}, UINT32_C({len(arguments)}),",
            f"      {'call_stack_inputs' if stack_inputs else '0'}, UINT32_C({len(stack_inputs)})",
            "    };",
            "    if (memory_fault != 0U) {",
            "      service_context->fault = SPX_CALL_MEMORY_FAULT;",
            "      return;" if result_type == "void" else f"      return ({result_type})0;",
            "    }",
            f"    spx_machine_state *call_output = &service_context->call_outputs[{trace_position}];",
            "    *call_output = call_input;",
            "    service_context->fault = spx_invoke_call(service_context->runtime, &call_event, &call_input, call_output);",
            "    if (service_context->fault != SPX_CALL_OK) {",
        ]
    )
    lines.append("      return;" if result_type == "void" else f"      return ({result_type})0;")
    lines.extend(
        [
            "    }",
            f"    service_context->service_ids[event_index] = UINT32_C({service_number});",
            f"    service_context->argument_counts[event_index] = UINT32_C({argument_count});",
        ]
    )
    candidate_arguments = _array(
        candidate.get("arguments"), "runtime candidate arguments"
    )
    for index in range(argument_count):
        logical_type = type_index[service_parameter_type_ids[index]]
        if getattr(logical_type, "kind") == "bytes":
            expression = _object(
                candidate_arguments[index], "runtime byte candidate argument"
            )
            name = str(expression.get("name"))
            if expression.get("op") != "bytes_address" or name not in parameter_positions:
                raise SemanticPathError(
                    "runtime byte candidate argument has no byte-view origin"
                )
            lines.append(
                f"    service_context->arguments[event_index][{index}] = "
                f"service_context->parameters[{parameter_positions[name]}];"
            )
        else:
            lines.append(
                f"    service_context->arguments[event_index][{index}] = "
                f"(uint64_t)argument_{index};"
            )
    if result_type != "void":
        result = _result_projection_read(result_projection, output="call_output")
        lines.extend(
            [
                f"    {result_type} logical_service_result = ({result_type})({result});",
                "    service_context->logical_results[event_index] = (uint64_t)logical_service_result;",
                "    service_context->count = event_index + UINT32_C(1);",
                "    return logical_service_result;",
            ]
        )
    else:
        lines.extend(
            [
                "    service_context->logical_results[event_index] = UINT64_C(0);",
                "    service_context->count = event_index + UINT32_C(1);",
                "    return;",
            ]
        )
    return lines


def _completion_condition(
    path: Mapping[str, object],
    *,
    renderer: "_ExpressionRenderer",
    service_numbers: Mapping[str, int],
    operation: PortableOperationV2,
    type_index: Mapping[str, object],
) -> str:
    trace = _rows(path.get("trace"), "completion trace")
    conditions = [f"service_context.count == UINT32_C({len(trace)})"]
    conditions.extend(
        renderer.render(value) for value in _array(path.get("guards"), "completion guards")
    )
    path_results = _object(path.get("results"), "completion results")
    if set(path_results) != {result.identity for result in operation.results}:
        raise SemanticPathError("completion result inventory differs")
    for result in operation.results:
        observed = (
            "logical_result"
            if len(operation.results) == 1
            else f"logical_result.{result.identity}"
        )
        c_type = _logical_c_type(type_index[result.type_id])
        conditions.append(
            f"{observed} == ({c_type})({renderer.render(path_results[result.identity])})"
        )
    path_state = _object(path.get("state"), "completion state")
    for state_id, expected in sorted(path_state.items()):
        conditions.append(
            f"component_context.state.{state_id} == ({renderer.render(expected)})"
        )
    for position, event in enumerate(trace):
        service_id = str(event["service_id"])
        conditions.extend(
            [
                f"service_context.service_ids[{position}] == UINT32_C({service_numbers[service_id]})",
                f"service_context.argument_counts[{position}] == UINT32_C({len(_array(event.get('arguments'), 'completion arguments'))})",
            ]
        )
        conditions.extend(
            f"service_context.arguments[{position}][{index}] == (uint64_t)({renderer.render(value)})"
            for index, value in enumerate(
                _array(event.get("arguments"), "completion arguments")
            )
        )
    return " && ".join(f"({value})" for value in conditions)


def _render_outcome(
    value: object, renderer: "_ExpressionRenderer"
) -> tuple[list[str], str]:
    outcome = _object(value, "completion outcome")
    kind = outcome.get("kind")
    if kind == "return":
        target = renderer.render(outcome.get("value"))
        return (
            [f"    uint32_t completed_outcome = (uint32_t)({target});"],
            "    return (spx_step_result){ SPX_RETURN, 0U, completed_outcome };",
        )
    if kind == "fallthrough":
        target = int(outcome.get("target_rva") or 0)
        return (
            [],
            f"    return (spx_step_result){{ SPX_FALLTHROUGH, UINT32_C({target}), 0U }};",
        )
    if kind == "jump":
        target = int(outcome.get("target_rva") or 0)
        return (
            [],
            f"    return (spx_step_result){{ SPX_JUMP, UINT32_C({target}), 0U }};",
        )
    if kind == "indirect_jump":
        target = renderer.render(outcome.get("target"))
        return (
            [f"    uint32_t completed_outcome = (uint32_t)({target});"],
            "    return (spx_step_result){ SPX_INDIRECT_JUMP, 0U, completed_outcome };",
        )
    if kind == "branch":
        condition = renderer.render(outcome.get("condition"))
        true_target = int(outcome.get("true_target_rva") or 0)
        false_target = int(outcome.get("false_target_rva") or 0)
        return (
            [
                "    uint32_t completed_outcome = "
                f"({condition}) ? UINT32_C({true_target}) : "
                f"UINT32_C({false_target});"
            ],
            "    return (spx_step_result){ SPX_BRANCH, completed_outcome, 0U };",
        )
    raise SemanticPathError(f"finite runtime exit kind {kind!r} is unsupported")


class _ExpressionRenderer:
    def __init__(
        self,
        parameters: Mapping[str, int],
        *,
        state_positions: Mapping[str, int] | None = None,
        context: str,
    ) -> None:
        self.parameters = parameters
        self.state_positions = dict(state_positions or {})
        self.context = context

    def render(self, value: object) -> str:
        row = _object(value, "finite runtime expression")
        op = row.get("op")
        if op == "parameter":
            name = str(row.get("name"))
            if name not in self.parameters:
                raise SemanticPathError("runtime expression has an unknown parameter")
            return f"{self.context}.parameters[{self.parameters[name]}]"
        if op == "state_input":
            name = str(row.get("name"))
            if name not in self.state_positions:
                raise SemanticPathError("runtime expression has an unknown state input")
            return f"{self.context}.state_values[{self.state_positions[name]}]"
        if op == "symbol":
            name = str(row.get("name"))
            if not name.startswith("machine_"):
                raise SemanticPathError("runtime expression has an unknown entry symbol")
            field = name.removeprefix("machine_")
            if field not in {*_STATE_FIELDS, *_FLAG_FIELDS}:
                raise SemanticPathError("runtime expression has an unsupported entry field")
            return f"{self.context}.entry.{field}"
        if op == "service_result":
            return f"{self.context}.logical_results[{int(row['index'])}]"
        if op == "bytes_address":
            name = str(row.get("name"))
            if name not in self.parameters:
                raise SemanticPathError(
                    "runtime byte-view expression has an unknown parameter"
                )
            return f"{self.context}.parameters[{self.parameters[name]}]"
        if op == "service_machine_result":
            field = str(row.get("register"))
            if field not in _STATE_FIELDS:
                raise SemanticPathError("runtime service result register is invalid")
            return f"{self.context}.call_outputs[{int(row['index'])}].{field}"
        if op == "service_machine_flag":
            field = str(row.get("flag"))
            if field not in _FLAG_FIELDS:
                raise SemanticPathError("runtime service result flag is invalid")
            return f"{self.context}.call_outputs[{int(row['index'])}].{field}"
        if op == "const":
            return f"UINT32_C({int(row.get('value', 0)) & 0xFFFFFFFF})"
        if op == "true":
            return "UINT32_C(1)"
        if op == "false":
            return "UINT32_C(0)"
        if op == "load":
            return (
                f"component_read({self.context}.runtime, (uint32_t)({self.render(row.get('address'))}), "
                f"UINT32_C({int(row.get('width', 4))}), &memory_fault)"
            )
        args = _array(row.get("args"), f"runtime {op} arguments")
        rendered = [self.render(item) if isinstance(item, Mapping) else str(int(item)) for item in args]
        binary = {
            "add32": "+", "sub32": "-", "and32": "&", "or32": "|",
            "xor32": "^", "eq": "==", "ult32": "<",
        }
        if op in binary and len(rendered) == 2:
            return f"((uint32_t)({rendered[0]}) {binary[op]} (uint32_t)({rendered[1]}))"
        if op == "ite" and len(rendered) == 3:
            return f"(({rendered[0]}) ? ({rendered[1]}) : ({rendered[2]}))"
        if op == "not" and len(rendered) == 1:
            return f"(!({rendered[0]}))"
        if op == "msb" and len(rendered) == 2:
            return f"(((uint32_t)({rendered[1]}) >> ({rendered[0]} - 1U)) & 1U)"
        if op == "parity" and len(rendered) in {1, 2}:
            return f"component_parity((uint32_t)({rendered[-1]}))"
        if op == "sub_overflow" and len(rendered) == 4:
            return f"component_sub_overflow((uint32_t)({rendered[1]}), (uint32_t)({rendered[2]}), (uint32_t)({rendered[3]}))"
        if op == "add_overflow" and len(rendered) == 4:
            return f"component_add_overflow((uint32_t)({rendered[1]}), (uint32_t)({rendered[2]}), (uint32_t)({rendered[3]}))"
        raise SemanticPathError(f"runtime expression operation {op!r} is unsupported")


def _projection_read(value: Mapping[str, object], *, state: str) -> str:
    kind = value.get("kind")
    if kind == "register":
        return f"{state}->{value['register']}"
    if kind == "constant":
        return f"UINT32_C({int(value.get('value', 0)) & 0xFFFFFFFF})"
    if kind == "stack":
        return (
            f"component_read(rt, {state}->esp + UINT32_C({int(value.get('offset', 0)) & 0xFFFFFFFF}), "
            f"UINT32_C({int(value.get('width', 32)) // 8}), &memory_fault)"
        )
    if kind == "static_slot":
        return (
            f"component_read(rt, UINT32_C({int(value.get('rva', 0))}), "
            f"UINT32_C({int(value.get('width', 32)) // 8}), &memory_fault)"
        )
    if kind == "resource":
        return _projection_read(_object(value.get("source"), "resource source"), state=state)
    raise SemanticPathError(f"runtime parameter projection {kind!r} is unsupported")


def _projection_write(
    value: Mapping[str, object], expression: str, *, state: str
) -> list[str]:
    kind = value.get("kind")
    if kind == "register":
        field = str(value.get("register"))
        if field not in _STATE_FIELDS:
            raise SemanticPathError("runtime state projection register is invalid")
        return [f"    {state}->{field} = (uint32_t)({expression});"]
    if kind == "stack":
        return [
            f"    component_write(rt, {state}->esp + "
            f"UINT32_C({int(value.get('offset', 0)) & 0xFFFFFFFF}), "
            f"UINT32_C({int(value.get('width', 32)) // 8}), "
            f"(uint32_t)({expression}), &memory_fault);"
        ]
    if kind == "static_slot":
        return [
            f"    component_write(rt, UINT32_C({int(value.get('rva', 0))}), "
            f"UINT32_C({int(value.get('width', 32)) // 8}), "
            f"(uint32_t)({expression}), &memory_fault);"
        ]
    if kind == "resource":
        return _projection_write(
            _object(value.get("source"), "runtime resource projection"),
            expression,
            state=state,
        )
    raise SemanticPathError(f"runtime state projection {kind!r} is unsupported")


def _result_projection_read(value: object, *, output: str) -> str:
    row = _object(value, "runtime service result projection")
    kind = row.get("kind")
    if kind == "register":
        field = str(row.get("register"))
        if field not in _STATE_FIELDS:
            raise SemanticPathError("runtime service result register is invalid")
        return f"{output}->{field}"
    if kind == "resource":
        return _result_projection_read(row.get("source"), output=output)
    raise SemanticPathError(f"runtime service result projection {kind!r} is unsupported")


def _logical_c_type(value: object) -> str:
    kind = getattr(value, "kind")
    if kind == "resource":
        return "spx_resource_v2"
    c_type = getattr(value, "c_type")
    if kind in {"scalar", "enum"} and isinstance(c_type, str):
        return c_type
    if kind == "bytes":
        qualifier = "const " if getattr(value, "access") == "read" else ""
        return f"{qualifier}spx_bytes_view_v2 *"
    raise SemanticPathError(
        "finite runtime values must be scalar, enum, resource, or byte view"
    )


def _c_identifier(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticPathError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise SemanticPathError(f"{context} must be an array")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    rows = _array(value, context)
    if any(not isinstance(row, Mapping) for row in rows):
        raise SemanticPathError(f"{context} must contain objects")
    return list(rows)  # type: ignore[return-value]


__all__ = ["attach_service_bindings", "render_finite_path_operation"]
