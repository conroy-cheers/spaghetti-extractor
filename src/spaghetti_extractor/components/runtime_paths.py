"""Executable lowering of checked finite portable-component path models."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .atomics import ATOMIC_OBJECT_RESOURCE_KIND
from .boundary_plan import BoundaryOperationPlanV2
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
    boundary_plan: BoundaryOperationPlanV2 | None = None,
) -> str:
    """Render one source operation and its exact external-event protocol."""

    if boundary_plan is not None:
        clause_ids = {item.identity for item in boundary_plan.actions}
        expected_clause_ids = {
            f"parameter.{item.identity}" for item in operation.parameters
        } | {
            f"result.{item.identity}" for item in operation.results
        } | {
            f"state.{item.identity}" for item in interface.state
        } | {
            f"effect.{item.identity}" for item in binding.effects
        }
        if not expected_clause_ids <= clause_ids:
            raise SemanticPathError(
                "checked boundary plan does not cover the runtime operation boundary"
            )

    atomic_actions = _rows(model.get("atomic_actions", []), "atomic actions")
    if binding.callback_operation_ids:
        raise SemanticPathError(
            "finite runtime lowering requires operations without callbacks"
        )
    if bool(operation.effect_ids or binding.effects) != bool(atomic_actions) or {
        row.effect_id for row in binding.effects
    } != set(operation.effect_ids):
        raise SemanticPathError(
            "finite runtime direct effects require an exact atomic world model"
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
    view_parameters = [
        value
        for value in operation.parameters
        if type_index[value.type_id].kind == "view"
    ]
    callback_types = [
        logical_type
        for logical_type in interface.types
        if logical_type.kind == "callback"
    ]
    state_positions = {
        value.identity: index for index, value in enumerate(interface.state)
    }
    state_bindings = (
        _plan_state_bindings(boundary_plan)
        if boundary_plan is not None
        else {
            value.identity: {
                "entry": value.entry.payload,
                "exit": value.exit.payload,
            }
            for value in binding.state
        }
    )
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

    lines: list[str] = []
    for logical_type in callback_types:
        callback_name = f"spx_callback_{logical_type.identity}_v2"
        type_tag = int(canonical_sha256_v3({
            "component": interface.identity,
            "callback_type": logical_type.identity,
        })[:8], 16)
        lines.extend([
            f"struct {callback_name} {{",
            "  spx_capability_core capability;",
            "  uint32_t machine_word;",
            "};",
            f"static void {prefix}_{logical_type.identity}_bind(",
            f"    {callback_name} *handle, uint32_t machine_word, uint64_t generation) {{",
            "  if (handle == 0) return;",
            f"  spx_capability_bind(&handle->capability, UINT32_C({type_tag}), "
            "UINT32_C(2), machine_word, generation);",
            "  handle->machine_word = machine_word;",
            "}",
            f"static uint32_t {prefix}_{logical_type.identity}_word(",
            f"    {callback_name} *handle) {{",
            "  spx_capability_status status;",
            "  if (handle == 0) return UINT32_C(0);",
            "  status = spx_capability_begin(",
            f"      &handle->capability, UINT32_C({type_tag}), handle->capability.generation);",
            "  if (status != SPX_CAPABILITY_OK) return UINT32_C(0);",
            "  spx_capability_finish(&handle->capability, SPX_CAPABILITY_OK);",
            "  return handle->machine_word;",
            "}",
            "",
        ])
    lines.extend([
        f"typedef struct {prefix}_service_context {{",
        "  spx_runtime *runtime;",
        "  spx_machine_state entry;",
        f"  spx_machine_state call_outputs[{max_events}];",
        f"  uint64_t parameters[{max(1, len(operation.parameters))}];",
        f"  uint32_t atomic_observed[{max(1, len(operation.parameters))}];",
        f"  const spx_bytes_view_v2 *byte_views[{max(1, len(operation.parameters))}];",
        f"  uint64_t state_values[{max(1, len(interface.state))}];",
        f"  uint64_t logical_results[{max_events}];",
        *[
            f"  spx_callback_{logical_type.identity}_v2 "
            f"callback_{logical_type.identity}_results[{max_events}];"
            for logical_type in callback_types
        ],
        f"  uint32_t service_ids[{max_events}];",
        f"  uint32_t argument_counts[{max_events}];",
        f"  uint64_t arguments[{max_events}][{max_arguments}];",
        "  uint32_t count;",
        "  spx_call_status fault;",
        f"}} {prefix}_service_context;",
        "",
    ])
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
    if view_parameters:
        lines.extend(
            [
                f"static uint32_t {prefix}_view_read(",
                "    void *opaque, spx_ref_v1 base, uint64_t byte_offset,",
                "    uint32_t width, uint64_t *result) {",
                "  spx_runtime *rt = (spx_runtime *)opaque;",
                "  spx_ref_v1 derived;",
                "  spx_machine_reference_v1 machine;",
                "  uint32_t address = UINT32_C(0), fault = UINT32_C(0);",
                "  if (result == 0 || width == 0U || width > 4U || base.offset > base.extent ||",
                "      byte_offset > base.extent - base.offset ||",
                "      (uint64_t)width > base.extent - base.offset - byte_offset ||",
                "      spx_ref_derive(base, byte_offset, 0U, &derived) != SPX_REF_OK)",
                "    return UINT32_C(1);",
                "  machine = (spx_machine_reference_v1){",
                "    derived.domain, derived.object, derived.generation, derived.offset,",
                "    derived.extent, derived.permissions",
                "  };",
                "  if (rt == 0 || rt->realize_reference == 0 ||",
                "      rt->realize_reference(rt->context, &machine, UINT32_C(1),",
                "          UINT32_C(0), UINT32_C(0), &address) != SPX_BOUNDARY_OK)",
                "    return UINT32_C(1);",
                "  *result = component_read(rt, address, width, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                f"static uint32_t {prefix}_view_write(",
                "    void *opaque, spx_ref_v1 base, uint64_t byte_offset,",
                "    uint32_t width, uint64_t value) {",
                "  spx_runtime *rt = (spx_runtime *)opaque;",
                "  spx_ref_v1 derived;",
                "  spx_machine_reference_v1 machine;",
                "  uint32_t address = UINT32_C(0), fault = UINT32_C(0);",
                "  if (width == 0U || width > 4U || base.offset > base.extent ||",
                "      byte_offset > base.extent - base.offset ||",
                "      (uint64_t)width > base.extent - base.offset - byte_offset ||",
                "      spx_ref_derive(base, byte_offset, 0U, &derived) != SPX_REF_OK)",
                "    return UINT32_C(1);",
                "  machine = (spx_machine_reference_v1){",
                "    derived.domain, derived.object, derived.generation, derived.offset,",
                "    derived.extent, derived.permissions",
                "  };",
                "  if (rt == 0 || rt->realize_reference == 0 ||",
                "      rt->realize_reference(rt->context, &machine, UINT32_C(2),",
                "          UINT32_C(0), UINT32_C(0), &address) != SPX_BOUNDARY_OK)",
                "    return UINT32_C(1);",
                "  component_write(rt, address, width, (uint32_t)value, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
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
        result_logical_type = (
            None if service.result_type_id is None else type_index[service.result_type_id]
        )
        failure_return = _service_failure_return(result_type, result_logical_type)
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
        lines.append(f"    {failure_return}")
        lines.append("  }")
        for index, type_id in enumerate(service.parameter_type_ids):
            argument_type = type_index[type_id]
            if getattr(argument_type, "kind") not in {"reference", "view"}:
                continue
            reference = (
                f"argument_{index}"
                if getattr(argument_type, "kind") == "reference"
                else f"argument_{index}->base"
            )
            permissions, nullable, allow_one_past = _origin_policy(argument_type)
            lines.extend(
                [
                    f"  spx_machine_reference_v1 argument_{index}_machine = {{",
                    f"    {reference}.domain, {reference}.object, {reference}.generation,",
                    f"    {reference}.offset, {reference}.extent, {reference}.permissions",
                    "  };",
                    f"  uint32_t argument_{index}_word = UINT32_C(0);",
                    "  if (service_context->runtime == 0 ||",
                    "      service_context->runtime->realize_reference == 0 ||",
                    f"      service_context->runtime->realize_reference(service_context->runtime->context, &argument_{index}_machine,",
                    f"          UINT32_C({permissions}), UINT32_C({nullable}), UINT32_C({allow_one_past}),",
                    f"          &argument_{index}_word) != SPX_BOUNDARY_OK) {{",
                    "    service_context->fault = SPX_CALL_MEMORY_FAULT;",
                    f"    {failure_return}",
                    "  }",
                ]
            )
        for candidate_index, candidate in enumerate(candidates.get(service.identity, ())):
            condition = _candidate_condition(
                candidate,
                renderer=renderer,
                service_numbers=service_numbers,
                parameter_positions=parameter_positions,
                service_parameter_type_ids=service.parameter_type_ids,
                type_index=type_index,
                prefix=prefix,
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
                    service_result_type_id=service.result_type_id,
                    prefix=prefix,
                )
            )
            lines.append("  }")
        lines.extend(
            [
                "  service_context->fault = SPX_CALL_UNIMPLEMENTED;",
                f"  {failure_return}",
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
        logical_type = type_index[
            next(row.type_id for row in interface.state if row.identity == state_id)
        ]
        state_type = _logical_c_type(logical_type)
        projection = state_bindings[state_id]["entry"]
        if getattr(logical_type, "kind") == "reference":
            lines.extend(
                _origin_import_lines(
                    logical_type=logical_type,
                    projection=projection,
                    name=f"logical_state_{position}",
                    state="state",
                    c_type="spx_ref_v1",
                    type_index=type_index,
                    prefix=prefix,
                )
            )
            lines.extend(
                [
                    f"  component_context.state.{state_id} = logical_state_{position};",
                    f"  service_context.state_values[{position}] = "
                    f"(uint64_t)logical_state_{position}_word;",
                ]
            )
        else:
            lines.extend(
                [
                    f"  {state_type} logical_state_{position} = ({state_type})"
                    f"({_projection_read(projection, state='state')});",
                    f"  component_context.state.{state_id} = logical_state_{position};",
                    f"  service_context.state_values[{position}] = "
                    f"(uint64_t)logical_state_{position};",
                ]
            )
    parameter_bindings = (
        _plan_parameter_bindings(boundary_plan)
        if boundary_plan is not None
        else {value.identity: value.projection.payload for value in binding.parameters}
    )
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
        if (
            logical_type.kind == "resource"
            and logical_type.resource_kind == ATOMIC_OBJECT_RESOURCE_KIND
        ):
            payload = projected
            if payload.get("kind") != "atomic_object":
                raise SemanticPathError(
                    "runtime atomic parameter requires an atomic-object projection"
                )
            source = _object(payload.get("source"), "runtime atomic source")
            if source.get("kind") != "constant":
                raise SemanticPathError(
                    "runtime atomic object currently requires a proved constant address"
                )
            lines.extend(
                [
                    f"  spx_atomic_object argument_{index}_object;",
                    f"  spx_atomic_object_bind(&argument_{index}_object, rt, "
                    f"UINT32_C({int(source.get('value', 0))}), "
                    f"UINT32_C({int(payload.get('width', 0))}));",
                    f"  spx_atomic_object *argument_{index} = &argument_{index}_object;",
                    f"  service_context.parameters[{index}] = UINT64_C(0);",
                ]
            )
            arguments_by_id[logical.identity] = f"argument_{index}"
            continue
        if logical_type.kind == "callback":
            payload = projected
            if payload.get("kind") != "callback_handle":
                raise SemanticPathError(
                    "runtime callback parameter requires a callback-handle projection"
                )
            word = _projection_read(
                _object(payload.get("source"), "runtime callback source"),
                state="state",
            )
            callback_name = f"spx_callback_{logical_type.identity}_v2"
            lines.extend([
                f"  uint32_t argument_{index}_word = (uint32_t)({word});",
                f"  {callback_name} argument_{index}_object;",
                f"  {prefix}_{logical_type.identity}_bind(&argument_{index}_object, "
                f"argument_{index}_word, UINT64_C(1));",
                f"  {callback_name} *argument_{index} = "
                f"argument_{index}_word == UINT32_C(0) ? 0 : &argument_{index}_object;",
                f"  service_context.parameters[{index}] = (uint64_t)argument_{index}_word;",
            ])
            arguments_by_id[logical.identity] = f"argument_{index}"
            continue
        if logical_type.kind in {"reference", "view"}:
            lines.extend(
                _origin_import_lines(
                    logical_type=logical_type,
                    projection=projected,
                    name=f"argument_{index}",
                    state="state",
                    c_type=c_type,
                    type_index=type_index,
                    prefix=prefix,
                )
            )
            lines.append(
                f"  service_context.parameters[{index}] = "
                f"(uint64_t)argument_{index}_word;"
            )
            arguments_by_id[logical.identity] = f"argument_{index}"
            continue
        value = _projection_read(projected, state="state")
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
        projected = parameter_bindings[logical.identity]
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
    origin_result_words: dict[str, str] = {}
    for result in operation.results:
        logical_type = type_index[result.type_id]
        if getattr(logical_type, "kind") not in {"reference", "view"}:
            continue
        observed = (
            "logical_result"
            if len(operation.results) == 1
            else f"logical_result.{result.identity}"
        )
        reference = observed if getattr(logical_type, "kind") == "reference" else f"{observed}.base"
        word_name = f"logical_result_{_c_identifier(result.identity)}_word"
        lines.extend(
            _origin_realize_lines(
                logical_type=logical_type,
                reference=reference,
                word_name=word_name,
            )
        )
        origin_result_words[result.identity] = word_name
    for action in atomic_actions:
        parameter_id = str(action.get("parameter_id"))
        if parameter_id not in parameter_positions:
            raise SemanticPathError("runtime atomic model references an unknown parameter")
        index = parameter_positions[parameter_id]
        lines.extend(
            [
                f"  if (spx_atomic_object_call_count(&argument_{index}_object) != UINT32_C(1)) ",
                "    return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
                f"  if (spx_atomic_object_status(&argument_{index}_object) == SPX_ATOMIC_FAULT) ",
                "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
                f"  if (spx_atomic_object_status(&argument_{index}_object) != SPX_ATOMIC_OK) ",
                "    return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
                f"  service_context.atomic_observed[{index}] = "
                f"spx_atomic_object_observation(&argument_{index}_object)->observed;",
            ]
        )
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
    origin_state_words: dict[str, str] = {}
    for state_id in state_positions:
        logical_type = type_index[
            next(row.type_id for row in interface.state if row.identity == state_id)
        ]
        if getattr(logical_type, "kind") != "reference":
            continue
        word_name = f"logical_state_{_c_identifier(state_id)}_word"
        lines.extend(
            _origin_realize_lines(
                logical_type=logical_type,
                reference=f"component_context.state.{state_id}",
                word_name=word_name,
            )
        )
        origin_state_words[state_id] = word_name
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
            prefix=prefix,
            origin_result_words=origin_result_words,
            origin_state_words=origin_state_words,
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
            state_expression = origin_state_words.get(
                state_id, f"component_context.state.{state_id}"
            )
            lines.extend(
                _projection_write(
                    state_bindings[state_id]["exit"],
                    state_expression,
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


def _plan_parameter_bindings(
    plan: BoundaryOperationPlanV2,
) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for action in plan.actions:
        clause = _object(action.clause, "boundary parameter action")
        path = clause.get("logical_path")
        if not isinstance(path, Mapping) or path.get("root") != "parameter":
            continue
        observe = _object(clause.get("observe"), "boundary parameter observer")
        result[str(path.get("id"))] = _observer_projection(observe)
    return result


def _plan_state_bindings(
    plan: BoundaryOperationPlanV2,
) -> dict[str, dict[str, Mapping[str, object]]]:
    result: dict[str, dict[str, Mapping[str, object]]] = {}
    for action in plan.actions:
        clause = _object(action.clause, "boundary state action")
        path = clause.get("logical_path")
        if not isinstance(path, Mapping) or path.get("root") != "state":
            continue
        observe = _object(clause.get("observe"), "boundary state observer")
        realizers = _rows(clause.get("realize"), "boundary state realizers")
        entry = _observer_projection(observe)
        result[str(path.get("id"))] = {
            "entry": entry,
            "exit": _realizer_projection(entry, realizers),
        }
    return result


def _observer_projection(
    expression: Mapping[str, object],
) -> Mapping[str, object]:
    if expression.get("op") == "machine":
        attributes = _object(expression.get("attributes"), "boundary observer attributes")
        place = _object(attributes.get("place"), "boundary observer place")
        return _object(place.get("selector"), "boundary observer selector")
    if expression.get("op") == "authority_call":
        attributes = _object(expression.get("attributes"), "authority observer attributes")
        primitive = attributes.get("primitive")
        if primitive == "origin.resolve":
            return _origin_observer_projection(expression, kind="reference")
        if primitive == "capability.import":
            args = _array(expression.get("args"), "capability observer arguments")
            sort = _object(expression.get("sort"), "capability observer sort")
            if not args or sort.get("kind") not in {"resource", "callback"}:
                raise SemanticPathError("capability observer shape is invalid")
            source = _expression_projection(args[0], "capability machine word")
            if sort.get("kind") == "callback":
                return {
                    "kind": "callback_handle",
                    "protocol_id": str(sort.get("type_id")),
                    "authority_id": str(attributes.get("binding")),
                    "source": source,
                }
            return {
                "kind": "resource",
                "resource_kind": str(attributes.get("binding")),
                "source": source,
            }
    if expression.get("op") == "make_view":
        args = _array(expression.get("args"), "boundary view observer arguments")
        if len(args) != 2 or not all(isinstance(item, Mapping) for item in args):
            raise SemanticPathError("boundary view observer shape is invalid")
        result = dict(_origin_observer_projection(args[0], kind="view"))
        extent_expression = _object(args[1], "view extent")
        if extent_expression.get("op") == "ref_remaining":
            extent_args = _array(
                extent_expression.get("args"), "view origin-remainder arguments"
            )
            if len(extent_args) != 1 or extent_args[0] != args[0]:
                raise SemanticPathError(
                    "view origin remainder must be derived from its resolved base"
                )
            result["extent"] = {"kind": "origin_remainder"}
        else:
            result["extent"] = _expression_projection(extent_expression, "view extent")
        return result
    raise SemanticPathError(
        "runtime lowering requires a registered executable boundary observer"
    )


def _origin_observer_projection(
    expression: Mapping[str, object], *, kind: str
) -> Mapping[str, object]:
    attributes = _object(expression.get("attributes"), "origin observer attributes")
    if expression.get("op") != "authority_call" or attributes.get("primitive") != "origin.resolve":
        raise SemanticPathError("origin observer does not use origin.resolve")
    args = _array(expression.get("args"), "origin observer arguments")
    if len(args) != 2 or not all(isinstance(item, Mapping) for item in args):
        raise SemanticPathError("origin observer shape is invalid")
    return {
        "kind": kind,
        "source" if kind == "reference" else "base": _expression_projection(
            args[0], "origin address"
        ),
        "requested_extent": _expression_projection(args[1], "origin requested extent"),
        "authority_id": str(attributes.get("binding")),
    }


def _expression_projection(
    expression: object, context: str
) -> Mapping[str, object]:
    row = _object(expression, context)
    if row.get("op") == "machine":
        attributes = _object(row.get("attributes"), f"{context} attributes")
        place = _object(attributes.get("place"), f"{context} place")
        return _object(place.get("selector"), f"{context} selector")
    if row.get("op") == "const":
        attributes = _object(row.get("attributes"), f"{context} attributes")
        sort = _object(row.get("sort"), f"{context} sort")
        return {
            "kind": "constant",
            "value": int(attributes.get("value", 0)),
            "width": int(sort.get("width", 32)),
        }
    raise SemanticPathError(f"{context} is not directly executable")


def _realizer_projection(
    observer: Mapping[str, object],
    realizers: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    kind = observer.get("kind")
    if kind in {"resource", "callback_handle"}:
        if len(realizers) != 1:
            raise SemanticPathError("capability binding requires one realization")
        value = _object(realizers[0].get("value"), "capability realization value")
        attributes = _object(value.get("attributes"), "capability realization attributes")
        if value.get("op") != "authority_call" or attributes.get("primitive") != "capability.export":
            raise SemanticPathError("capability realization does not use capability.export")
        place = _object(realizers[0].get("place"), "capability realization place")
        result = dict(observer)
        result["source"] = _object(place.get("selector"), "capability realization selector")
        return result
    if kind not in {"reference", "view"}:
        if len(realizers) != 1:
            raise SemanticPathError("runtime scalar binding requires one realization")
        place = _object(realizers[0].get("place"), "boundary realization place")
        return _object(place.get("selector"), "boundary realization selector")
    result = dict(observer)
    address_field = "source" if kind == "reference" else "base"
    address_rows = []
    extent_rows = []
    for realizer in realizers:
        value = _object(realizer.get("value"), "boundary realization value")
        if value.get("op") == "authority_call" and _object(
            value.get("attributes"), "origin realizer attributes"
        ).get("primitive") == "origin.address":
            address_rows.append(realizer)
        elif value.get("op") == "view_extent":
            extent_rows.append(realizer)
    if len(address_rows) != 1 or (kind == "view" and len(extent_rows) != 1):
        raise SemanticPathError("origin realization inventory is invalid")
    address_place = _object(address_rows[0].get("place"), "origin realization place")
    result[address_field] = _object(address_place.get("selector"), "origin realization selector")
    if kind == "view":
        extent_place = _object(extent_rows[0].get("place"), "view extent realization place")
        result["extent"] = _object(extent_place.get("selector"), "view extent realization selector")
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
    prefix: str,
) -> str:
    position = int(candidate["position"])
    conditions = [f"event_index == UINT32_C({position})"]
    trace_guards = _array(candidate.get("guards"), "service candidate guards")
    conditions.extend(renderer.render(value) for value in trace_guards)
    service_id = str(candidate["service_id"])
    service_prefix = _array(
        candidate.get("prefix_service_ids"), "service candidate prefix"
    )
    if len(service_prefix) != position:
        raise SemanticPathError("runtime service candidate prefix is stale")
    for previous, previous_service in enumerate(service_prefix):
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
        elif getattr(logical_type, "kind") == "callback":
            conditions.append(
                f"(uint64_t){prefix}_{getattr(logical_type, 'identity')}_word(argument_{index}) == "
                f"(uint64_t)({renderer.render(expression)})"
            )
        elif getattr(logical_type, "kind") in {"reference", "view"}:
            conditions.append(
                f"(uint64_t)argument_{index}_word == "
                f"(uint64_t)({renderer.render(expression)})"
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
    service_result_type_id: str | None,
    prefix: str,
) -> list[str]:
    event = _object(candidate.get("machine_event"), "runtime machine event")
    kind = event.get("kind")
    event_kind = {
        "external_call": "SPX_CALL_EXTERNAL_IMPORT",
        "indirect_call": "SPX_CALL_INDIRECT",
        "component_call": "SPX_CALL_INTERNAL_DIRECT",
        "internal_call": "SPX_CALL_INTERNAL_DIRECT",
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
            f"      {_service_failure_return(result_type, None if service_result_type_id is None else type_index[service_result_type_id])}",
            "    }",
            f"    spx_machine_state *call_output = &service_context->call_outputs[{trace_position}];",
            "    *call_output = call_input;",
            "    service_context->fault = spx_invoke_call(service_context->runtime, &call_event, &call_input, call_output);",
            "    if (service_context->fault != SPX_CALL_OK) {",
        ]
    )
    lines.append(
        "      " + _service_failure_return(
            result_type,
            None if service_result_type_id is None else type_index[service_result_type_id],
        )
    )
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
        elif getattr(logical_type, "kind") == "callback":
            lines.append(
                f"    service_context->arguments[event_index][{index}] = "
                f"(uint64_t){prefix}_{getattr(logical_type, 'identity')}_word(argument_{index});"
            )
        elif getattr(logical_type, "kind") in {"reference", "view"}:
            lines.append(
                f"    service_context->arguments[event_index][{index}] = "
                f"(uint64_t)argument_{index}_word;"
            )
        else:
            lines.append(
                f"    service_context->arguments[event_index][{index}] = "
                f"(uint64_t)argument_{index};"
            )
    if result_type != "void":
        result = _result_projection_read(result_projection, output="call_output")
        result_logical_type = (
            None
            if service_result_type_id is None
            else type_index[service_result_type_id]
        )
        if result_logical_type is not None and getattr(result_logical_type, "kind") == "callback":
            identity = getattr(result_logical_type, "identity")
            nullable = bool(getattr(result_logical_type, "nullable"))
            lines.extend([
                f"    uint32_t logical_service_word = (uint32_t)({result});",
                f"    spx_callback_{identity}_v2 *logical_service_result = 0;",
                *(
                    ["    if (logical_service_word != UINT32_C(0)) {"]
                    if nullable
                    else ["    {"]
                ),
                f"      logical_service_result = &service_context->callback_{identity}_results[event_index];",
                f"      {prefix}_{identity}_bind(logical_service_result, logical_service_word, "
                "(uint64_t)event_index + UINT64_C(1));",
                "    }",
                "    service_context->logical_results[event_index] = (uint64_t)logical_service_word;",
                "    service_context->count = event_index + UINT32_C(1);",
                "    return logical_service_result;",
            ])
            return lines
        if result_logical_type is not None and getattr(result_logical_type, "kind") == "reference":
            permissions, nullable, allow_one_past = _origin_policy(result_logical_type)
            requested_projection = _object(
                _object(result_projection, "reference service result").get("requested_extent"),
                "reference service result requested extent",
            )
            requested = _result_projection_read(requested_projection, output="call_output")
            lines.extend(
                [
                    f"    uint32_t logical_service_word = (uint32_t)({result});",
                    "    spx_machine_reference_v1 logical_service_machine = {0};",
                    "    if (service_context->runtime == 0 ||",
                    "        service_context->runtime->resolve_reference == 0 ||",
                    "        service_context->runtime->resolve_reference(",
                    "            service_context->runtime->context, logical_service_word,",
                    f"            (uint32_t)({requested}), UINT32_C({permissions}),",
                    f"            UINT32_C({nullable}), UINT32_C({allow_one_past}),",
                    "            &logical_service_machine) != SPX_BOUNDARY_OK) {",
                    "      service_context->fault = SPX_CALL_MEMORY_FAULT;",
                    "      return (spx_ref_v1){0};",
                    "    }",
                    "    spx_ref_v1 logical_service_result = {",
                    "      logical_service_machine.domain, logical_service_machine.object,",
                    "      logical_service_machine.generation, logical_service_machine.offset,",
                    "      logical_service_machine.extent, logical_service_machine.permissions",
                    "    };",
                    "    service_context->logical_results[event_index] = (uint64_t)logical_service_word;",
                    "    service_context->count = event_index + UINT32_C(1);",
                    "    return logical_service_result;",
                ]
            )
            return lines
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
    prefix: str,
    origin_result_words: Mapping[str, str],
    origin_state_words: Mapping[str, str],
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
        logical_type = type_index[result.type_id]
        if result.identity in origin_result_words:
            conditions.append(
                f"{origin_result_words[result.identity]} == "
                f"(uint32_t)({renderer.render(path_results[result.identity])})"
            )
        elif getattr(logical_type, "kind") == "callback":
            conditions.append(
                f"{prefix}_{getattr(logical_type, 'identity')}_word({observed}) == "
                f"(uint32_t)({renderer.render(path_results[result.identity])})"
            )
        else:
            conditions.append(
                f"{observed} == ({c_type})({renderer.render(path_results[result.identity])})"
            )
    path_state = _object(path.get("state"), "completion state")
    for state_id, expected in sorted(path_state.items()):
        observed_state = origin_state_words.get(
            state_id, f"component_context.state.{state_id}"
        )
        conditions.append(
            f"{observed_state} == ({renderer.render(expected)})"
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
        if op == "atomic_observed":
            name = str(row.get("name"))
            if name not in self.parameters:
                raise SemanticPathError(
                    "runtime atomic observation has an unknown parameter"
                )
            return f"{self.context}.atomic_observed[{self.parameters[name]}]"
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
    if kind == "callback_handle":
        return _projection_read(
            _object(value.get("source"), "callback-handle source"), state=state
        )
    if kind == "reference":
        return _projection_read(
            _object(value.get("source"), "reference source"), state=state
        )
    if kind == "view":
        return _projection_read(
            _object(value.get("base"), "view base"), state=state
        )
    raise SemanticPathError(f"runtime parameter projection {kind!r} is unsupported")


def _origin_import_lines(
    *,
    logical_type: object,
    projection: Mapping[str, object],
    name: str,
    state: str,
    c_type: str,
    type_index: Mapping[str, object],
    prefix: str,
) -> list[str]:
    kind = getattr(logical_type, "kind")
    if projection.get("kind") != kind or kind not in {"reference", "view"}:
        raise SemanticPathError("origin import projection kind differs")
    address_field = "source" if kind == "reference" else "base"
    address = _projection_read(
        _object(projection.get(address_field), "origin address projection"),
        state=state,
    )
    requested_extent = _projection_read(
        _object(
            projection.get("requested_extent"),
            "origin requested-extent projection",
        ),
        state=state,
    )
    permissions, nullable, allow_one_past = _origin_policy(logical_type)
    lines = [
        f"  uint32_t {name}_word = (uint32_t)({address});",
        f"  spx_machine_reference_v1 {name}_machine = {{0}};",
        f"  if (rt->resolve_reference == 0 || rt->resolve_reference(",
        f"      rt->context, {name}_word, (uint32_t)({requested_extent}),",
        f"      UINT32_C({permissions}), UINT32_C({nullable}), "
        f"UINT32_C({allow_one_past}), &{name}_machine) != SPX_BOUNDARY_OK)",
        "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
        f"  spx_ref_v1 {name}_reference = {{",
        f"    {name}_machine.domain, {name}_machine.object,",
        f"    {name}_machine.generation, {name}_machine.offset,",
        f"    {name}_machine.extent, {name}_machine.permissions",
        "  };",
    ]
    if kind == "reference":
        lines.append(f"  {c_type} {name} = {name}_reference;")
        return lines
    extent_projection = _object(projection.get("extent"), "view extent projection")
    extent = (
        f"({name}_reference.extent - {name}_reference.offset)"
        if extent_projection.get("kind") == "origin_remainder"
        else _projection_read(extent_projection, state=state)
    )
    element_width = _logical_element_width(logical_type, type_index)
    qualifier = "const " if str(c_type).startswith("const ") else ""
    access = str(getattr(logical_type, "access"))
    reader = "0" if access == "write" else f"{prefix}_view_read"
    writer = "0" if access == "read" else f"{prefix}_view_write"
    lines.extend(
        [
            f"  spx_view_v1 {name}_view = "
            f"{{{name}_reference, (uint64_t)({extent}), UINT32_C({element_width}), "
            f"rt, {reader}, {writer}}};",
            f"  {qualifier}spx_view_v1 *{name} = &{name}_view;",
        ]
    )
    return lines


def _origin_policy(logical_type: object) -> tuple[int, int, int]:
    permissions = {"read": 1, "write": 2, "read_write": 3}.get(
        str(getattr(logical_type, "access"))
    )
    if permissions is None:
        raise SemanticPathError("origin access policy is unsupported")
    return (
        permissions,
        int(bool(getattr(logical_type, "nullable", False))),
        int(bool(getattr(logical_type, "allow_one_past", False))),
    )


def _origin_realize_lines(
    *, logical_type: object, reference: str, word_name: str
) -> list[str]:
    permissions, nullable, allow_one_past = _origin_policy(logical_type)
    machine_name = f"{word_name}_reference"
    return [
        f"  spx_machine_reference_v1 {machine_name} = {{",
        f"    {reference}.domain, {reference}.object, {reference}.generation,",
        f"    {reference}.offset, {reference}.extent, {reference}.permissions",
        "  };",
        f"  uint32_t {word_name} = UINT32_C(0);",
        f"  if (rt->realize_reference == 0 || rt->realize_reference(",
        f"      rt->context, &{machine_name}, UINT32_C({permissions}),",
        f"      UINT32_C({nullable}), UINT32_C({allow_one_past}), &{word_name}) "
        "!= SPX_BOUNDARY_OK)",
        "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
    ]


def _logical_element_width(
    logical_type: object, type_index: Mapping[str, object]
) -> int:
    element_id = getattr(logical_type, "element_type_id", None)
    element = type_index.get(str(element_id))
    c_type = None if element is None else getattr(element, "c_type", None)
    if not isinstance(c_type, str):
        raise SemanticPathError("view element type has no concrete scalar width")
    bits = int(c_type.removeprefix("uint").removeprefix("int").removesuffix("_t"))
    if bits % 8 != 0:
        raise SemanticPathError("view element width is not byte aligned")
    return bits // 8


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
    if kind == "callback_handle":
        return _projection_write(
            _object(value.get("source"), "runtime callback-handle projection"),
            expression,
            state=state,
        )
    if kind == "reference":
        return _projection_write(
            _object(value.get("source"), "runtime reference source"),
            expression,
            state=state,
        )
    if kind == "view":
        return _projection_write(
            _object(value.get("base"), "runtime view base"),
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
    if kind == "constant":
        return f"UINT32_C({int(row.get('value', 0)) & 0xFFFFFFFF})"
    if kind == "resource":
        return _result_projection_read(row.get("source"), output=output)
    if kind == "callback_handle":
        return _result_projection_read(row.get("source"), output=output)
    if kind == "reference":
        return _result_projection_read(row.get("source"), output=output)
    raise SemanticPathError(f"runtime service result projection {kind!r} is unsupported")


def _logical_c_type(value: object) -> str:
    kind = getattr(value, "kind")
    if kind == "resource":
        if getattr(value, "resource_kind") == ATOMIC_OBJECT_RESOURCE_KIND:
            return "spx_atomic_object *"
        return "spx_resource_v2"
    c_type = getattr(value, "c_type")
    if kind in {"scalar", "enum"} and isinstance(c_type, str):
        return c_type
    if kind == "bytes":
        qualifier = "const " if getattr(value, "access") == "read" else ""
        return f"{qualifier}spx_bytes_view_v2 *"
    if kind == "callback":
        return f"spx_callback_{getattr(value, 'identity')}_v2 *"
    if kind == "reference":
        return "spx_ref_v1"
    if kind == "view":
        qualifier = "const " if getattr(value, "access") == "read" else ""
        return f"{qualifier}spx_view_v1 *"
    raise SemanticPathError(
        "finite runtime value kind is unsupported"
    )


def _service_failure_return(result_type: str, logical_type: object | None) -> str:
    if result_type == "void":
        return "return;"
    if logical_type is not None and getattr(logical_type, "kind") == "reference":
        return "return (spx_ref_v1){0};"
    if logical_type is not None and getattr(logical_type, "kind") == "view":
        return "return (spx_view_v1){0};"
    return f"return ({result_type})0;"


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
