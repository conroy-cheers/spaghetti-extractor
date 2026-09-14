"""Checked external-service C rendering for V5 component overlays."""

from __future__ import annotations

from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import BoundaryModelError, array, object_
from ..transfer.values import _c_string
from .component_c_v5 import _parameter_type, _result_type
from .machine_overlay_result_views import result_view_lines
from .finite_word_transducers import FiniteWordMapError, parse_finite_word_map
from .interface_package_v5 import CompiledComponentInterfaceV5
from .local_cell_transducers import (
    LocalCellTransducerError,
    checked_initial_words,
    checked_local_cell_selection,
)
from .machine_overlay_boundaries_v5 import (
    authority_selector_expression as _authority_selector_expression,
    checked_opaque_resource_projection as _checked_opaque_resource_projection,
)


def _service_provider_declaration(
    bundle: CompiledComponentInterfaceV5, binding: Mapping[str, object]
) -> str:
    service = next(
        item
        for item in bundle.interface.services
        if item.identity == binding["service_id"]
    )
    signature = bundle.intent.schema.signature_index[service.signature_id]
    parameters = ["void *"] + [
        _parameter_type(bundle.intent.schema.type_index, item)
        for item in signature.parameters
    ]
    storage = (
        "extern" if binding["provider_kind"] == "component_operation" else "static"
    )
    return (
        f"{storage} {_result_type(bundle.intent.schema.type_index, signature)} "
        f"{binding['symbol']}({', '.join(parameters)});"
    )


def _checked_service_argument_transducers(
    *,
    signature: object,
    types: Mapping[str, object],
    argument_words: int,
    value: object,
    relation_values: object,
    local_cell_values: object,
    argument_interface_values: object,
    caller_memory_frame: object,
    profile_sha256: object,
    context: str,
) -> tuple[
    list[dict[str, object]] | None,
    list[dict[str, object]],
    list[dict[str, object]],
]:
    """Normalize one checked call-frame map for imports and interface methods."""

    parameters = tuple(getattr(signature, "parameters"))
    raw_argument_interfaces = array(
        argument_interface_values, f"{context} argument-interface relations"
    )
    argument_interfaces = {
        _uint(
            object_(relation, f"{context} argument-interface relation").get(
                "argument_index"
            ),
            f"{context} argument-interface index",
        ): object_(relation, f"{context} argument-interface relation")
        for relation in raw_argument_interfaces
    }
    if len(argument_interfaces) != len(raw_argument_interfaces):
        raise BoundaryModelError(
            f"{context} argument-interface relations are duplicated"
        )
    if value is None:
        if (
            argument_words != len(parameters)
            or array(relation_values, f"{context} out-interface relations")
            or array(local_cell_values, f"{context} local-cell relations")
        ):
            raise BoundaryModelError(f"{context} arity is incompatible")
        input_interfaces: list[dict[str, object]] = []
        for parameter_index, relation in sorted(argument_interfaces.items()):
            interface_id = relation.get("interface_id")
            parameter = (
                parameters[parameter_index]
                if parameter_index < len(parameters)
                else None
            )
            if (
                set(relation) != {"argument_index", "interface_id"}
                or parameter is None
                or parameter.interpretation != "resource"
                or parameter.access != "none"
                or not isinstance(interface_id, str)
                or not interface_id
                or not isinstance(profile_sha256, str)
                or not profile_sha256
            ):
                raise BoundaryModelError(
                    f"{context} argument-interface relation is incompatible"
                )
            input_interfaces.append(
                {
                    "physical_index": parameter_index,
                    "parameter_index": parameter_index,
                    "profile_sha256": profile_sha256,
                    "interface_id": interface_id,
                }
            )
        return None, [], input_interfaces
    if not isinstance(value, list) or len(value) != argument_words:
        raise BoundaryModelError(f"{context} transducer arity is incompatible")
    transducers = [
        dict(object_(item, f"{context} argument transducer")) for item in value
    ]
    relations = {
        canonical_sha256_v3(dict(relation)): object_(
            relation, f"{context} out-interface relation"
        )
        for relation in array(relation_values, f"{context} out-interface relations")
    }
    local_cell_relations = {
        canonical_sha256_v3(dict(relation)): object_(
            relation, f"{context} local-cell relation"
        )
        for relation in array(local_cell_values, f"{context} local-cell relations")
    }
    mapped_parameters: set[int] = set()
    mapped_record_fields: dict[int, set[str]] = {}
    local_cell_ids: set[str] = set()
    out_interfaces: list[dict[str, object]] = []
    input_interfaces: list[dict[str, object]] = []
    for physical_index, transducer in enumerate(transducers):
        transducer_kind = transducer.get("kind")
        if transducer_kind == "constant":
            continue
        if transducer_kind == "local_cell":
            cell_id = transducer.get("cell_id")
            try:
                initial_words = checked_initial_words(
                    transducer.get("initial_words"), context=context
                )
            except LocalCellTransducerError as exc:
                raise BoundaryModelError(str(exc)) from exc
            relation_sha256 = transducer.get("local_cell_relation_sha256")
            relation = (
                None
                if relation_sha256 is None
                else local_cell_relations.get(str(relation_sha256))
            )
            memory = _caller_memory_argument(
                caller_memory_frame,
                physical_index=physical_index,
                argument_words=argument_words,
            )
            if (
                not isinstance(cell_id, str)
                or not cell_id
                or cell_id in local_cell_ids
                or memory.get("role") != "caller_memory"
                or memory.get("retention") != "during_call"
                or memory.get("access") not in {"read", "read_write"}
                or memory.get("extent") not in {"fixed_word", "enclosing_object"}
                or (memory.get("extent") == "fixed_word" and len(initial_words) != 1)
            ):
                raise BoundaryModelError(
                    f"{context} local-cell transducer is incompatible"
                )
            if relation is None:
                if relation_sha256 is not None or any(
                    word is None for word in initial_words
                ):
                    raise BoundaryModelError(
                        f"{context} partial local cell has no checked relation"
                    )
            else:
                try:
                    checked_local_cell_selection(
                        relation,
                        physical_index=physical_index,
                        initial_words=initial_words,
                        memory=memory,
                        context=context,
                    )
                except LocalCellTransducerError as exc:
                    raise BoundaryModelError(
                        f"{context} local-cell relation is incompatible: {exc}"
                    ) from exc
            transducer["initial_words"] = list(initial_words)
            local_cell_ids.add(cell_id)
            continue
        if transducer_kind == "finite_word_map":
            try:
                parameter_index, _cases = parse_finite_word_map(
                    transducer,
                    context=context,
                )
            except FiniteWordMapError as exc:
                raise BoundaryModelError(str(exc)) from exc
            if (
                parameter_index >= len(parameters)
                or parameter_index in mapped_parameters
            ):
                raise BoundaryModelError(
                    f"{context} transducer parameter map is invalid"
                )
            parameter = parameters[parameter_index]
            if parameter.interpretation != "value":
                raise BoundaryModelError(
                    f"{context} finite-word map requires a value parameter"
                )
            mapped_parameters.add(parameter_index)
            continue
        if transducer_kind == "record_field":
            parameter_index = _uint(
                transducer.get("parameter_index"),
                f"{context} record-field parameter",
            )
            field_id = transducer.get("field_id")
            if parameter_index >= len(parameters) or not isinstance(field_id, str):
                raise BoundaryModelError(
                    f"{context} record-field parameter map is invalid"
                )
            parameter = parameters[parameter_index]
            logical_type = types.get(parameter.type_id)
            fields = () if logical_type is None else tuple(logical_type.body.get("fields", ()))
            matches = [field for field in fields if field.get("id") == field_id]
            if (
                parameter.interpretation != "value"
                or logical_type is None
                or logical_type.kind != "record"
                or parameter_index in mapped_parameters
                or len(matches) != 1
                or not _is_word_record_field(types, matches[0])
                or field_id in mapped_record_fields.setdefault(parameter_index, set())
            ):
                raise BoundaryModelError(
                    f"{context} record-field transducer is incompatible"
                )
            mapped_record_fields[parameter_index].add(field_id)
            continue
        if transducer_kind == "aggregate_result":
            raise BoundaryModelError(
                f"{context} aggregate-result transducer was not ABI-normalized"
            )
        parameter_index = _uint(
            transducer.get("parameter_index"),
            f"{context} transducer parameter",
        )
        if parameter_index >= len(parameters) or parameter_index in mapped_parameters:
            raise BoundaryModelError(f"{context} transducer parameter map is invalid")
        mapped_parameters.add(parameter_index)
        parameter = parameters[parameter_index]
        if transducer_kind == "logical_argument":
            logical_type = types.get(parameter.type_id)
            if logical_type is not None and logical_type.kind == "record":
                raise BoundaryModelError(
                    f"{context} record value requires field transducers"
                )
            if parameter.interpretation == "resource" and parameter.access != "none":
                raise BoundaryModelError(
                    f"{context} writable resource requires an out-interface transducer"
                )
            relation = argument_interfaces.get(physical_index)
            if relation is not None:
                interface_id = relation.get("interface_id")
                if (
                    set(relation) != {"argument_index", "interface_id"}
                    or parameter.interpretation != "resource"
                    or parameter.access != "none"
                    or not isinstance(interface_id, str)
                    or not interface_id
                    or not isinstance(profile_sha256, str)
                    or not profile_sha256
                ):
                    raise BoundaryModelError(
                        f"{context} argument-interface relation is incompatible"
                    )
                input_interfaces.append(
                    {
                        "physical_index": physical_index,
                        "parameter_index": parameter_index,
                        "profile_sha256": profile_sha256,
                        "interface_id": interface_id,
                    }
                )
            continue
        if (
            transducer_kind != "out_interface"
            or parameter.interpretation != "resource"
            or parameter.access not in {"write", "read_write"}
        ):
            raise BoundaryModelError(
                f"{context} out-interface transducer is incompatible"
            )
        relation_sha256 = str(transducer.get("out_interface_relation_sha256", ""))
        relation = relations.get(relation_sha256)
        if (
            relation is None
            or relation.get("argument_index") != physical_index
            or relation.get("write_width") != 4
            or relation.get("success_condition") != "hresult_succeeded_eax"
            or not isinstance(relation.get("interface_id"), str)
            or not isinstance(profile_sha256, str)
            or not profile_sha256
        ):
            raise BoundaryModelError(
                f"{context} out-interface relation is incompatible"
            )
        if parameter.nullable and not bool(relation.get("nullable")):
            raise BoundaryModelError(
                f"{context} nullable logical output contradicts its physical relation"
            )
        out_interfaces.append(
            {
                "physical_index": physical_index,
                "parameter_index": parameter_index,
                "profile_sha256": profile_sha256,
                "interface_id": relation["interface_id"],
                "relation_sha256": relation_sha256,
                # The logical signature is the authoritative contract exposed
                # to Portable-C.  A more-permissive physical declaration must
                # not silently make a non-null logical resource nullable.
                "nullable": bool(parameter.nullable),
            }
        )
    for parameter_index, field_ids in mapped_record_fields.items():
        parameter = parameters[parameter_index]
        logical_type = types[parameter.type_id]
        expected = {str(field["id"]) for field in logical_type.body["fields"]}
        if field_ids != expected:
            raise BoundaryModelError(
                f"{context} record-field transducer is not total"
            )
        mapped_parameters.add(parameter_index)
    if mapped_parameters != set(range(len(parameters))):
        raise BoundaryModelError(
            f"{context} transducer is not total over logical parameters: "
            f"mapped={sorted(mapped_parameters)!r}, "
            f"expected={list(range(len(parameters)))!r}"
        )
    if {item["physical_index"] for item in input_interfaces} != set(
        argument_interfaces
    ):
        raise BoundaryModelError(
            f"{context} argument-interface relation is not mapped logically"
        )
    return transducers, out_interfaces, input_interfaces


def _is_word_record_field(
    types: Mapping[str, object], field: Mapping[str, object]
) -> bool:
    value = types.get(str(field.get("type_id")))
    if value is None or field.get("bit_width") is not None:
        return False
    if value.kind == "integer":
        return value.body.get("width_bits") == 32
    if value.kind == "enum":
        underlying = types.get(str(value.body.get("underlying_type_id")))
        return (
            underlying is not None
            and underlying.kind == "integer"
            and underlying.body.get("width_bits") == 32
        )
    return value.kind == "pointer"


def _caller_memory_argument(
    value: object,
    *,
    physical_index: int,
    argument_words: int,
) -> Mapping[str, object]:
    frame = object_(value, "component checked caller-memory frame")
    if frame.get("status") != "complete":
        raise BoundaryModelError("component caller-memory frame is incomplete")
    matches = [
        object_(row, "component caller-memory argument")
        for row in array(frame.get("arguments"), "component caller-memory arguments")
        if isinstance(row, Mapping) and row.get("argument_index") == physical_index
    ]
    if len(matches) != 1 or not 0 <= physical_index < argument_words:
        raise BoundaryModelError(
            "component caller-memory argument is absent or ambiguous"
        )
    return matches[0]


def _external_service_runtime_helpers() -> list[str]:
    return [
        "static void spx_component_write(",
        "    spx_runtime *rt, uint32_t address, uint32_t width,",
        "    uint32_t value, uint32_t *fault) {",
        "  if (rt == 0 || rt->write == 0) { *fault = 1U; return; }",
        "  rt->write(rt->context, address, width, value, fault);",
        "}",
        "",
    ]


def _external_service_thunk(
    bundle: CompiledComponentInterfaceV5,
    binding: Mapping[str, object],
    authority_selectors: Mapping[str, str],
) -> list[str]:
    service = next(
        item
        for item in bundle.interface.services
        if item.identity == binding["service_id"]
    )
    signature = bundle.intent.schema.signature_index[service.signature_id]
    types = bundle.intent.schema.type_index
    result_type = _result_type(types, signature)
    if len(signature.results) > 1 or (
        signature.results
        and signature.results[0].interpretation
        not in {"value", "reference", "callback", "view"}
    ):
        raise BoundaryModelError(
            "component external service result requires a checked reference or capability transducer"
        )
    parameters = ["void *opaque"] + [
        f"{_parameter_type(types, item)} logical_{_c_identifier(item.identity)}"
        for item in signature.parameters
    ]
    offsets = tuple(int(item) for item in binding["argument_offsets"])
    transducers = binding.get("argument_transducers")
    out_interfaces = tuple(
        object_(item, "component external out-interface")
        for item in binding.get("out_interfaces", [])
    )
    input_interfaces = tuple(
        object_(item, "component external input-interface")
        for item in binding.get("argument_interfaces", [])
    )
    cell_offsets = {
        int(item["parameter_index"]): len(offsets) * 4 + index * 4
        for index, item in enumerate(out_interfaces)
    }
    local_cells = tuple(
        (physical_index, object_(item, "component external local cell"))
        for physical_index, item in enumerate(transducers or [])
        if isinstance(item, Mapping) and item.get("kind") == "local_cell"
    )
    local_cell_relations = {
        canonical_sha256_v3(dict(item)): object_(
            item, "component external local-cell relation"
        )
        for item in binding.get("local_cells", [])
    }
    local_cell_selections = {}
    local_cell_offsets: dict[str, int] = {}
    next_cell_offset = len(offsets) * 4 + len(out_interfaces) * 4
    for physical_index, cell in local_cells:
        cell_id = str(cell.get("cell_id", ""))
        initial_words = cell.get("initial_words")
        if (
            not cell_id
            or cell_id in local_cell_offsets
            or not isinstance(initial_words, list)
            or not initial_words
        ):
            raise BoundaryModelError(
                "component external local-cell inventory is invalid"
            )
        relation_sha256 = cell.get("local_cell_relation_sha256")
        relation = (
            None
            if relation_sha256 is None
            else local_cell_relations.get(str(relation_sha256))
        )
        if relation_sha256 is not None and relation is None:
            raise BoundaryModelError(
                "component external local-cell relation is absent"
            )
        if relation is not None:
            try:
                local_cell_selections[cell_id] = checked_local_cell_selection(
                    relation,
                    physical_index=physical_index,
                    initial_words=checked_initial_words(
                        initial_words, context="component external local cell"
                    ),
                    memory={
                        "role": "caller_memory",
                        "access": "read_write",
                        "extent": "enclosing_object",
                        "retention": "during_call",
                    },
                    context="component external local cell",
                )
            except LocalCellTransducerError as exc:
                raise BoundaryModelError(str(exc)) from exc
        local_cell_offsets[cell_id] = next_cell_offset
        next_cell_offset += len(initial_words) * 4
    local_word_offsets = tuple(
        local_cell_offsets[str(cell["cell_id"])] + word_index * 4
        for _physical_index, cell in local_cells
        for word_index, word in enumerate(cell["initial_words"])
        if word is not None
        or (
            str(cell["cell_id"]) in local_cell_selections
            and word_index
            in (
                local_cell_selections[str(cell["cell_id"])].output_word_indices
                | local_cell_selections[
                    str(cell["cell_id"])
                ].failure_preserved_word_indices
                | local_cell_selections[
                    str(cell["cell_id"])
                ].failure_observed_word_indices
            )
        )
    )
    storage_offsets = (*offsets, *cell_offsets.values(), *local_word_offsets)
    frame_size = max(max(storage_offsets, default=-4) + 4, next_cell_offset)
    if frame_size <= 0 or frame_size > 0x1000:
        raise BoundaryModelError(
            "component external service stack frame is unsupported"
        )
    lines = [
        f"static {result_type} {binding['symbol']}({', '.join(parameters)}) {{",
        "  spx_component_service_context_v1 *service =",
        "      (spx_component_service_context_v1 *)opaque;",
        "  spx_machine_state call_input;",
        "  spx_machine_state call_output;",
        "  spx_call_status call_status;",
        "  uint32_t memory_fault = 0U;",
        "  uint32_t restore_fault = 0U;",
        f"  if (service == 0 || service->runtime == 0 || service->state == 0 ||",
        "      service->memory_fault == 0 || service->service_fault == 0)",
        f"    {_zero_result_expression(result_type)}",
        "  if (*service->memory_fault != UINT32_C(0) ||",
        "      *service->service_fault != UINT32_C(0))",
        f"    {_zero_result_expression(result_type)}",
        f"  if (service->state->esp < UINT32_C({frame_size}))",
        "    goto spx_service_memory_fail;",
    ]
    initial_cell_words: dict[tuple[str, int], str] = {}
    for _physical_index, cell in local_cells:
        cell_id = str(cell["cell_id"])
        for word_index, word in enumerate(cell["initial_words"]):
            if word is None:
                continue
            variable = f"initial_local_cell_{_c_identifier(cell_id)}_{word_index}"
            initial_cell_words[(cell_id, word_index)] = variable
            lines.append(
                f"  uint32_t {variable} = {_initial_local_cell_word_expression(word)};"
            )
    if initial_cell_words:
        lines.append("  if (memory_fault != 0U) goto spx_service_memory_fail;")
    out_by_parameter = {int(item["parameter_index"]): item for item in out_interfaces}
    if transducers is None:
        for index, value in enumerate(signature.parameters):
            physical = f"physical_argument_{index}"
            lines.append(f"  uint32_t {physical} = 0U;")
            lines.extend(
                _external_logical_word_lines(
                    value=value,
                    logical=f"logical_{_c_identifier(value.identity)}",
                    physical=physical,
                    binding=binding,
                    parameter_index=index,
                    input_interfaces=input_interfaces,
                )
            )
    else:
        for physical_index in range(len(offsets)):
            lines.append(f"  uint32_t physical_argument_{physical_index} = 0U;")
        logical_words: dict[int, str] = {}
        for parameter_index, value in enumerate(signature.parameters):
            logical = f"logical_{_c_identifier(value.identity)}"
            if parameter_index in out_by_parameter:
                lines.extend(
                    [
                        f"  if ({logical} == 0 || {logical}->type_tag != UINT32_C(0) ||",
                        f"      {logical}->generation != UINT32_C(0) || {logical}->identity != UINT64_C(0))",
                        "    goto spx_service_fail;",
                    ]
                )
                continue
            logical_type = types[value.type_id]
            if logical_type.kind == "record":
                continue
            physical = f"logical_argument_word_{parameter_index}"
            logical_words[parameter_index] = physical
            lines.append(f"  uint32_t {physical} = 0U;")
            lines.extend(
                _external_logical_word_lines(
                    value=value,
                    logical=logical,
                    physical=physical,
                    binding=binding,
                    parameter_index=parameter_index,
                    input_interfaces=input_interfaces,
                )
            )
        for physical_index, raw_transducer in enumerate(transducers):
            transducer = object_(
                raw_transducer, "component external argument transducer"
            )
            if transducer.get("kind") == "constant":
                lines.append(
                    f"  physical_argument_{physical_index} = UINT32_C({int(transducer['value'])});"
                )
            elif transducer.get("kind") == "logical_argument":
                parameter_index = int(transducer["parameter_index"])
                lines.append(
                    f"  physical_argument_{physical_index} = {logical_words[parameter_index]};"
                )
            elif transducer.get("kind") == "record_field":
                parameter_index = int(transducer["parameter_index"])
                field_id = _c_identifier(str(transducer["field_id"]))
                parameter = signature.parameters[parameter_index]
                logical = f"logical_{_c_identifier(parameter.identity)}"
                lines.append(
                    f"  physical_argument_{physical_index} = (uint32_t){logical}.{field_id};"
                )
            elif transducer.get("kind") == "finite_word_map":
                try:
                    parameter_index, cases = parse_finite_word_map(
                        transducer,
                        context="component external finite-word transducer",
                    )
                except FiniteWordMapError as exc:
                    raise BoundaryModelError(str(exc)) from exc
                logical_word = logical_words[parameter_index]
                lines.extend(
                    [
                        f"  switch ({logical_word}) {{",
                        *(
                            f"    case UINT32_C({case.logical_value}): "
                            f"physical_argument_{physical_index} = "
                            f"UINT32_C({case.physical_value}); break;"
                            for case in cases
                        ),
                        "    default: goto spx_service_fail;",
                        "  }",
                    ]
                )
    if binding["provider_kind"] == "interface_method":
        receiver = int(binding["receiver_argument"])
        slot_offset = int(binding["slot"]) * 4
        lines.extend(
            [
                "  uint32_t interface_vtable = spx_component_read(",
                f"      service->runtime, physical_argument_{receiver}, UINT32_C(4), &memory_fault);",
                "  uint32_t interface_target = 0U;",
                "  if (memory_fault != 0U)",
                "    goto spx_service_memory_fail;",
                "  interface_target = spx_component_read(",
                f"      service->runtime, interface_vtable + UINT32_C({slot_offset}),",
                "      UINT32_C(4), &memory_fault);",
                "  if (memory_fault != 0U)",
                "    goto spx_service_memory_fail;",
                "  if (interface_target == 0U)",
                "    goto spx_service_fail;",
            ]
        )
    captured_target = binding.get("captured_target_projection")
    if captured_target is not None:
        lines.extend(
            _captured_external_target_lines(
                object_(
                    captured_target,
                    "component captured external target projection",
                )
            )
        )
    lines.extend(
        [
            "  call_input = *service->state;",
            f"  call_input.esp -= UINT32_C({frame_size});",
        ]
    )
    for item in out_interfaces:
        parameter_index = int(item["parameter_index"])
        physical_index = int(item["physical_index"])
        lines.append(
            f"  physical_argument_{physical_index} = call_input.esp + UINT32_C({cell_offsets[parameter_index]});"
        )
    for physical_index, cell in local_cells:
        lines.append(
            f"  physical_argument_{physical_index} = call_input.esp + UINT32_C({local_cell_offsets[str(cell['cell_id'])]});"
        )
    for index, offset in enumerate(storage_offsets):
        lines.append(
            f"  uint32_t saved_frame_word_{index} = spx_component_read(service->runtime, "
            f"call_input.esp + UINT32_C({offset}), UINT32_C(4), &memory_fault);"
        )
    lines.append("  if (memory_fault != 0U) goto spx_service_memory_fail;")
    for index, offset in enumerate(offsets):
        lines.append(
            f"  spx_component_write(service->runtime, call_input.esp + UINT32_C({offset}), "
            f"UINT32_C(4), physical_argument_{index}, &memory_fault);"
        )
    for offset in cell_offsets.values():
        lines.append(
            f"  spx_component_write(service->runtime, call_input.esp + UINT32_C({offset}), "
            "UINT32_C(4), UINT32_C(0), &memory_fault);"
        )
    for _physical_index, cell in local_cells:
        base_offset = local_cell_offsets[str(cell["cell_id"])]
        cell_id = str(cell["cell_id"])
        for word_index, word in enumerate(cell["initial_words"]):
            if word is None:
                continue
            lines.append(
                "  spx_component_write(service->runtime, call_input.esp + "
                f"UINT32_C({base_offset + word_index * 4}), UINT32_C(4), "
                f"{initial_cell_words[(cell_id, word_index)]}, &memory_fault);"
            )
    lines.append("  if (memory_fault != 0U) goto spx_service_memory_restore_fail;")
    events = array(binding.get("events"), "component external service events")
    if not events:
        raise BoundaryModelError("component external service has no machine events")
    runtime_event = object_(events[0], "component external runtime event")
    event_offsets = tuple(
        int(item)
        for item in array(
            runtime_event.get("event_stack_offsets"),
            "component external runtime event stack offsets",
        )
    )
    offset_index = {offset: index for index, offset in enumerate(offsets)}
    if any(offset not in offset_index for offset in event_offsets):
        raise BoundaryModelError("component external event stack projection is stale")
    if event_offsets:
        lines.extend(
            [
                "  const spx_stack_input stack_inputs[] = {",
                *(
                    f"    {{ UINT32_C({offset}), UINT32_C(4), "
                    f"physical_argument_{offset_index[offset]} }},"
                    for offset in event_offsets
                ),
                "  };",
            ]
        )
    if binding["provider_kind"] == "interface_method":
        event_head = [
            "  const spx_call_event event = {",
            f"    SPX_CALL_INDIRECT, UINT32_C({runtime_event['source_rva']}), UINT32_C({runtime_event['instruction_rva']}),",
            f"    UINT32_C({runtime_event['event_index']}), interface_target, UINT32_C({runtime_event['return_rva']}),",
            "    (const char *)0, (const char *)0, UINT32_C(0), UINT32_C(0),",
        ]
    elif captured_target is not None:
        ordinal = binding["ordinal"]
        event_head = [
            "  const spx_call_event event = {",
            f"    SPX_CALL_INDIRECT, UINT32_C({runtime_event['source_rva']}), UINT32_C({runtime_event['instruction_rva']}),",
            f"    UINT32_C({runtime_event['event_index']}), captured_external_target, UINT32_C({runtime_event['return_rva']}),",
            f"    {_c_string(binding['dll'])}, {_c_string(binding['import_symbol'])},",
            f"    UINT32_C({0 if ordinal is None else ordinal}), UINT32_C({0 if ordinal is None else 1}),",
        ]
    else:
        ordinal = binding["ordinal"]
        event_head = [
            "  const spx_call_event event = {",
            f"    SPX_CALL_EXTERNAL_IMPORT, UINT32_C(0), UINT32_C({runtime_event['instruction_rva']}),",
            f"    UINT32_C({runtime_event['event_index']}), UINT32_C(0), UINT32_C({runtime_event['return_rva']}),",
            f"    {_c_string(binding['dll'])}, {_c_string(binding['import_symbol'])},",
            f"    UINT32_C({0 if ordinal is None else ordinal}), UINT32_C({0 if ordinal is None else 1}),",
        ]
    lines.extend(
        [
            *event_head,
            "    (const uint32_t *)0, UINT32_C(0),",
            f"    {'stack_inputs' if event_offsets else '(const spx_stack_input *)0'}, UINT32_C({len(event_offsets)})",
            "  };",
            "  call_output = call_input;",
            "  call_status = spx_invoke_call(",
            "      service->runtime, &event, &call_input, &call_output);",
        ]
    )
    for item in out_interfaces:
        parameter_index = int(item["parameter_index"])
        lines.append(
            f"  uint32_t physical_out_interface_{parameter_index} = spx_component_read("
        )
        lines.append(
            f"      service->runtime, call_input.esp + UINT32_C({cell_offsets[parameter_index]}),"
        )
        lines.append("      UINT32_C(4), &memory_fault);")
    local_result_expression = "call_output.eax"
    record_result_fields: tuple[tuple[str, str], ...] = ()
    result_projection = binding.get("result_projection")
    if (
        isinstance(result_projection, Mapping)
        and result_projection.get("kind") == "local_cell_word"
    ):
        cell_id = str(result_projection.get("cell_id", ""))
        word_index = result_projection.get("word_index")
        matching_cells = [
            cell
            for _physical_index, cell in local_cells
            if cell.get("cell_id") == cell_id
        ]
        if (
            len(matching_cells) != 1
            or not isinstance(word_index, int)
            or isinstance(word_index, bool)
            or not 0 <= word_index < len(matching_cells[0]["initial_words"])
        ):
            raise BoundaryModelError(
                "component external local-cell result projection is invalid"
            )
        selected_cell = matching_cells[0]
        selected_relation = None
        relation_sha256 = selected_cell.get("local_cell_relation_sha256")
        if relation_sha256 is not None:
            relation = local_cell_relations.get(str(relation_sha256))
            if relation is None:
                raise BoundaryModelError(
                    "component external local-cell result relation is absent"
                )
            try:
                selected_relation = checked_local_cell_selection(
                    relation,
                    physical_index=next(
                        physical_index
                        for physical_index, cell in local_cells
                        if cell is selected_cell
                    ),
                    initial_words=checked_initial_words(
                        selected_cell.get("initial_words"),
                        context="component external local-cell result",
                    ),
                    memory={
                        "role": "caller_memory",
                        "access": "read_write",
                        "extent": "enclosing_object",
                        "retention": "during_call",
                    },
                    context="component external local-cell result",
                )
            except LocalCellTransducerError as exc:
                raise BoundaryModelError(str(exc)) from exc
            if word_index not in selected_relation.output_word_indices or (
                selected_relation.output_condition != "always"
                and word_index not in selected_relation.failure_preserved_word_indices
                and word_index not in selected_relation.failure_observed_word_indices
            ):
                raise BoundaryModelError(
                    "component external local-cell result is not total"
                )
        elif selected_cell["initial_words"][word_index] is None:
            raise BoundaryModelError(
                "component external local-cell result is not total"
            )
        lines.extend(
            [
                "  uint32_t physical_local_cell_result = spx_component_read(",
                "      service->runtime, call_input.esp + "
                f"UINT32_C({local_cell_offsets[cell_id] + word_index * 4}),",
                "      UINT32_C(4), &memory_fault);",
            ]
        )
        if (
            selected_relation is not None
            and selected_relation.output_condition == "hresult_succeeded_eax"
            and int(word_index) in selected_relation.failure_preserved_word_indices
        ):
            initial_result = initial_cell_words[(cell_id, int(word_index))]
            lines.extend(
                [
                    "  uint32_t checked_local_cell_result =",
                    "      ((call_output.eax & UINT32_C(0x80000000)) == UINT32_C(0))",
                    f"      ? physical_local_cell_result : {initial_result};",
                ]
            )
            local_result_expression = "checked_local_cell_result"
        else:
            local_result_expression = "physical_local_cell_result"
    elif (
        isinstance(result_projection, Mapping)
        and result_projection.get("kind") == "local_cell_record"
    ):
        cell_id = str(result_projection.get("cell_id", ""))
        matching_cells = [
            (physical_index, cell)
            for physical_index, cell in local_cells
            if cell.get("cell_id") == cell_id
        ]
        raw_fields = result_projection.get("fields")
        result_value = signature.results[0] if signature.results else None
        logical_type = None if result_value is None else types[result_value.type_id]
        schema_fields = () if logical_type is None else tuple(logical_type.body.get("fields", ()))
        if (
            len(matching_cells) != 1
            or logical_type is None
            or logical_type.kind != "record"
            or not isinstance(raw_fields, list)
        ):
            raise BoundaryModelError(
                "component external local-cell record result projection is invalid"
            )
        physical_index, selected_cell = matching_cells[0]
        relation_sha256 = selected_cell.get("local_cell_relation_sha256")
        relation = local_cell_relations.get(str(relation_sha256))
        try:
            selection = checked_local_cell_selection(
                relation,
                physical_index=physical_index,
                initial_words=checked_initial_words(
                    selected_cell.get("initial_words"),
                    context="component external local-cell record result",
                ),
                memory={
                    "role": "caller_memory",
                    "access": "read_write",
                    "extent": "enclosing_object",
                    "retention": "during_call",
                },
                context="component external local-cell record result",
            )
        except (BoundaryModelError, LocalCellTransducerError) as exc:
            raise BoundaryModelError(str(exc)) from exc
        fields_by_id = {
            str(object_(field, "component local-cell record field").get("id")): object_(
                field, "component local-cell record field"
            )
            for field in raw_fields
        }
        expected_ids = tuple(str(field["id"]) for field in schema_fields)
        if (
            selection.output_condition != "always"
            or set(fields_by_id) != set(expected_ids)
            or len(fields_by_id) != len(raw_fields)
        ):
            raise BoundaryModelError(
                "component external local-cell record result is not total"
            )
        record_fields: list[tuple[str, str]] = []
        for field in schema_fields:
            field_id = str(field["id"])
            word_index = fields_by_id[field_id].get("word_index")
            if (
                not isinstance(word_index, int)
                or isinstance(word_index, bool)
                or word_index not in selection.output_word_indices
            ):
                raise BoundaryModelError(
                    "component external local-cell record result is not total"
                )
            variable = f"physical_local_cell_result_{_c_identifier(field_id)}"
            lines.extend(
                [
                    f"  uint32_t {variable} = spx_component_read(",
                    "      service->runtime, call_input.esp + "
                    f"UINT32_C({local_cell_offsets[cell_id] + word_index * 4}),",
                    "      UINT32_C(4), &memory_fault);",
                ]
            )
            record_fields.append((field_id, variable))
        record_result_fields = tuple(record_fields)
    lines.extend(_external_stack_restore_lines(storage_offsets, "restore_fault"))
    lines.extend(
        [
            "  if (memory_fault != 0U || restore_fault != 0U ||",
            "      call_status == SPX_CALL_MEMORY_FAULT)",
            "    goto spx_service_memory_fail;",
            "  if (call_status != SPX_CALL_OK)",
            "    goto spx_service_fail;",
        ]
    )
    lines.extend(_external_out_interface_writeback_lines(signature, out_interfaces))
    if result_type == "void":
        lines.extend(["  return;", "spx_service_memory_restore_fail:"])
    elif signature.results[0].interpretation == 'view':
        lines.extend(result_view_lines(signature=signature, types=types,
            projection=binding.get('result_projection'), authority_selectors=authority_selectors,
            runtime='service->runtime', result_word='call_output.eax', failure=['    goto spx_service_fail;']))
        lines.append('spx_service_memory_restore_fail:')
    elif signature.results[0].interpretation == "reference":
        lines.extend(
            _external_reference_result_lines(
                result=signature.results[0],
                result_type=result_type,
                projection=binding.get("result_projection"),
                authority_selectors=authority_selectors,
            )
        )
        lines.append("spx_service_memory_restore_fail:")
    elif signature.results[0].interpretation == "callback":
        nullable = signature.results[0].nullable
        callback_type = _c_identifier(signature.results[0].type_id)
        lines.extend(
            [
                "  if (call_output.eax == 0U) {",
                (
                    f"    return (spx_callback_{callback_type}_v5 *)0;"
                    if nullable
                    else "    goto spx_service_fail;"
                ),
                "  }",
                "  service->callback_result.physical_word = call_output.eax;",
                "  service->callback_result.target_rva = UINT32_C(0);",
                f"  return (spx_callback_{callback_type}_v5 *)&service->callback_result;",
                "spx_service_memory_restore_fail:",
            ]
        )
    elif record_result_fields:
        lines.extend(
            [
                f"  return ({result_type}){{",
                *(
                    f"    .{_c_identifier(field_id)} = ({variable}),"
                    for field_id, variable in record_result_fields
                ),
                "  };",
                "spx_service_memory_restore_fail:",
            ]
        )
    else:
        lines.extend(
            [
                f"  return ({result_type}){local_result_expression};",
                "spx_service_memory_restore_fail:",
            ]
        )
    lines.extend(_external_stack_restore_lines(storage_offsets, "restore_fault"))
    lines.extend(
        [
            "spx_service_memory_fail:",
            "  *service->memory_fault = UINT32_C(1);",
            f"  {_zero_result_expression(result_type)}",
            "spx_service_fail:",
            "  *service->service_fault = UINT32_C(1);",
            f"  {_zero_result_expression(result_type)}",
            "}",
            "",
        ]
    )
    return lines


def _captured_external_target_lines(
    projection: Mapping[str, object],
) -> list[str]:
    if projection.get("width") != 32 or projection.get("at") != "entry":
        raise BoundaryModelError(
            "component captured external target is not a 32-bit entry word"
        )
    kind = projection.get("kind")
    if kind == "register":
        register = projection.get("register")
        if register not in {
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
        }:
            raise BoundaryModelError(
                "component captured external target register is unsupported"
            )
        expression = f"service->state->{register}"
    elif kind == "stack":
        offset = _uint(
            projection.get("offset"), "component captured external target offset"
        )
        expression = (
            "spx_component_read(service->runtime, service->state->esp + "
            f"UINT32_C({offset}), UINT32_C(4), &memory_fault)"
        )
    elif kind == "static_slot":
        rva = _uint(projection.get("rva"), "component captured target slot RVA")
        if rva > 0xfffffffc:
            raise BoundaryModelError("component captured target slot is truncated")
        return [
            "  uint64_t captured_target_address = (uint64_t)service->runtime->image_base +",
            f"      UINT64_C({rva});",
            "  if (captured_target_address > UINT64_C(4294967292))",
            "    goto spx_service_memory_fail;",
            "  uint32_t captured_external_target = spx_component_read(service->runtime,",
            "      (uint32_t)captured_target_address, UINT32_C(4), &memory_fault);",
            "  if (memory_fault != 0U)",
            "    goto spx_service_memory_fail;",
            "  if (captured_external_target == 0U)",
            "    goto spx_service_fail;",
        ]
    else:
        raise BoundaryModelError(
            "component captured external target projection is unsupported"
        )
    return [
        f"  uint32_t captured_external_target = {expression};",
        "  if (memory_fault != 0U)",
        "    goto spx_service_memory_fail;",
        "  if (captured_external_target == 0U)",
        "    goto spx_service_fail;",
    ]


def _external_reference_result_lines(
    *,
    result: object,
    result_type: str,
    projection: object,
    authority_selectors: Mapping[str, str],
) -> list[str]:
    row = object_(projection, "component external reference result projection")
    source = object_(row.get("source"), "component external reference result source")
    requested = object_(
        row.get("requested_extent"),
        "component external reference result requested extent",
    )
    if (
        row.get("kind") != "reference"
        or source.get("kind") != "register"
        or source.get("register") != "eax"
        or source.get("width") != 32
        or requested.get("kind") != "constant"
    ):
        raise BoundaryModelError(
            "component external reference result transducer is unsupported"
        )
    permissions = {"read": 1, "write": 2, "read_write": 3}.get(
        getattr(result, "access", None), 0
    )
    nullable = 1 if getattr(result, "nullable", False) else 0
    extent = _uint(requested.get("value"), "component external reference result extent")
    selector = _authority_selector_expression(row, authority_selectors)
    return [
        "  spx_machine_reference_v1 service_result_reference = {0};",
        "  if (service->runtime->resolve_reference == 0 ||",
        "      service->runtime->resolve_reference(service->runtime->context,",
        f"          call_output.eax, UINT32_C({extent}), UINT32_C({permissions}),",
        f"          {selector}, UINT32_C({nullable}), UINT32_C(0),",
        "          &service_result_reference) != SPX_BOUNDARY_OK)",
        "    goto spx_service_fail;",
        f"  return ({result_type}){{",
        "    service_result_reference.domain,",
        "    service_result_reference.object,",
        "    service_result_reference.generation,",
        "    service_result_reference.offset, service_result_reference.extent,",
        "    service_result_reference.permissions",
        "  };",
    ]


def _external_logical_word_lines(
    *,
    value: object,
    logical: str,
    physical: str,
    binding: Mapping[str, object],
    parameter_index: int,
    input_interfaces: Sequence[Mapping[str, object]] = (),
) -> list[str]:
    if value.interpretation == "value":
        return [f"  {physical} = (uint32_t){logical};"]
    if value.interpretation == "view":
        permissions = {"read": 1, "write": 2, "read_write": 3}.get(value.access)
        if permissions is None:
            raise BoundaryModelError(
                "component external service view access is unsupported"
            )
        return [
            f"  spx_machine_reference_v1 {physical}_reference = {{0}};",
            f"  if ({logical} == 0) goto spx_service_fail;",
            f"  {physical}_reference = (spx_machine_reference_v1){{",
            f"    {logical}->base.domain, {logical}->base.object,",
            f"    {logical}->base.generation, {logical}->base.offset,",
            f"    {logical}->base.extent, {logical}->base.permissions",
            "  };",
            "  if (service->runtime->realize_reference == 0 ||",
            "      service->runtime->realize_reference(service->runtime->context,",
            f"          &{physical}_reference, UINT32_C({permissions}), UINT32_C(0), UINT32_C(0),",
            f"          &{physical}) != SPX_BOUNDARY_OK)",
            "    goto spx_service_fail;",
        ]
    if value.interpretation == "reference":
        permissions = {"read": 1, "write": 2, "read_write": 3}.get(value.access, 0)
        return [
            f"  spx_machine_reference_v1 {physical}_reference = {{",
            f"    {logical}.domain, {logical}.object, {logical}.generation,",
            f"    {logical}.offset, {logical}.extent, {logical}.permissions",
            "  };",
            "  if (service->runtime->realize_reference == 0 ||",
            "      service->runtime->realize_reference(service->runtime->context,",
            f"          &{physical}_reference, UINT32_C({permissions}), UINT32_C({1 if value.nullable else 0}),",
            f"          UINT32_C(0), &{physical}) != SPX_BOUNDARY_OK)",
            "    goto spx_service_fail;",
        ]
    if value.interpretation == "callback":
        return [
            f"  if ({logical} == 0 || {logical}->physical_word == 0U)",
            "    goto spx_service_fail;",
            f"  {physical} = {logical}->physical_word;",
        ]
    if value.interpretation == "resource":
        interface_relations = [
            relation
            for relation in input_interfaces
            if relation.get("parameter_index") == parameter_index
        ]
        if len(interface_relations) > 1:
            raise BoundaryModelError(
                "component service resource has ambiguous interface relations"
            )
        if interface_relations:
            relation = interface_relations[0]
            return [
                f"  spx_machine_resource_v1 {physical}_resource = {{",
                f"    {logical}.type_tag, {logical}.generation, {logical}.identity",
                "  };",
                "  if (service->runtime->realize_interface_resource == 0 ||",
                "      service->runtime->realize_interface_resource(",
                "          service->runtime->context,",
                f"          {_c_string(str(relation['profile_sha256']))},",
                f"          {_c_string(str(relation['interface_id']))},",
                f"          &{physical}_resource, UINT32_C({1 if value.nullable else 0}),",
                f"          &{physical}) != SPX_BOUNDARY_OK)",
                "    goto spx_service_fail;",
            ]
        if binding["provider_kind"] in {"external_call", "interface_method"}:
            _source, type_tag = _checked_opaque_resource_projection(
                value=value,
                projection={
                    "kind": "resource",
                    "resource_kind": value.resource_kind,
                    "source": {
                        "kind": "constant",
                        "value": 0,
                        "width": 32,
                    },
                },
                context="component external opaque resource",
            )
            nullable = 1 if value.nullable else 0
            return [
                f"  if ({logical}.identity == UINT64_C(0)) {{",
                f"    if (UINT32_C({nullable}) == 0U || {logical}.type_tag != 0U ||",
                f"        {logical}.generation != 0U)",
                "      goto spx_service_fail;",
                f"    {physical} = UINT32_C(0);",
                "  } else {",
                f"    if ({logical}.type_tag != UINT32_C({type_tag}) ||",
                f"        {logical}.generation != UINT32_C(1) ||",
                f"        {logical}.identity > UINT32_MAX)",
                "      goto spx_service_fail;",
                f"    {physical} = (uint32_t){logical}.identity;",
                "  }",
            ]
        raise BoundaryModelError(
            "component service resource requires a checked resource transducer"
        )
    raise BoundaryModelError(
        "component external service argument requires a checked capability transducer"
    )


def _external_out_interface_writeback_lines(
    signature: object, out_interfaces: Sequence[Mapping[str, object]]
) -> list[str]:
    if not out_interfaces:
        return []
    lines: list[str] = []
    for item in out_interfaces:
        parameter_index = int(item["parameter_index"])
        nullable = 1 if item["nullable"] else 0
        lines.extend(
            [
                f"  spx_machine_resource_v1 resolved_out_interface_{parameter_index} = {{0}};",
                "  if ((int32_t)call_output.eax >= INT32_C(0) &&",
                "      (service->runtime->resolve_interface_resource == 0 ||",
                "       service->runtime->resolve_interface_resource(",
                "           service->runtime->context,",
                f"           {_c_string(str(item['profile_sha256']))},",
                f"           {_c_string(str(item['interface_id']))},",
                f"           physical_out_interface_{parameter_index}, UINT32_C({nullable}),",
                f"           &resolved_out_interface_{parameter_index}) != SPX_BOUNDARY_OK))",
                "    goto spx_service_fail;",
            ]
        )
    lines.append("  if ((int32_t)call_output.eax >= INT32_C(0)) {")
    for item in out_interfaces:
        parameter_index = int(item["parameter_index"])
        logical = (
            f"logical_{_c_identifier(signature.parameters[parameter_index].identity)}"
        )
        lines.extend(
            [
                f"    {logical}->type_tag = resolved_out_interface_{parameter_index}.type_tag;",
                f"    {logical}->generation = resolved_out_interface_{parameter_index}.generation;",
                f"    {logical}->identity = resolved_out_interface_{parameter_index}.identity;",
            ]
        )
    lines.append("  }")
    return lines


def _initial_local_cell_word_expression(word: object) -> str:
    if word is None:
        return "UINT32_C(0)"
    if isinstance(word, int) and not isinstance(word, bool):
        return f"UINT32_C({_uint(word, 'local-cell initial word')})"
    row = object_(word, "local-cell initial word")
    if row.get("kind") != "entry_projection":
        raise BoundaryModelError("local-cell initial word kind is unsupported")
    projection = object_(row.get("projection"), "local-cell initial word projection")
    kind = projection.get("kind")
    if kind == "constant":
        return f"UINT32_C({_uint(projection.get('value'), 'local-cell projection')})"
    if kind == "register":
        register = projection.get("register")
        if register not in {
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
        }:
            raise BoundaryModelError(
                "local-cell initial register projection is unsupported"
            )
        return f"service->state->{register}"
    if kind == "stack":
        offset = _uint(projection.get("offset"), "local-cell initial stack offset")
        return (
            "spx_component_read(service->runtime, service->state->esp + "
            f"UINT32_C({offset}), UINT32_C(4), &memory_fault)"
        )
    raise BoundaryModelError("local-cell initial projection cannot be rendered")


def _external_stack_restore_lines(offsets: Sequence[int], fault_name: str) -> list[str]:
    return [
        f"  spx_component_write(service->runtime, call_input.esp + UINT32_C({offset}), "
        f"UINT32_C(4), saved_frame_word_{index}, &{fault_name});"
        for index, offset in enumerate(offsets)
    ]


def _zero_result_expression(result_type: str) -> str:
    if result_type == "void":
        return "return;"
    if result_type.startswith("spx_") and "*" not in result_type:
        return f"return ({result_type}){{0}};"
    return f"return ({result_type})0;"


def _uint(value: object, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFFFFFF
    ):
        raise BoundaryModelError(f"{context} must fit u32")
    return value


def _c_identifier(value: str) -> str:
    result = value.replace("-", "_").replace(".", "_")
    if (
        not result
        or not (result[0].isalpha() or result[0] == "_")
        or any(not (character.isalnum() or character == "_") for character in result)
    ):
        raise BoundaryModelError("component overlay identity is not a C identifier")
    return result


__all__ = [
    "_checked_service_argument_transducers",
    "_external_service_runtime_helpers",
    "_external_service_thunk",
    "_service_provider_declaration",
]
