"""C and CBMC harness rendering for checked component refinement."""

from __future__ import annotations

from typing import Mapping

from .atomics import ATOMIC_OBJECT_RESOURCE_KIND
from .interface_ir import ProofKernelComponentInterface, ProofKernelLogicalType


class _UnsupportedRefinement(ValueError):
    pass


def _render_expression(
    value: object,
    *,
    byte_tokens: Mapping[str, int] | None = None,
    machine_words: Mapping[str, str] | None = None,
    state_machine_words: Mapping[str, str] | None = None,
) -> str:
    row = _object(value, "normalized expression")
    op = row.get("op")
    if op == "parameter":
        name = _text(row.get("name"), "parameter expression")
        return name if machine_words is None else machine_words.get(name, name)
    if op == "atomic_observed":
        return "spx_atomic_observed_" + _text(
            row.get("name"), "atomic observation"
        )
    if op == "state_input":
        name = _text(row.get("name"), "state-input expression")
        default = "spx_initial_state_" + name
        return (
            default
            if state_machine_words is None
            else state_machine_words.get(name, default)
        )
    if op == "service_result":
        index = row.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise _UnsupportedRefinement("service-result index is invalid")
        width = row.get("width", 64)
        if (
            not isinstance(width, int)
            or isinstance(width, bool)
            or not 1 <= width <= 64
        ):
            raise _UnsupportedRefinement("service-result width is invalid")
        expression = f"spx_oracle.results[{index}]"
        if width < 64:
            mask = (1 << width) - 1
            expression = f"({expression} & UINT64_C({mask}))"
        return expression
    if op == "service_writeback":
        index = row.get("index")
        parameter_index = row.get("parameter_index")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            or not isinstance(parameter_index, int)
            or isinstance(parameter_index, bool)
            or parameter_index < 0
        ):
            raise _UnsupportedRefinement("service-writeback index is invalid")
        return f"spx_oracle.writebacks[{index}][{parameter_index}]"
    if op == "byte_read":
        name = _text(row.get("name"), "byte-read view")
        index = row.get("index")
        if not isinstance(index, Mapping):
            raise _UnsupportedRefinement("byte-read index is malformed")
        return (
            f"__CPROVER_uninterpreted_spx_byte_{name}("
            f"(uint32_t)({_render_expression(index, byte_tokens=byte_tokens, machine_words=machine_words, state_machine_words=state_machine_words)}))"
        )
    if op == "load":
        address = row.get("address")
        width = row.get("width")
        if not isinstance(address, Mapping) or width not in {1, 2, 4, 8}:
            raise _UnsupportedRefinement("logical memory load is malformed")
        return (
            "spx_refinement_machine_load((uint32_t)("
            + _render_expression(
                address,
                byte_tokens=byte_tokens,
                machine_words=machine_words,
                state_machine_words=state_machine_words,
            )
            + f"), UINT32_C({width}))"
        )
    if op == "bytes_address":
        name = _text(row.get("name"), "byte-view address")
        if byte_tokens is None or name not in byte_tokens:
            raise _UnsupportedRefinement(
                f"byte-view address {name!r} has no operation parameter"
            )
        return f"UINT64_C({byte_tokens[name]})"
    if op == "const":
        return f"UINT32_C({int(row.get('value', 0)) & 0xffffffff})"
    if op in {"true", "false"}:
        return "UINT32_C(1)" if op == "true" else "UINT32_C(0)"
    args = row.get("args")
    if not isinstance(args, list):
        raise _UnsupportedRefinement(f"expression {op!r} has no arguments")
    rendered = [
        _render_expression(
            item,
            byte_tokens=byte_tokens,
            machine_words=machine_words,
            state_machine_words=state_machine_words,
        )
        if isinstance(item, Mapping)
        else str(item)
        for item in args
    ]
    binary = {
        "add32": "+", "sub32": "-", "and32": "&", "or32": "|",
        "xor32": "^", "eq": "==", "ult32": "<", "shl32": "<<",
        "lshr32": ">>",
    }
    if op in binary and len(rendered) == 2:
        return f"((uint32_t)({rendered[0]}) {binary[op]} (uint32_t)({rendered[1]}))"
    if op == "ite" and len(rendered) == 3:
        return f"(({rendered[0]}) ? ({rendered[1]}) : ({rendered[2]}))"
    if op == "not" and len(rendered) == 1:
        return f"(!({rendered[0]}))"
    if op == "and_bool" and len(rendered) == 2:
        return f"(({rendered[0]}) && ({rendered[1]}))"
    if op == "or_bool" and len(rendered) == 2:
        return f"(({rendered[0]}) || ({rendered[1]}))"
    if op == "xor_bool" and len(rendered) == 2:
        return f"((!!({rendered[0]})) != (!!({rendered[1]})))"
    if op == "msb" and len(rendered) == 2:
        return f"(((uint32_t)({rendered[1]}) >> ({rendered[0]} - 1U)) & 1U)"
    if op == "parity" and len(rendered) == 2:
        return f"spx_even_parity_u8((uint8_t)({rendered[1]}))"
    if op == "add_overflow" and len(rendered) == 4:
        return (
            "spx_add_overflow_u32((uint32_t)(%s), (uint32_t)(%s), "
            "(uint32_t)(%s), (uint32_t)(%s))"
            % tuple(rendered)
        )
    if op == "sub_overflow" and len(rendered) == 4:
        return (
            "spx_sub_overflow_u32((uint32_t)(%s), (uint32_t)(%s), "
            "(uint32_t)(%s), (uint32_t)(%s))"
            % tuple(rendered)
        )
    raise _UnsupportedRefinement(f"expression operation {op!r} is unsupported")

def _render_atomic_refinement_oracle(
    actions: list[Mapping[str, object]], *, nondeterministic_u32: str
) -> list[str]:
    if not actions:
        return []
    lines = ["struct spx_atomic_object { uint32_t token; };", ""]
    for action in actions:
        name = _text(action.get("parameter_id"), "atomic parameter id")
        lines.extend(
            [
                f"static uint32_t spx_atomic_called_{name};",
                f"static uint32_t spx_atomic_expected_{name};",
                f"static uint32_t spx_atomic_desired_{name};",
                f"static uint32_t spx_atomic_observed_{name};",
            ]
        )
    lines.extend(
        [
            "spx_atomic_status spx_atomic_compare_exchange(",
            "    spx_atomic_object *object, uint32_t expected, uint32_t desired,",
            "    spx_atomic_observation *observation) {",
            "  if (object == 0 || observation == 0) return SPX_ATOMIC_UNSUPPORTED;",
        ]
    )
    for index, action in enumerate(actions):
        name = _text(action.get("parameter_id"), "atomic parameter id")
        keyword = "if" if index == 0 else "else if"
        lines.extend(
            [
                f"  {keyword} (object->token == UINT32_C({index + 1})) {{",
                f"    spx_atomic_called_{name}++;",
                f"    spx_atomic_expected_{name} = expected;",
                f"    spx_atomic_desired_{name} = desired;",
                f"    spx_atomic_observed_{name} = {nondeterministic_u32}();",
                f"    observation->observed = spx_atomic_observed_{name};",
                "    observation->exchanged = observation->observed == expected;",
                "    observation->written = observation->exchanged ? desired : observation->observed;",
                "    return SPX_ATOMIC_OK;",
                "  }",
            ]
        )
    lines.extend(["  return SPX_ATOMIC_UNSUPPORTED;", "}", ""])
    lines.extend(
        [
            "spx_atomic_status spx_atomic_exchange(",
            "    spx_atomic_object *object, uint32_t desired,",
            "    spx_atomic_observation *observation) {",
            "  if (object == 0 || observation == 0) return SPX_ATOMIC_UNSUPPORTED;",
        ]
    )
    for index, action in enumerate(actions):
        name = _text(action.get("parameter_id"), "atomic parameter id")
        keyword = "if" if index == 0 else "else if"
        lines.extend(
            [
                f"  {keyword} (object->token == UINT32_C({index + 1})) {{",
                f"    spx_atomic_called_{name}++;",
                f"    spx_atomic_desired_{name} = desired;",
                f"    spx_atomic_observed_{name} = {nondeterministic_u32}();",
                f"    observation->observed = spx_atomic_observed_{name};",
                "    observation->exchanged = UINT32_C(1);",
                "    observation->written = desired;",
                "    return SPX_ATOMIC_OK;",
                "  }",
            ]
        )
    lines.extend(["  return SPX_ATOMIC_UNSUPPORTED;", "}", ""])
    return lines

def _render_callback_refinement_types(
    interface: ProofKernelComponentInterface,
) -> list[str]:
    lines: list[str] = []
    for logical_type in interface.types:
        if logical_type.kind != "callback":
            continue
        identity = logical_type.identity
        lines.extend(
            [
                f"static uint32_t spx_refinement_callback_{identity}_word(",
                f"    const spx_callback_{identity}_v2 *handle) {{",
                "  return handle == 0 ? UINT32_C(0) : handle->physical_word;",
                "}",
            ]
        )
    if lines:
        lines.append("")
    return lines

def _render_service_path_harness(
    *,
    interface: ProofKernelComponentInterface,
    operation_id: str,
    operation_symbol: str,
    result_type: str,
    declarations: list[str],
    arguments: str,
    model: Mapping[str, object],
    common: list[str],
    nondeterministic_functions: Mapping[str, str],
) -> str:
    paths = _rows(model.get("paths"), "semantic paths")
    if not paths:
        raise _UnsupportedRefinement("service path model has no paths")
    enabled = set(_string_rows(model.get("service_ids"), "semantic service ids"))
    services = [row for row in interface.services if row.identity in enabled]
    if {row.identity for row in services} != enabled:
        raise _UnsupportedRefinement("semantic path model has unknown services")
    service_numbers = {
        service.identity: index + 1
        for index, service in enumerate(interface.services)
    }
    max_events = max(1, int(model.get("max_events", 0)))
    max_arguments = max(
        1,
        max((len(service.parameter_type_ids) for service in services), default=0),
    )
    operation = interface.operation_index()[operation_id]
    type_index = interface.type_index()
    reference_constraints: dict[int, dict[str, object]] = {}
    trace_services: dict[int, set[str]] = {}
    for path in paths:
        for trace_index, event in enumerate(
            _rows(path.get("trace"), "semantic path trace")
        ):
            trace_services.setdefault(trace_index, set()).add(
                _text(event.get("service_id"), "semantic trace service id")
            )
        for row in _rows(
            path.get("reference_origins", []), "path reference origins"
        ):
            trace_index = int(row["trace_index"])
            constraint = {
                key: value for key, value in row.items() if key != "trace_index"
            }
            previous = reference_constraints.get(trace_index)
            if previous is not None and previous != constraint:
                raise _UnsupportedRefinement(
                    "interaction reference constraint differs between machine paths"
                )
            reference_constraints[trace_index] = constraint
    byte_parameters = [
        parameter
        for parameter in operation.parameters
        if type_index[parameter.type_id].kind == "bytes"
    ]
    byte_tokens = {
        parameter.identity: index + 1
        for index, parameter in enumerate(byte_parameters)
    }
    machine_words = {
        parameter.identity: (
            f"spx_machine_word_{parameter.identity}"
            if type_index[parameter.type_id].kind in {"reference", "view"}
            else parameter.identity
        )
        for parameter in operation.parameters
    }
    state_machine_words = {
        field.identity: (
            f"spx_refinement_reference_word(spx_initial_state_{field.identity})"
            if type_index[field.type_id].kind == "reference"
            else f"spx_initial_state_{field.identity}"
        )
        for field in interface.state
    }

    def render_expression(value: object) -> str:
        return _render_expression(
            value,
            byte_tokens=byte_tokens,
            machine_words=machine_words,
            state_machine_words=state_machine_words,
        )
    atomic_actions = _rows(model.get("atomic_actions", []), "atomic actions")
    lines = [
        *common,
        "static uint32_t spx_even_parity_u8(uint8_t value) {",
        "  value ^= (uint8_t)(value >> 4); value &= UINT8_C(15);",
        "  return (UINT16_C(0x9669) >> value) & UINT32_C(1);",
        "}",
        "static uint32_t spx_add_overflow_u32(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {",
        "  uint32_t mask = width == UINT32_C(32) ? UINT32_MAX : ((UINT32_C(1) << width) - UINT32_C(1));",
        "  uint32_t sign = UINT32_C(1) << (width - UINT32_C(1));",
        "  return ((~(left ^ right) & (left ^ result) & sign & mask) != UINT32_C(0));",
        "}",
        "static uint32_t spx_sub_overflow_u32(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {",
        "  uint32_t mask = width == UINT32_C(32) ? UINT32_MAX : ((UINT32_C(1) << width) - UINT32_C(1));",
        "  uint32_t sign = UINT32_C(1) << (width - UINT32_C(1));",
        "  return (((left ^ right) & (left ^ result) & sign & mask) != UINT32_C(0));",
        "}",
        "typedef struct {",
        "  uint32_t count;",
        "  uint32_t overflow;",
        f"  uint32_t ids[{max_events}];",
        f"  uint32_t argument_counts[{max_events}];",
        f"  uint64_t arguments[{max_events}][{max_arguments}];",
        f"  uint64_t results[{max_events}];",
        f"  uint64_t writebacks[{max_events}][{max_arguments}];",
        f"  const spx_bytes_view_v2 *byte_views[{max(1, len(byte_parameters))}];",
        "} spx_refinement_oracle_v1;",
        "static spx_refinement_oracle_v1 spx_oracle;",
        "static uint64_t spx_refinement_bytes_token(",
        "    const spx_refinement_oracle_v1 *oracle,",
        "    const spx_bytes_view_v2 *view) {",
        *(
            f"  if (view == oracle->byte_views[{index}]) return UINT64_C({index + 1});"
            for index in range(len(byte_parameters))
        ),
        "  return UINT64_C(0);",
        "}",
    ]
    for service in services:
        if service.result_type_id is None:
            continue
        logical_result = type_index[service.result_type_id]
        if logical_result.kind == "callback":
            lines.append(
                f"static spx_callback_{logical_result.identity}_v2 "
                f"spx_refinement_{service.identity}_results[{max_events}];"
            )
    if any(
        service.result_type_id is not None
        and type_index[service.result_type_id].kind == "callback"
        for service in services
    ):
        lines.append("")
    for service in services:
        resource_cells = [
            (position, type_index[type_id])
            for position, type_id in enumerate(service.parameter_type_ids)
            if type_index[type_id].kind == "resource_cell"
        ]
        if resource_cells and (
            service.result_type_id is None
            or type_index[service.result_type_id].kind not in {"scalar", "enum"}
            or type_index[service.result_type_id].c_type != "int32_t"
        ):
            raise _UnsupportedRefinement(
                f"resource-cell service {service.identity!r} lacks an int32 HRESULT result"
            )
        result = (
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
                f"static {result} spx_refinement_service_{service.identity}({', '.join(parameters)}) {{",
                "  spx_refinement_oracle_v1 *oracle = (spx_refinement_oracle_v1 *)opaque;",
                "  uint32_t index = oracle->count++;",
                f"  if (index >= UINT32_C({max_events})) {{ oracle->overflow = UINT32_C(1); index = UINT32_C(0); }}",
                f"  oracle->ids[index] = UINT32_C({service_numbers[service.identity]});",
                f"  oracle->argument_counts[index] = UINT32_C({len(service.parameter_type_ids)});",
            ]
        )
        for position, type_id in enumerate(service.parameter_type_ids):
            if type_index[type_id].kind == "bytes":
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"spx_refinement_bytes_token(oracle, argument_{position});"
                )
            elif type_index[type_id].kind == "callback":
                identity = type_index[type_id].identity
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"(uint64_t)spx_refinement_callback_{identity}_word(argument_{position});"
                )
            elif type_index[type_id].kind == "view":
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"spx_refinement_reference_word(argument_{position}->base);"
                )
            elif type_index[type_id].kind == "reference":
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"spx_refinement_reference_word(argument_{position});"
                )
            elif type_index[type_id].kind == "resource":
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"argument_{position}.identity;"
                )
            elif type_index[type_id].kind == "resource_cell":
                lines.extend([
                    f"  if (argument_{position} == 0) oracle->overflow = UINT32_C(1);",
                    f"  oracle->arguments[index][{position}] = "
                    f"argument_{position} == 0 ? UINT64_MAX : argument_{position}->identity;",
                ])
            else:
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"{_render_scalar_word(f'argument_{position}', type_index[type_id])};"
                )
        if result != "void":
            logical_result_type = type_index[service.result_type_id]
            if logical_result_type.kind == "reference":
                origin_cases = []
                for trace_index, constraint in sorted(reference_constraints.items()):
                    argument_index = int(constraint["input_argument_index"])
                    services_at_index = trace_services.get(trace_index, set())
                    if len(services_at_index) > 1:
                        raise _UnsupportedRefinement(
                            "interaction reference origin has an ambiguous service position"
                        )
                    if services_at_index != {service.identity}:
                        continue
                    if argument_index >= len(service.parameter_type_ids):
                        raise _UnsupportedRefinement(
                            "interaction origin references an unknown service argument"
                        )
                    origin_type = type_index[service.parameter_type_ids[argument_index]]
                    if origin_type.kind == "view":
                        origin_expression = f"argument_{argument_index}->base"
                    elif origin_type.kind == "reference":
                        origin_expression = f"argument_{argument_index}"
                    else:
                        raise _UnsupportedRefinement(
                            "interaction reference output is not tied to a reference or view input"
                        )
                    minimum_remaining = constraint.get("nonnull_min_remaining")
                    nonzero_argument_index = None
                    minimum = None
                    if minimum_remaining is not None:
                        remaining = _object(
                            minimum_remaining,
                            "interaction non-null remaining constraint",
                        )
                        nonzero_argument_index = int(
                            remaining["nonzero_argument_index"]
                        )
                        minimum = int(remaining["minimum"])
                        if (
                            nonzero_argument_index < 0
                            or nonzero_argument_index
                            >= len(service.parameter_type_ids)
                            or type_index[
                                service.parameter_type_ids[nonzero_argument_index]
                            ].kind
                            not in {"scalar", "enum"}
                            or minimum <= 0
                        ):
                            raise _UnsupportedRefinement(
                                "interaction remaining constraint is not scalar-guarded"
                            )
                    origin_cases.extend(
                        _render_reference_service_result_case(
                            trace_index=trace_index,
                            origin_expression=origin_expression,
                            nullable=bool(logical_result_type.nullable),
                            allow_one_past=bool(logical_result_type.allow_one_past),
                            nonzero_argument_index=nonzero_argument_index,
                            minimum_remaining=minimum,
                            nondeterministic_u32=nondeterministic_functions["uint32_t"],
                        )
                    )
                if not origin_cases:
                    raise _UnsupportedRefinement(
                        f"reference service {service.identity!r} has no checked origin contract"
                    )
                lines.extend(
                    [
                        *origin_cases,
                        "  oracle->overflow = UINT32_C(1);",
                        "  return (spx_ref_v1){0};",
                    ]
                )
            elif logical_result_type.kind == "callback":
                identity = logical_result_type.identity
                nullable = logical_result_type.nullable
                lines.extend(
                    [
                        "  uint32_t logical_word = "
                        f"{nondeterministic_functions['uint32_t']}();",
                        "  oracle->results[index] = (uint64_t)logical_word;",
                        *(
                            [
                                "  if (logical_word == UINT32_C(0)) return 0;"
                            ]
                            if nullable
                            else [
                                "  __CPROVER_assume(logical_word != UINT32_C(0));"
                            ]
                        ),
                        f"  spx_refinement_{service.identity}_results[index].physical_word = logical_word;",
                        f"  spx_refinement_{service.identity}_results[index].target_rva = UINT32_C(0);",
                        f"  return &spx_refinement_{service.identity}_results[index];",
                    ]
                )
            else:
                result_storage = (
                    "logical_result.identity"
                    if logical_result_type.kind == "resource"
                    else _render_scalar_word("logical_result", logical_result_type)
                )
                lines.extend([
                    f"  {result} logical_result = "
                    f"{nondeterministic_functions[result]}();",
                    f"  oracle->results[index] = {result_storage};",
                ])
                if resource_cells:
                    lines.append(
                        "  if (logical_result >= INT32_C(0)) {"
                    )
                    for position, _cell_type in resource_cells:
                        lines.extend([
                            f"    spx_resource_v2 logical_writeback_{position} = {{",
                            f"      {nondeterministic_functions['uint32_t']}(),",
                            f"      {nondeterministic_functions['uint32_t']}(),",
                            f"      {nondeterministic_functions['uint64_t']}()",
                            "    };",
                            f"    *argument_{position} = logical_writeback_{position};",
                            f"    oracle->writebacks[index][{position}] = logical_writeback_{position}.identity;",
                        ])
                    lines.append("  } else {")
                    for position, _cell_type in resource_cells:
                        lines.append(
                            f"    oracle->writebacks[index][{position}] = UINT64_C(0);"
                        )
                    lines.append("  }")
                lines.append("  return logical_result;")
        lines.extend(["}", ""])

    service_type = f"spx_{interface.identity}_services_v2"
    lines.extend(
        [
            "void spx_refinement_harness(void) {",
            f"  {service_type} services = {{0}};",
            "  services.context = &spx_oracle;",
        ]
    )
    lines.extend(
        f"  services.{service.identity} = spx_refinement_service_{service.identity};"
        for service in services
    )
    lines.extend(
        [
            f"  spx_{interface.identity}_context_v2 context = {{0}};",
            "  context.services = &services;",
        ]
    )
    protocol_type = f"spx_{interface.identity}_protocol_state_v2"
    lines.append(
        "  uint32_t spx_initial_protocol_state = "
        f"{nondeterministic_functions['uint32_t']}();"
    )
    pre_states = [
        f"spx_initial_protocol_state == UINT32_C({interface.protocol_states.index(state)})"
        for state in operation.pre_states
    ]
    lines.append(f"  __CPROVER_assume({' || '.join(pre_states)});")
    lines.append(
        f"  context.protocol_state = ({protocol_type})spx_initial_protocol_state;"
    )
    lines.extend(declarations)
    for field in interface.state:
        c_type = _logical_c_type(type_index[field.type_id])
        if type_index[field.type_id].kind == "reference":
            lines.extend(
                _render_reference_state_initialization(
                    field_id=field.identity,
                    parameter_ids=[
                        parameter.identity
                        for parameter in operation.parameters
                        if type_index[parameter.type_id].kind in {"reference", "view"}
                    ],
                    nullable=bool(type_index[field.type_id].nullable),
                    allow_one_past=bool(type_index[field.type_id].allow_one_past),
                    nondeterministic_u32=nondeterministic_functions["uint32_t"],
                )
            )
            lines.append(
                f"  context.state.{field.identity} = spx_initial_state_{field.identity};"
            )
        else:
            lines.extend(
                [
                    f"  {c_type} spx_initial_state_{field.identity} = "
                    f"{nondeterministic_functions[c_type]}();",
                    f"  context.state.{field.identity} = "
                    f"spx_initial_state_{field.identity};",
                ]
            )
    entry_preconditions = _rows(
        model.get("entry_preconditions", []), "entry preconditions"
    )
    if entry_preconditions:
        rendered_preconditions = [
            render_expression(item)
            for item in entry_preconditions
        ]
        lines.append(
            "  __CPROVER_assume("
            + " || ".join(f"({item})" for item in rendered_preconditions)
            + ");"
        )
    lines.extend(
        f"  spx_oracle.byte_views[{index}] = &spx_bytes_{parameter.identity}_view;"
        for index, parameter in enumerate(byte_parameters)
    )
    if operation.results:
        lines.append(f"  {result_type} observed = {operation_symbol}({arguments});")
    else:
        lines.append(f"  {operation_symbol}({arguments});")
    clauses: list[str] = []
    for path in paths:
        trace = _rows(path.get("trace"), "semantic path trace")
        guards = path.get("guards")
        if not isinstance(guards, list) or any(
            not isinstance(guard, Mapping) for guard in guards
        ):
            raise _UnsupportedRefinement("semantic path guards are malformed")
        conditions = ["spx_oracle.overflow == UINT32_C(0)"]
        for action in atomic_actions:
            name = _text(action.get("parameter_id"), "atomic parameter id")
            conditions.extend([
                f"spx_atomic_called_{name} == UINT32_C(1)",
                f"spx_atomic_desired_{name} == "
                f"(uint32_t)({render_expression(action.get('desired'))})",
            ])
            if action.get("operation") == "compare_exchange":
                conditions.append(
                    f"spx_atomic_expected_{name} == "
                    f"(uint32_t)({render_expression(action.get('expected'))})"
                )
        conditions.extend(
            f"({render_expression(guard)})"
            for guard in guards
        )
        conditions.append(f"spx_oracle.count == UINT32_C({len(trace)})")
        path_results = _object(path.get("results"), "semantic path results")
        if set(path_results) != {result.identity for result in operation.results}:
            raise _UnsupportedRefinement("semantic path result inventory differs")
        for result in operation.results:
            observed = (
                "observed"
                if len(operation.results) == 1
                else f"observed.{result.identity}"
            )
            c_type = _logical_c_type(type_index[result.type_id])
            logical_result_type = type_index[result.type_id]
            expected = render_expression(path_results[result.identity])
            if logical_result_type.kind == "callback":
                conditions.append(
                    f"spx_refinement_callback_{logical_result_type.identity}_word({observed}) "
                    f"== (uint32_t)({expected})"
                )
            elif logical_result_type.kind == "reference":
                conditions.append(
                    f"spx_refinement_reference_word({observed}) == "
                    f"(uint64_t)({expected})"
                )
            elif logical_result_type.kind == "resource":
                conditions.append(
                    f"{observed}.identity == (uint64_t)({expected})"
                )
            elif logical_result_type.kind in {"scalar", "enum"}:
                conditions.append(
                    f"{_render_scalar_word(observed, logical_result_type)} == "
                    f"{_render_expected_scalar_word(expected, logical_result_type)}"
                )
            else:
                conditions.append(
                    f"{observed} == ({c_type})({expected})"
                )
        path_state = _object(path.get("state"), "semantic path state")
        if set(path_state) != {field.identity for field in interface.state}:
            raise _UnsupportedRefinement("semantic path state inventory differs")
        for field in interface.state:
            expected_state = render_expression(path_state[field.identity])
            if type_index[field.type_id].kind == "reference":
                conditions.append(
                    f"spx_refinement_reference_word(context.state.{field.identity}) == "
                    f"(uint64_t)({expected_state})"
                )
            elif type_index[field.type_id].kind == "resource":
                conditions.append(
                    f"context.state.{field.identity}.identity == "
                    f"(uint64_t)({expected_state})"
                )
            elif type_index[field.type_id].kind in {"scalar", "enum"}:
                logical_state_type = type_index[field.type_id]
                conditions.append(
                    f"{_render_scalar_word(f'context.state.{field.identity}', logical_state_type)} == "
                    f"{_render_expected_scalar_word(expected_state, logical_state_type)}"
                )
            else:
                conditions.append(
                    f"context.state.{field.identity} == "
                    f"({_logical_c_type(type_index[field.type_id])})"
                    f"({expected_state})"
                )
        post_states = [
            f"context.protocol_state == SPX_{interface.identity.upper()}_PROTOCOL_{state.upper()}"
            for state in operation.post_states
        ]
        conditions.append("(" + " || ".join(post_states) + ")")
        for event_index, event in enumerate(trace):
            service_id = _text(event.get("service_id"), "semantic trace service id")
            if service_id not in service_numbers:
                raise _UnsupportedRefinement(
                    "semantic trace references an unknown service"
                )
            event_arguments = event.get("arguments")
            if not isinstance(event_arguments, list) or any(
                not isinstance(expression, Mapping) for expression in event_arguments
            ):
                raise _UnsupportedRefinement("semantic trace arguments are malformed")
            conditions.extend(
                [
                    f"spx_oracle.ids[{event_index}] == UINT32_C({service_numbers[service_id]})",
                    f"spx_oracle.argument_counts[{event_index}] == UINT32_C({len(event_arguments)})",
                ]
            )
            conditions.extend(
                f"spx_oracle.arguments[{event_index}][{argument_index}] == "
                f"(uint64_t)({render_expression(expression)})"
                for argument_index, expression in enumerate(event_arguments)
            )
        clauses.append("(" + " && ".join(f"({item})" for item in conditions) + ")")
    assertion = " ||\n      ".join(clauses)
    lines.extend(
        [
            f'  __CPROVER_assert(({assertion}), "spx-refinement:{operation_id}:results-state-trace");',
            "}",
            "",
        ]
    )
    return "\n".join(lines)

def _logical_c_type(logical_type: ProofKernelLogicalType) -> str:
    if logical_type.kind in {"scalar", "enum"} and logical_type.c_type is not None:
        return logical_type.c_type
    if logical_type.kind == "resource":
        if logical_type.resource_kind == ATOMIC_OBJECT_RESOURCE_KIND:
            return "spx_atomic_object *"
        return "spx_resource_v2"
    if logical_type.kind == "resource_cell":
        return "spx_resource_v2 *"
    if logical_type.kind == "bytes":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_bytes_view_v2 *"
    if logical_type.kind == "callback":
        return f"spx_callback_{logical_type.identity}_v2 *"
    if logical_type.kind == "reference":
        return "spx_ref_v1"
    if logical_type.kind == "view":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_view_v1 *"
    raise _UnsupportedRefinement(
        f"logical type {logical_type.identity!r} cannot be represented in the scalar path checker"
    )

def _render_scalar_word(
    expression: str, logical_type: ProofKernelLogicalType
) -> str:
    """Encode a checked scalar as its fixed-width unsigned bit pattern.

    CBMC's conversion checker deliberately rejects a direct cast of a negative
    signed value to an unsigned type.  Service traces nevertheless carry raw
    machine words, so spell out the modulo conversion without ever converting
    a negative operand.  The ``value + 1`` form also handles INT64_MIN without
    signed negation overflow.
    """

    if logical_type.kind not in {"scalar", "enum"} or logical_type.c_type is None:
        raise _UnsupportedRefinement(
            f"logical type {logical_type.identity!r} is not a scalar word"
        )
    c_type = logical_type.c_type
    signed = c_type.startswith("int")
    width_text = c_type.removeprefix("uint").removeprefix("int").removesuffix("_t")
    try:
        width = int(width_text)
    except ValueError as exc:
        raise _UnsupportedRefinement(
            f"logical scalar type {logical_type.identity!r} has unsupported C type {c_type!r}"
        ) from exc
    if width not in {8, 16, 32, 64}:
        raise _UnsupportedRefinement(
            f"logical scalar type {logical_type.identity!r} has unsupported width {width}"
        )
    if not signed:
        return f"(uint64_t)({expression})"
    mask = (1 << width) - 1
    return (
        f"(({expression}) < 0 ? "
        f"UINT64_C({mask}) - (uint64_t)(-((int64_t)({expression}) + INT64_C(1))) "
        f": (uint64_t)({expression}))"
    )

def _render_expected_scalar_word(
    expression: str, logical_type: ProofKernelLogicalType
) -> str:
    """Restrict a normalized machine-word expression to a logical scalar width."""

    if logical_type.kind not in {"scalar", "enum"} or logical_type.c_type is None:
        raise _UnsupportedRefinement(
            f"logical type {logical_type.identity!r} is not a scalar word"
        )
    width_text = (
        logical_type.c_type.removeprefix("uint")
        .removeprefix("int")
        .removesuffix("_t")
    )
    try:
        width = int(width_text)
    except ValueError as exc:
        raise _UnsupportedRefinement(
            f"logical scalar type {logical_type.identity!r} has unsupported "
            f"C type {logical_type.c_type!r}"
        ) from exc
    if width not in {8, 16, 32, 64}:
        raise _UnsupportedRefinement(
            f"logical scalar type {logical_type.identity!r} has unsupported width {width}"
        )
    mask = (1 << width) - 1
    return f"((uint64_t)({expression}) & UINT64_C({mask}))"

def _render_checked_reference_support(parameter_ids: list[str]) -> list[str]:
    contexts = [
        f"static spx_refinement_reference_context_v1 spx_reference_context_{name};"
        for name in parameter_ids
    ]
    origin_cases: list[str] = []
    for name in parameter_ids:
        context = f"spx_reference_context_{name}"
        origin_cases.extend(
            [
                f"  if (reference.domain == {context}.origin.domain &&",
                f"      reference.object == {context}.origin.object &&",
                f"      reference.generation == {context}.origin.generation &&",
                f"      reference.extent == {context}.origin.extent &&",
                f"      reference.offset >= {context}.origin.offset &&",
                f"      reference.offset - {context}.origin.offset <= UINT32_MAX &&",
                f"      {context}.machine_base <= UINT32_MAX -",
                f"          (uint32_t)(reference.offset - {context}.origin.offset))",
                f"    return (uint64_t)({context}.machine_base +",
                f"        (uint32_t)(reference.offset - {context}.origin.offset));",
            ]
        )
    return [
        "typedef struct { uint32_t machine_base; spx_ref_v1 origin; }",
        "    spx_refinement_reference_context_v1;",
        *contexts,
        "uint8_t __CPROVER_uninterpreted_spx_memory_u8(uint32_t address);",
        "static uint64_t spx_refinement_machine_load(uint32_t address, uint32_t width) {",
        "  uint64_t value = (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address);",
        "  if (width > UINT32_C(1)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(1)) << 8;",
        "  if (width > UINT32_C(2)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(2)) << 16;",
        "  if (width > UINT32_C(3)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(3)) << 24;",
        "  if (width > UINT32_C(4)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(4)) << 32;",
        "  if (width > UINT32_C(5)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(5)) << 40;",
        "  if (width > UINT32_C(6)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(6)) << 48;",
        "  if (width > UINT32_C(7)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(7)) << 56;",
        "  return value;",
        "}",
        "static uint32_t spx_refinement_reference_is_null(spx_ref_v1 value) {",
        "  return value.domain == UINT64_C(0) && value.object == UINT64_C(0) &&",
        "      value.generation == UINT64_C(0) && value.offset == UINT64_C(0) &&",
        "      value.extent == UINT64_C(0) && value.permissions == UINT32_C(0);",
        "}",
        "static uint64_t spx_refinement_reference_word(spx_ref_v1 reference) {",
        "  if (spx_refinement_reference_is_null(reference)) return UINT64_C(0);",
        *origin_cases,
        "  return UINT64_MAX;",
        "}",
        "static uint32_t spx_refinement_reference_read(",
        "    void *opaque, spx_ref_v1 base, uint64_t offset,",
        "    uint32_t width, uint64_t *result) {",
        "  spx_refinement_reference_context_v1 *context =",
        "      (spx_refinement_reference_context_v1 *)opaque;",
        "  uint64_t machine_word;",
        "  if (context == 0 || result == 0 || width == UINT32_C(0) || width > UINT32_C(8) ||",
        "      base.domain != context->origin.domain || base.object != context->origin.object ||",
        "      base.generation != context->origin.generation || base.extent != context->origin.extent ||",
        "      base.offset < context->origin.offset || base.offset > base.extent ||",
        "      offset > base.extent - base.offset) return UINT32_C(1);",
        "  machine_word = spx_refinement_reference_word(base);",
        "  if (machine_word > UINT32_MAX || offset > UINT32_MAX ||",
        "      (uint32_t)machine_word > UINT32_MAX - (uint32_t)offset ||",
        "      width > UINT32_MAX - ((uint32_t)machine_word + (uint32_t)offset))",
        "    return UINT32_C(1);",
        "  *result = spx_refinement_machine_load(",
        "      (uint32_t)machine_word + (uint32_t)offset, width);",
        "  return UINT32_C(0);",
        "}",
    ]

def _render_reference_service_result_case(
    *,
    trace_index: int,
    origin_expression: str,
    nullable: bool,
    allow_one_past: bool,
    nonzero_argument_index: int | None,
    minimum_remaining: int | None,
    nondeterministic_u32: str,
) -> list[str]:
    lines = [
        f"  if (index == UINT32_C({trace_index})) {{",
        f"    spx_ref_v1 logical_origin = {origin_expression};",
    ]
    if nullable:
        lines.extend(
            [
                f"    if (({nondeterministic_u32}() & UINT32_C(1)) == UINT32_C(0)) {{",
                "      oracle->results[index] = UINT64_C(0);",
                "      return (spx_ref_v1){0};",
                "    }",
            ]
        )
    lines.extend(
        [
            f"    uint32_t logical_offset = {nondeterministic_u32}();",
            "    __CPROVER_assume(logical_origin.extent <= UINT32_MAX);",
            "    __CPROVER_assume((uint64_t)logical_offset >= logical_origin.offset);",
            (
                "    __CPROVER_assume((uint64_t)logical_offset <= logical_origin.extent);"
                if allow_one_past
                else "    __CPROVER_assume((uint64_t)logical_offset < logical_origin.extent);"
            ),
            *(
                []
                if nonzero_argument_index is None or minimum_remaining is None
                else [
                    f"    __CPROVER_assume(argument_{nonzero_argument_index} == 0 ||",
                    f"        (logical_origin.extent >= UINT64_C({minimum_remaining}) &&",
                    f"         (uint64_t)logical_offset <= logical_origin.extent - UINT64_C({minimum_remaining})));",
                ]
            ),
            "    spx_ref_v1 logical_result = logical_origin;",
            "    logical_result.offset = (uint64_t)logical_offset;",
            "    oracle->results[index] = spx_refinement_reference_word(logical_result);",
            "    return logical_result;",
            "  }",
        ]
    )
    return lines

def _render_reference_state_initialization(
    *,
    field_id: str,
    parameter_ids: list[str],
    nullable: bool,
    allow_one_past: bool,
    nondeterministic_u32: str,
) -> list[str]:
    name = f"spx_initial_state_{field_id}"
    lines = [f"  spx_ref_v1 {name} = {{0}};"]
    if not parameter_ids:
        if not nullable:
            raise _UnsupportedRefinement(
                f"reference state {field_id!r} has no checked origin"
            )
        return lines
    selector_limit = len(parameter_ids) + (1 if nullable else 0)
    lines.append(
        f"  uint32_t spx_initial_state_selector_{field_id} = "
        f"{nondeterministic_u32}() % UINT32_C({selector_limit});"
    )
    for index, parameter_id in enumerate(parameter_ids):
        selector = index + (1 if nullable else 0)
        prefix = "if" if index == 0 else "else if"
        lines.extend(
            [
                f"  {prefix} (spx_initial_state_selector_{field_id} == UINT32_C({selector})) {{",
                f"    uint32_t spx_initial_state_offset_{field_id} = {nondeterministic_u32}();",
                f"    {name} = spx_reference_context_{parameter_id}.origin;",
                f"    __CPROVER_assume((uint64_t)spx_initial_state_offset_{field_id} "
                f"{('<=' if allow_one_past else '<')} {name}.extent);",
                f"    {name}.offset = (uint64_t)spx_initial_state_offset_{field_id};",
                "  }",
            ]
        )
    return lines

def _string_rows(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise _UnsupportedRefinement(f"{context} must be an array of strings")
    return tuple(value)

def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentRefinementError(f"{context} must be an object")
    return value

def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, Mapping) for row in value):
        raise ComponentRefinementError(f"{context} must be an array of objects")
    return list(value)

def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentRefinementError(f"{context} must be a nonempty string")
    return value
