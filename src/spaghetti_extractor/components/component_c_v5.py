"""Direct C ABI rendering for canonical V5 component interfaces.

The renderer consumes only ``BoundarySchemaV1`` and
``PortableComponentInterfaceV5``.  The few legacy-looking typedef spellings
are source-level aliases for already-authored component C; they are not format
adapters and carry no authority.
"""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ..boundary import BoundarySignatureV1, BoundaryTypeV1, BoundaryValueV1
from ..boundary._canonical import BoundaryModelError
from .interface_package_v5 import CompiledComponentInterfaceV5


def render_component_c_headers_v5(
    bundle: CompiledComponentInterfaceV5,
    operation_symbols: Mapping[str, str],
    induction_source: Mapping[str, object] | None = None,
) -> Mapping[str, str]:
    """Render the public, implementation, and conformance V5 C artifacts."""

    interface = bundle.interface
    component = _c(interface.identity)
    expected = {operation.identity for operation in interface.operations}
    if set(operation_symbols) != expected:
        raise BoundaryModelError("V5 component operation-symbol map is not total")
    for symbol in operation_symbols.values():
        _c(symbol)

    from .component_local_bytes import local_bytes_header

    public = _render_public(bundle, component)
    implementation = _render_implementation(bundle, component, operation_symbols)
    conformance = _render_conformance(bundle, component, operation_symbols)
    result = {
        "portable-component.h": public,
        "portable-component-implementation.h": implementation,
        "component-conformance.c": conformance,
        "portable-component-local-bytes.h": local_bytes_header(),
    }
    if induction_source is not None:
        result["portable-component-inductive.h"] = _render_inductive_header(
            bundle, operation_symbols, induction_source
        )
        result["component-induction-wrapper.c"] = _render_inductive_wrapper(
            bundle, operation_symbols, induction_source
        )
    return result


def _render_public(bundle: CompiledComponentInterfaceV5, component: str) -> str:
    schema = bundle.intent.schema
    interface = bundle.interface
    guard = f"SPX_{component.upper()}_PUBLIC_V5_H"
    lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct spx_ref_v1 {",
        "  uint64_t domain;",
        "  uint64_t object;",
        "  uint64_t generation;",
        "  uint64_t offset;",
        "  uint64_t extent;",
        "  uint32_t permissions;",
        "} spx_ref_v1;",
        "typedef spx_ref_v1 spx_ref_v5;",
        "#define SPX_REF_V1_DEFINED 1",
        "",
        "typedef struct spx_view_v1 {",
        "  void *context;",
        "  uint32_t (*read_u8)(void *, uint32_t, uint8_t *);",
        "  uint32_t (*write_u8)(void *, uint32_t, uint8_t);",
        "  spx_ref_v5 base;",
        "  uint64_t extent;",
        "  uint32_t element_width;",
        "  void *access_context;",
        "  uint32_t (*read)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t *);",
        "  uint32_t (*write)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t);",
        "} spx_view_v1;",
        "typedef spx_view_v1 spx_view_v5;",
        "typedef spx_view_v1 spx_bytes_view_v2;",
        "#define SPX_VIEW_V1_DEFINED 1",
        "",
        "typedef struct spx_resource_v5 {",
        "  uint32_t type_tag;",
        "  uint32_t generation;",
        "  uint64_t identity;",
        "} spx_resource_v5;",
        "typedef spx_resource_v5 spx_resource_v2;",
        "",
        "typedef uint32_t spx_ref_status;",
        "enum {",
        "  SPX_REF_OK = 0u, SPX_REF_FAULT = 1u, SPX_REF_EXPIRED = 2u,",
        "  SPX_REF_WRONG_ORIGIN = 3u, SPX_REF_PERMISSION = 4u",
        "};",
        "spx_ref_status spx_view_read_u8(const spx_view_v5 *, uint64_t, uint8_t *);",
        "spx_ref_status spx_view_write_u8(const spx_view_v5 *, uint64_t, uint8_t);",
        "spx_ref_status spx_ref_derive(spx_ref_v5, uint64_t, uint32_t, spx_ref_v5 *);",
        "spx_ref_status spx_ref_difference(spx_ref_v5, spx_ref_v5, int64_t *);",
        "",
    ]
    floats = [t for t in schema.types if t.kind == "float"]
    if floats:
        for value in floats:
            _plain_type(schema.type_index, value)
        lines.extend(['#include <float.h>', '#include <limits.h>',
                      '#if defined(__FAST_MATH__) || (defined(__FINITE_MATH_ONLY__) && __FINITE_MATH_ONLY__ > 0)',
                      '#error "binary floating interfaces require ordinary C floating semantics"', '#endif'])
        for kind in sorted({str(t.body['format']) for t in floats}):
            width,ctype,prefix,mantissa,exponent = {'binary32': (32,'float','FLT',24,128),
                'binary64': (64,'double','DBL',53,1024)}.get(kind,(None,None,None,None,None))
            if width is None:
                raise BoundaryModelError('V5 component C supports binary32/binary64 floating interfaces; '+kind+' requires another binding')
            lines.append(f'_Static_assert(sizeof({ctype}) * CHAR_BIT == {width} && FLT_RADIX == 2 && '
                         f'{prefix}_MANT_DIG == {mantissa} && {prefix}_MAX_EXP == {exponent} && '
                         f'{prefix}_MIN_EXP == {3-exponent} && {prefix}_HAS_SUBNORM == 1, '
                         f'"{kind} C representation is unavailable");')
    # A tag first declared in a parameter list has prototype scope in C.
    # Declare every nominal opaque type before records or service signatures so
    # all generated declarations and later implementation definitions agree.
    lines.extend(f"struct spx_opaque_{_c(t.identity)}_v5;"
                 for t in schema.types if t.kind == "opaque")
    lines.extend(_record_type_declarations(schema.type_index))
    callback_types = sorted(
        {
            value.type_id
            for signature in schema.signatures
            for value in (*signature.parameters, *signature.results)
            if value.interpretation == "callback"
        }
    )
    for type_id in callback_types:
        name = _c(type_id)
        lines.extend(
            [
                f"typedef struct spx_callback_{name}_v5 {{",
                "  uint32_t physical_word;",
                "  uint32_t target_rva;",
                f"}} spx_callback_{name}_v5;",
                f"typedef spx_callback_{name}_v5 spx_callback_{name}_v2;",
            ]
        )
    if callback_types:
        lines.append("")

    if _uses_atomic_resource(bundle):
        lines.extend(['#include "spx-atomics.h"', ""])

    service_type = f"spx_{component}_services_v5"
    lines.extend([f"typedef struct {service_type} {{", "  void *context;"])
    for service in interface.services:
        signature = schema.signature_index[service.signature_id]
        result = _result_type(schema.type_index, signature)
        parameters = ["void *"] + [
            _parameter_type(schema.type_index, value) for value in signature.parameters
        ]
        lines.append(
            f"  {result} (*{_c(service.identity)})({', '.join(parameters)});"
        )
    if not interface.services:
        lines.append("  uint8_t reserved;")
    protocol_type = f"spx_{component}_protocol_state_v5"
    lines.extend([
        f"}} {service_type};",
        f"typedef {service_type} spx_{component}_services_v2;",
        "",
        f"typedef enum {protocol_type} {{",
    ])
    for position, state in enumerate(interface.protocol_states):
        lines.append(
            f"  SPX_{component.upper()}_PROTOCOL_{_c(state).upper()} = {position}"
            + ("," if position + 1 < len(interface.protocol_states) else "")
        )
    lines.extend([
        f"}} {protocol_type};",
        f"typedef {protocol_type} spx_{component}_protocol_state_v2;",
        "",
        f"typedef struct spx_{component}_context_v5 {{",
        f"  const {service_type} *services;",
        "  struct {",
    ])
    if interface.state:
        for item in interface.state:
            lines.append(
                f"    {_value_type(schema.type_index, item.value)} {_c(item.value.identity)};"
            )
    else:
        lines.append("    uint8_t reserved;")
    lines.extend(
        [
            "  } state;",
            f"  {protocol_type} protocol_state;",
            f"}} spx_{component}_context_v5;",
            f"typedef spx_{component}_context_v5 spx_{component}_context_v2;",
            "",
            f"#endif /* {guard} */",
            "",
        ]
    )
    return "\n".join(lines)


def _render_implementation(
    bundle: CompiledComponentInterfaceV5,
    component: str,
    operation_symbols: Mapping[str, str],
) -> str:
    guard = f"SPX_{component.upper()}_IMPLEMENTATION_V5_H"
    lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        '#include "portable-component.h"',
        "",
        "/* Proof markers are erased from every production object.  The CBMC",
        " * proof prelude defines them before this header is included. */",
        "#ifndef SPX_PROOF_BEGIN",
        "#define SPX_PROOF_BEGIN(operation_id) ((void)0)",
        "#endif",
        "#ifndef SPX_PROOF_SYNC",
        "#define SPX_PROOF_SYNC(sync_id, invariant, ...) ((void)0)",
        "#endif",
        "",
    ]
    for operation in bundle.interface.operations:
        lines.extend(
            [
                _operation_declaration(bundle,operation,operation_symbols[operation.identity])+";",
                "",
            ]
        )
    lines.extend([f"#endif /* {guard} */", ""])
    return "\n".join(lines)


def _operation_declaration(bundle,operation,symbol):
    schema=bundle.intent.schema
    signature=schema.signature_index[operation.signature_id]
    context=_fresh_c_name('context',{_c(value.identity) for value in signature.parameters})
    parameters=[f"spx_{_c(bundle.interface.identity)}_context_v5 *{context}"]+[
        f"{_parameter_type(schema.type_index,value)} {_c(value.identity)}" for value in signature.parameters]
    return f"{_result_type(schema.type_index,signature)} {symbol}({', '.join(parameters)})"


def render_component_c_skeleton_v5(bundle: CompiledComponentInterfaceV5,
                                    operation_symbols: Mapping[str,str]) -> str:
    """Generate editable operation definitions from the same declarations as C headers."""
    render_component_c_headers_v5(bundle,operation_symbols)
    lines=['#include "portable-component-implementation.h"','']
    for operation in bundle.interface.operations:
        lines += ['/* Operation: '+operation.identity+' */',
            _operation_declaration(bundle,operation,operation_symbols[operation.identity])+' {',
            '    #error "Implement operation '+operation.identity+' using the declared boundary"',
            '}', '']
    return '\n'.join(lines)


def _render_conformance(
    bundle: CompiledComponentInterfaceV5,
    component: str,
    operation_symbols: Mapping[str, str],
) -> str:
    schema = bundle.intent.schema
    lines = ['#include "portable-component-implementation.h"', ""]
    for operation in bundle.interface.operations:
        signature = schema.signature_index[operation.signature_id]
        parameters = [f"spx_{component}_context_v5 *"] + [
            _parameter_type(schema.type_index, value) for value in signature.parameters
        ]
        lines.append(
            f"typedef {_result_type(schema.type_index, signature)} "
            f"(*spx_{component}_{_c(operation.identity)}_fn_v5)({', '.join(parameters)});"
        )
        lines.append(
            f"spx_{component}_{_c(operation.identity)}_fn_v5 const "
            f"spx_{component}_{_c(operation.identity)}_conformance_v5 = "
            f"{operation_symbols[operation.identity]};"
        )
    lines.append("")
    return "\n".join(lines)


def _render_inductive_header(
    bundle: CompiledComponentInterfaceV5,
    operation_symbols: Mapping[str, str],
    value: Mapping[str, object],
) -> str:
    """Render source declarations from a separately checked induction plan.

    The caller binds the plan file as an independent implementation facet.  We
    intentionally consume only its source-shape projection here; its machine
    and refinement authority stays in the induction receipt.
    """

    required = {
        "interface_id", "operation_id", "state", "phase_ids",
        "completion_ids", "symbols",
    }
    if not required <= set(value):
        raise BoundaryModelError("induction source plan lacks its C source shape")
    component_id = str(value["interface_id"])
    operation_id = str(value["operation_id"])
    if _c(component_id) != _c(bundle.interface.identity):
        raise BoundaryModelError("induction source plan names another component")
    try:
        operation = next(
            item for item in bundle.interface.operations if item.identity == operation_id
        )
    except StopIteration as exc:
        raise BoundaryModelError("induction source plan names an unknown operation") from exc
    symbols_value = value["symbols"]
    if not isinstance(symbols_value, Mapping):
        raise BoundaryModelError("induction source plan symbols are not an object")
    symbols = {key: str(symbols_value.get(key, "")) for key in ("wrapper", "initialize", "step", "finish")}
    if symbols["wrapper"] != operation_symbols[operation_id] or any(
        not item for item in symbols.values()
    ):
        raise BoundaryModelError("induction source symbols disagree with the operation map")
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    component = _c(bundle.interface.identity)
    operation_c = _c(operation_id)
    prefix = f"spx_{component}_{operation_c}"
    state_type = f"{prefix}_state_v1"
    control_type = f"{prefix}_control_v1"
    occupied = {_c(item.identity) for item in signature.parameters}
    names = {key: _fresh_c_name(key, occupied) for key in ('context', 'state', 'phase_id', 'completion_id')}
    context = f"spx_{component}_context_v5 *{names['context']}"
    parameters = [context] + [
        f"{_parameter_type(types, item)} {_c(item.identity)}"
        for item in signature.parameters
    ]
    state_value = value["state"]
    phases_value = value["phase_ids"]
    completions_value = value["completion_ids"]
    if not isinstance(state_value, Sequence) or isinstance(state_value, (str, bytes)):
        raise BoundaryModelError("induction source state is not an array")
    if not isinstance(phases_value, Sequence) or isinstance(phases_value, (str, bytes)):
        raise BoundaryModelError("induction source phases are not an array")
    if not isinstance(completions_value, Sequence) or isinstance(completions_value, (str, bytes)):
        raise BoundaryModelError("induction source completions are not an array")
    guard = f"{prefix.upper()}_INDUCTIVE_SOURCE_V5_H"
    lines = [
        f"#ifndef {guard}", f"#define {guard}", "",
        '#include "portable-component-implementation.h"', "", "enum {",
        f"  {prefix.upper()}_CONTROL_RUNNING = 0u,",
        f"  {prefix.upper()}_CONTROL_COMPLETE = 1u", "};", "",
    ]
    for index, phase in enumerate(phases_value):
        lines.append(f"#define {prefix.upper()}_PHASE_{_c(str(phase)).upper()} {index}u")
    for index, completion in enumerate(completions_value):
        lines.append(
            f"#define {prefix.upper()}_COMPLETION_{_c(str(completion)).upper()} {index}u"
        )
    lines.extend(["", f"typedef struct {state_type} {{"])
    if state_value:
        for index, item in enumerate(state_value):
            if not isinstance(item, Mapping) or set(item) != {"id", "type_id"}:
                raise BoundaryModelError(f"induction state field {index} is malformed")
            type_id = str(item["type_id"])
            if type_id not in types:
                raise BoundaryModelError("induction state field names an unknown boundary type")
            lines.append(f"  {_plain_type(types, types[type_id])} {_c(str(item['id']))};")
    else:
        lines.append("  uint8_t reserved;")
    state_parameters = ", ".join([f"{state_type} *{names['state']}", *parameters])
    step_parameters = ", ".join(
        [f"{state_type} *{names['state']}", f"uint32_t {names['phase_id']}", *parameters]
    )
    finish_parameters = ", ".join(
        [f"const {state_type} *{names['state']}", f"uint32_t {names['completion_id']}", *parameters]
    )
    lines.extend(
        [
            f"}} {state_type};", "", f"typedef struct {control_type} {{",
            "  uint32_t kind;", "  uint32_t phase_id;", "  uint32_t completion_id;",
            f"}} {control_type};", "",
            f"{control_type} {symbols['initialize']}({state_parameters});",
            f"{control_type} {symbols['step']}({step_parameters});",
            f"{_result_type(types, signature)} {symbols['finish']}({finish_parameters});",
            "", f"#endif /* {guard} */", "",
        ]
    )
    return "\n".join(lines)


def _render_inductive_wrapper(
    bundle: CompiledComponentInterfaceV5,
    operation_symbols: Mapping[str, str],
    value: Mapping[str, object],
) -> str:
    """Render the checked induction protocol as the public operation symbol."""

    operation_id = str(value.get("operation_id", ""))
    symbols_value = value.get("symbols")
    if not isinstance(symbols_value, Mapping):
        raise BoundaryModelError("induction source plan symbols are not an object")
    symbols = {
        key: str(symbols_value.get(key, ""))
        for key in ("wrapper", "initialize", "step", "finish")
    }
    if symbols["wrapper"] != operation_symbols.get(operation_id) or any(
        not item for item in symbols.values()
    ):
        raise BoundaryModelError(
            "induction source symbols disagree with the operation map"
        )
    try:
        operation = next(
            item
            for item in bundle.interface.operations
            if item.identity == operation_id
        )
    except StopIteration as exc:
        raise BoundaryModelError(
            "induction source plan names an unknown operation"
        ) from exc
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    component = _c(bundle.interface.identity)
    operation_c = _c(operation_id)
    prefix = f"spx_{component}_{operation_c}"
    state_type = f"{prefix}_state_v1"
    control_type = f"{prefix}_control_v1"
    occupied = {_c(item.identity) for item in signature.parameters} | set(symbols.values())
    context, state, control = [_fresh_c_name(key, occupied) for key in ('context', 'state', 'control')]
    parameters = [f"spx_{component}_context_v5 *{context}"] + [
        f"{_parameter_type(types, item)} {_c(item.identity)}"
        for item in signature.parameters
    ]
    arguments = [context, *(_c(item.identity) for item in signature.parameters)]
    rendered_arguments = ", ".join(arguments)
    result_type = _result_type(types, signature)
    lines = [
        '#include "portable-component-inductive.h"',
        "",
        f"{result_type} {symbols['wrapper']}({', '.join(parameters)}) {{",
        f"  {state_type} {state} = {{0}};",
        f"  {control_type} {control} = {symbols['initialize']}(&{state}, {rendered_arguments});",
        f"  while ({control}.kind == {prefix.upper()}_CONTROL_RUNNING) {{",
        f"    {control} = {symbols['step']}(&{state}, {control}.phase_id, {rendered_arguments});",
        "  }",
    ]
    finish_call = (
        f"{symbols['finish']}(&{state}, {control}.completion_id, "
        f"{rendered_arguments})"
    )
    if result_type == "void":
        lines.extend([f"  {finish_call};", "  return;"])
    else:
        lines.append(f"  return {finish_call};")
    lines.extend(["}", ""])
    return "\n".join(lines)


def _result_type(
    types: Mapping[str, BoundaryTypeV1], signature: BoundarySignatureV1
) -> str:
    if not signature.results:
        return "void"
    return _value_type(types, signature.results[0])


def _parameter_type(types: Mapping[str, BoundaryTypeV1], value: BoundaryValueV1) -> str:
    rendered = _value_type(types, value)
    if value.interpretation == "view":
        return f"const {rendered} *"
    if value.interpretation == "resource" and value.resource_kind == "atomic_object":
        return "spx_atomic_object *"
    if value.interpretation == "resource" and value.access in {"write", "read_write"}:
        return f"{rendered} *"
    return rendered


def _value_type(types: Mapping[str, BoundaryTypeV1], value: BoundaryValueV1) -> str:
    if value.interpretation == "view":
        return "spx_view_v5"
    if value.interpretation == "reference":
        return "spx_ref_v5"
    if value.interpretation == "resource":
        if value.resource_kind == "atomic_object":
            return "spx_atomic_object *"
        return "spx_resource_v5"
    if value.interpretation == "callback":
        return f"spx_callback_{_c(value.type_id)}_v5 *"
    return _plain_type(types, types[value.type_id])


def _plain_type(types: Mapping[str, BoundaryTypeV1], value: BoundaryTypeV1) -> str:
    if value.kind == "void":
        return "void"
    if value.kind == "bool":
        return "uint8_t"
    if value.kind == "float":
        supported = {('binary32',32): 'float', ('binary64',64): 'double'}
        key = (value.body['format'],value.body['value_bits'])
        if key not in supported:
            raise BoundaryModelError('V5 component C requires binary32/32-bit or binary64/64-bit floats')
        return supported[key]
    if value.kind == "integer":
        width = int(value.body["width_bits"])
        if width not in {8, 16, 32, 64}:
            raise BoundaryModelError("V5 component C supports 8/16/32/64-bit integers")
        return f"{'int' if value.body['signed'] else 'uint'}{width}_t"
    if value.kind == "enum":
        return _plain_type(types, types[str(value.body["underlying_type_id"])])
    if value.kind == "pointer":
        return "uintptr_t"
    if value.kind == "opaque":
        return f"struct spx_opaque_{_c(value.identity)}_v5 *"
    if value.kind == "record":
        return f"spx_{_c(value.identity)}_v2"
    raise BoundaryModelError(
        f"V5 component C does not support plain boundary type {value.kind!r}"
    )


def _record_type_declarations(
    types: Mapping[str, BoundaryTypeV1],
) -> list[str]:
    """Render logical record values once, independently of physical ABI lowering."""

    pending = {
        identity: value
        for identity, value in types.items()
        if value.kind == "record"
    }
    rendered: set[str] = set()
    lines: list[str] = []
    while pending:
        ready = [
            identity
            for identity, value in pending.items()
            if all(
                types[str(field["type_id"])].kind != "record"
                or str(field["type_id"]) in rendered
                for field in value.body["fields"]
            )
        ]
        if not ready:
            raise BoundaryModelError(
                "V5 component C record values contain an unsupported value cycle"
            )
        for identity in sorted(ready):
            value = pending.pop(identity)
            name = f"spx_{_c(identity)}_v2"
            lines.append(f"typedef struct {name} {{")
            fields = tuple(value.body["fields"])
            if not fields:
                raise BoundaryModelError("V5 component C record values may not be empty")
            for field in fields:
                if field["bit_width"] is not None:
                    raise BoundaryModelError(
                        "V5 component C record values do not support bit-fields"
                    )
                field_type = types[str(field["type_id"])]
                lines.append(
                    f"  {_plain_type(types, field_type)} {_c(str(field['id']))};"
                )
            lines.extend([f"}} {name};", f"typedef {name} spx_{_c(identity)}_v5;", ""])
            rendered.add(identity)
    return lines


def _uses_atomic_resource(bundle: CompiledComponentInterfaceV5) -> bool:
    return any(
        value.interpretation == "resource" and value.resource_kind == "atomic_object"
        for signature in bundle.intent.schema.signatures
        for value in (*signature.parameters, *signature.results)
    )


def _c(value: str) -> str:
    result = value.replace("-", "_").replace(".", "_")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", result) is None:
        raise BoundaryModelError(f"value {value!r} cannot be represented as a C identifier")
    return result


def _fresh_c_name(preferred: str, occupied: set[str]) -> str:
    """Reserve a generated local without changing authored parameter names.

    Keep existing output unchanged when there is no collision. Callers share the
    occupied set for all locals in the same C scope, including authored inputs.
    """
    name=preferred
    suffix=2
    while name in occupied:
        name=f'{preferred}_{suffix}'
        suffix+=1
    occupied.add(name)
    return name


__all__ = ["render_component_c_headers_v5", "render_component_c_skeleton_v5"]
