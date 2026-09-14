"""Local source models for fixed memory views, using the existing view ABI.

These models are supplementary obligations. Neither their generation nor a
successful solver run qualifies a provider: source opacity, exact/source proof,
entry transport, evidence binding and composition must also be checked.
"""

from __future__ import annotations

from .bisimulation_summary_contracts import memory_summary_operations
from .bisimulation_mutable_memory import MAX_MUTABLE_MODEL_BYTES, mutable_memory_runtime
from .capabilities import spx_portable_reference_runtime_v5_source
from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_overlay_services_v5 import _c_identifier
from .machine_overlay_v5 import _view_runtime_helpers
from .bisimulation_source_dependencies import render_dependencies, context_setup


MUTABLE_MODEL_POLICY = "fixed-mutable-view-paired-bytes-write-frame-v1"
MUTABLE_CONTRACT_POLICY = "fixed-mutable-source-contract-experiment-v1"
READONLY_MODEL_POLICY = "fixed-readable-view-paired-input-empty-frame-v1"
READONLY_CONTRACT_POLICY = "fixed-readable-source-contract-experiment-v1"


def readonly_checker_options(unwind: int) -> list[str]:
    if not isinstance(unwind, int) or isinstance(unwind, bool) or unwind < 2:
        raise ValueError("read-only contract unwinding limit is invalid")
    return ["--json-ui", "--trace", "--bounds-check", "--pointer-check",
            "--signed-overflow-check", "--undefined-shift-check", "--div-by-zero-check",
            "--unwind", str(unwind), "--unwinding-assertions", "--no-self-loops-to-assumptions",
            "--sat-solver", "cadical"]


def mutable_checker_options(unwind: int) -> list[str]:
    # Repeated access callbacks create addressed temporaries. This is a solver
    # encoding budget, not a bound on admitted input counts or object lifetimes.
    return [*readonly_checker_options(unwind), "--object-bits", "9"]


def _fixed_memory_summary_operations(bundle: CompiledComponentInterfaceV5, *, mutable=False) -> tuple[str, ...] | None:
    """Admit declared fixed extents; never infer input bounds from unwinding."""
    operations = memory_summary_operations(bundle, mutable=mutable)
    if operations is None:
        return None
    for operation in bundle.interface.operations:
        signature = bundle.intent.schema.signature_index[operation.signature_id]
        for value in signature.parameters:
            if value.interpretation == "view" and (
                value.extent["kind"] != "fixed"
                or not isinstance(value.extent["bytes"], int)
                or isinstance(value.extent["bytes"], bool)
                or not 0 < value.extent["bytes"] <= 0x100000000
            ):
                return None
    if mutable and any(sum(value.extent["bytes"] for value in
            bundle.intent.schema.signature_index[op.signature_id].parameters
            if value.interpretation == "view") > MAX_MUTABLE_MODEL_BYTES for op in bundle.interface.operations):
        return None
    return operations


def fixed_readonly_summary_operations(bundle):
    return _fixed_memory_summary_operations(bundle)


def fixed_mutable_summary_operations(bundle):
    return _fixed_memory_summary_operations(bundle, mutable=True)


def render_readonly_source_model(**kwargs):
    return _render_memory_source_model(**kwargs, mutable=False)


def render_mutable_source_model(**kwargs):
    return _render_memory_source_model(**kwargs, mutable=True)


def _model_object(typ: str, name: str, *, mutable: bool) -> list[str]:
    if mutable:
        # Opaque transport does not expose allocation addresses or duration.
        # These objects exist before the operation, so DFCC still protects them.
        return [f"  {typ} {name}_storage;", f"  {typ} *{name} = &{name}_storage;"]
    return [f"  {typ} *{name} = malloc(sizeof(*{name}));",
            f"  __CPROVER_assume({name} != 0);"]


def _render_memory_source_model(
    *, bundle: CompiledComponentInterfaceV5, operation_id: str, symbol: str,
    kind: str = "input_dependence", mutable: bool = False,
    summary_dependencies=(),
) -> tuple[str, str]:
    """Generate a universal paired call with an optional DFCC frame contract.

    Each scalar and logical reference is arbitrary. Both calls receive related
    values and a shared uninterpreted byte map indexed by physical address.
    Addresses may overlap. Descriptor aliases are enumerated symbolically and
    transported consistently to the other call. Private contexts and descriptor
    storage are separate; the opacity premise excludes observing their layout.

    The view convention fixes byte width, callbacks and live readable contents.
    No assumption restricts a scalar parameter or a loop. Mutable calls have
    separate alias-preserving byte storage on each side and compare final bytes.
    Frame instrumentation permits only that byte storage in mutable mode and
    nothing in read-only mode; contexts, descriptors and transport stay protected.
    """
    operations = _fixed_memory_summary_operations(bundle, mutable=mutable)
    if (operations is None or operation_id not in operations or kind not in {"frame", "input_dependence"}
            or not symbol or _c_identifier(symbol) != symbol):
        raise ValueError("memory source model requires supported fixed view extents")
    operation = next(row for row in bundle.interface.operations if row.identity == operation_id)
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    context = f"spx_{_c_identifier(bundle.interface.identity)}_context_v5"
    result_type = _result_type(types, signature)
    flavor = "mutable" if mutable else "readonly"
    entry = f"spx_{flavor}_{kind}_{_c_identifier(operation_id)}"
    capacity = sum(v.extent["bytes"] for v in signature.parameters if v.interpretation == "view") if mutable else 0
    sides = ("left",) if kind == "frame" else ("left", "right")
    parameters = [f"{context} *spx_context"] + [
        f"{_parameter_type(types, value)} spx_parameter_{index}"
        for index, value in enumerate(signature.parameters)
    ]
    readonly_runtime = [
        'struct spx_readonly_domain { uint32_t address; uint64_t extent; };',
        'uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);',
        'static uint32_t spx_readonly_read(void *opaque, uint32_t address,',
        '    uint32_t width, uint32_t *fault) {',
        '  struct spx_readonly_domain *domain = (struct spx_readonly_domain *)opaque;',
        '  __CPROVER_assert(width >= 1U && width <= 4U && address >= domain->address &&',
        '      (uint64_t)address + width <= (uint64_t)domain->address + domain->extent,',
        '      "spx-readonly-readable-frame");',
        '  uint32_t result = 0U;',
        '  for (uint32_t i = 0U; i < width; ++i)',
        '    result |= (uint32_t)__CPROVER_uninterpreted_readonly_byte(address+i) << (8U*i);',
        '  *fault = 0U;',
        '  return result;',
        '}',
    ]
    lines = [
        '#include "state-machine-runtime.h"',
        '#include "portable-component-implementation.h"',
        'void *malloc(__CPROVER_size_t);',
        *(mutable_memory_runtime(capacity) if mutable else readonly_runtime),
        *_view_runtime_helpers(need_read=True, need_write=mutable),
        spx_portable_reference_runtime_v5_source(),
        *render_dependencies(summary_dependencies, mutable=mutable),
        f"{result_type} {symbol}({', '.join(parameters)})",
        '__CPROVER_requires(1)',
        '__CPROVER_ensures(1)',
        ('__CPROVER_assigns(__CPROVER_object_whole(spx_mutable_frame->values));'
         if mutable else '__CPROVER_assigns();'),
        f"void {entry}(void) {{",
    ]
    for side in sides:
        lines.extend(_model_object(context, f"spx_context_{side}", mutable=mutable))
        if summary_dependencies:
            lines.extend(context_setup(bundle.interface.identity, side))
    if mutable:
        for side in sides:
            lines.extend(_model_object("struct spx_mutable_world", f"spx_world_{side}", mutable=True))
            lines.extend([
                f"  uint8_t spx_values_{side}[{capacity}U];",
                f"  spx_world_{side}->values = spx_values_{side};",
            ])
    slot = 0
    view_indices: list[int] = []
    for index, value in enumerate(signature.parameters):
        name = f"spx_parameter_{index}"
        if value.interpretation != "view":
            lines.append(f"  {_parameter_type(types, value)} {name};")
            continue
        extent = value.extent["bytes"]
        lines.extend([
            f"  spx_ref_v5 {name}_base;",
            f"  uint32_t {name}_address;",
            f"  __CPROVER_assume((uint64_t){name}_address + UINT64_C({extent}) <= UINT64_C(4294967296));",
        ])
        for side in sides:
            prefix = f"{name}_{side}"
            for typ, suffix in (("spx_view_v5", ""), ("spx_component_view_context", "_context"),
                                ("spx_runtime", "_runtime"), ("struct spx_mutable_domain" if mutable else "struct spx_readonly_domain", "_memory")):
                lines.extend(_model_object(typ, prefix + suffix, mutable=mutable))
            if mutable:
                lines.extend([
                    f"  *{prefix}_memory = (struct spx_mutable_domain){{spx_world_{side}, {name}_address, UINT64_C({extent}), {3 if value.access == 'read_write' else 1}U}};",
                    f"  for (uint32_t i=0U; i<{extent}U; ++i) {{",
                    f"    spx_world_{side}->addresses[{slot}U+i] = {name}_address+i;",
                    f"    spx_world_{side}->values[{slot}U+i] = __CPROVER_uninterpreted_readonly_byte({name}_address+i);",
                    "  }",
                    f"  {prefix}_runtime->write = spx_mutable_write;",
                ])
            lines.extend([
                *([] if mutable else [f"  *{prefix}_memory = (struct spx_readonly_domain){{{name}_address, UINT64_C({extent})}};"]),
                f"  {prefix}_runtime->context = {prefix}_memory;",
                f"  {prefix}_runtime->read = spx_{flavor}_read;",
                f"  *{prefix}_context = (spx_component_view_context){{{prefix}_runtime, {name}_address, UINT64_C({extent}), {3 if value.access == 'read_write' else 1}U}};",
                f"  *{prefix} = (spx_view_v5){{.context={prefix}_context, .read_u8=spx_component_view_read,",
                f"      .base={name}_base, .extent=UINT64_C({extent}), .element_width=1U,",
                f"      .access_context={prefix}_context, .read=spx_component_view_read_span"
                + (", .write_u8=spx_component_view_write, .write=spx_component_view_write_span"
                   if mutable and value.access == "read_write" else "") + "};",
            ])
        compatible = [prior for prior in view_indices
                      if signature.parameters[prior].extent == value.extent
                      and signature.parameters[prior].access == value.access]
        if compatible:
            lines.extend([f"  uint32_t {name}_alias;",
                          f"  __CPROVER_assume({name}_alias <= {len(compatible)}U);"])
            for choice, prior in enumerate(compatible):
                lines.append(f"  if ({name}_alias == {choice}U) {{")
                for side in sides:
                    lines.append(f"    {name}_{side} = spx_parameter_{prior}_{side};")
                lines.append("  }")
        view_indices.append(index)
        slot += extent
    for side in sides:
        args = [f"spx_context_{side}"] + [
            f"spx_parameter_{index}" + (f"_{side}" if value.interpretation == "view" else "")
            for index, value in enumerate(signature.parameters)
        ]
        if mutable:
            lines.append(f"  spx_mutable_frame = spx_world_{side};")
        if summary_dependencies:
            lines.append(f"  spx_dependency_expected_context = &spx_dependency_token_{side};")
        call = f"{symbol}({', '.join(args)})"
        lines.append(f"  {result_type} spx_result_{side} = {call};" if result_type != "void" else f"  {call};")
    condition = "spx_result_left == spx_result_right" if result_type != "void" and kind == "input_dependence" else "1"
    lines.append(f'  __CPROVER_assert({condition}, "spx-{flavor}-{kind}:{operation_id}");')
    if mutable and kind == "input_dependence":
        lines.extend([f"  for (uint32_t i=0U; i<{capacity}U; ++i)",
                      '    __CPROVER_assert(spx_world_left->values[i] == spx_world_right->values[i], "spx-mutable-post-memory");'])
    lines.append("}")
    return "\n".join(lines) + "\n", entry
