"""Checked view adaptation at connected logical-operation boundaries."""

from __future__ import annotations

from ..boundary._canonical import BoundaryModelError


VIEW_CONTEXT_DECLARATION = """#ifndef SPX_COMPONENT_VIEW_CONTEXT_DEFINED
#define SPX_COMPONENT_VIEW_CONTEXT_DEFINED 1
typedef struct spx_component_view_context {
  spx_runtime *runtime;
  uint32_t address;
  uint64_t extent;
  uint32_t permissions;
} spx_component_view_context;
#endif
"""


def bounded_view_argument_lines(
    *, name: str, extent: str, access: str, selector: str, zero_result: str,
) -> list[str]:
    permissions = {"read": 1, "write": 2, "read_write": 3}.get(access)
    if permissions is None:
        raise BoundaryModelError("logical operation view access is unsupported")
    bounded = f"{name}_bounded"
    return [
        f"  spx_view_v5 {bounded};",
        f"  uint64_t {name}_requested = {extent};",
        f"  uint32_t {name}_address = UINT32_C(0);",
        f"  spx_machine_reference_v1 {name}_reference = {{0}};",
        f"  if ({name} == 0 || {name}_requested > UINT32_MAX ||",
        f"      {name}->base.offset > {name}->base.extent ||",
        f"      {name}_requested > {name}->extent ||",
        f"      {name}_requested > {name}->base.extent - {name}->base.offset ||",
        f"      {name}->element_width != UINT32_C(1)) {{",
        "    if (caller->service_fault != 0) *caller->service_fault = UINT32_C(1);",
        f"    {zero_result}",
        "  }",
        f"  {name}_reference = (spx_machine_reference_v1){{",
        f"    {name}->base.domain, {name}->base.object, {name}->base.generation,",
        f"    {name}->base.offset, {name}->base.extent, {name}->base.permissions",
        "  };",
        "  if (caller->runtime->realize_reference == 0 ||",
        "      caller->runtime->resolve_reference == 0 ||",
        "      caller->runtime->realize_reference(caller->runtime->context,",
        f"          &{name}_reference, UINT32_C({permissions}), UINT32_C(0),",
        f"          UINT32_C(0), &{name}_address) != SPX_BOUNDARY_OK ||",
        "      caller->runtime->resolve_reference(caller->runtime->context,",
        f"          {name}_address, (uint32_t){name}_requested, UINT32_C({permissions}),",
        f"          {selector}, UINT32_C(0), UINT32_C(0),",
        f"          &{name}_reference) != SPX_BOUNDARY_OK ||",
        f"      {name}_reference.offset > {name}_reference.extent ||",
        f"      {name}_requested > {name}_reference.extent - {name}_reference.offset) {{",
        "    if (caller->service_fault != 0) *caller->service_fault = UINT32_C(1);",
        f"    {zero_result}",
        "  }",
        f"  spx_component_view_context {name}_context = {{",
        f"    caller->runtime, {name}_address, {name}_requested, UINT32_C({permissions})",
        "  };",
        f"  {bounded} = (spx_view_v5){{",
        f"    .context = &{name}_context,",
        f"    .read_u8 = {'spx_component_view_read' if permissions & 1 else '0'},",
        f"    .write_u8 = {'spx_component_view_write' if permissions & 2 else '0'},",
        "    .base = {",
        f"      {name}_reference.domain, {name}_reference.object,",
        f"      {name}_reference.generation, {name}_reference.offset,",
        f"      {name}_reference.extent, {name}_reference.permissions",
        "    },",
        f"    .extent = {name}_requested, .element_width = UINT32_C(1),",
        f"    .access_context = &{name}_context,",
        f"    .read = {'spx_component_view_read_span' if permissions & 1 else '0'},",
        f"    .write = {'spx_component_view_write_span' if permissions & 2 else '0'}",
        "  };",
        f"  const spx_view_v5 *{name}_argument = &{bounded};",
    ]
