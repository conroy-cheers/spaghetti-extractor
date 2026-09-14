"""Reconstruct cut views with the production overlay's bound native decoder."""

from collections.abc import Mapping

from .bisimulation_reference_transport import machine_reference_expression
from .bisimulation_support import BisimulationRefinementError
from .machine_overlay_boundaries_v5 import authority_selector_expression


def native_view_specs(interface, operation_id, overlay_entry, authority, operation_projection):
    if authority is None:
        return None
    selectors = overlay_entry.get("object_authority_selectors")
    available = {row["id"] for row in authority["rules"]}
    if (not isinstance(selectors, Mapping) or any(
            not isinstance(key, str) or not key or not isinstance(value, str) or value not in available
            for key, value in selectors.items())):
        raise BisimulationRefinementError("native cut decoder lacks bound overlay authority selectors")
    projections = {row["id"]: row["projection"] for row in operation_projection["parameters"]}
    types = interface.type_index()
    result = {}
    for parameter in interface.operation_index()[operation_id].parameters:
        logical_type = types[parameter.type_id]
        projection = projections[parameter.identity]
        spec = {"permissions": {"read": 1, "write": 2, "read_write": 3}.get(logical_type.access),
                "selector": authority_selector_expression(projection, selectors)}
        if logical_type.kind == "view" and logical_type.nullable is True:
            from .machine_overlay_result_views import checked_nullable_input_projection
            checked_nullable_input_projection(projection)
            element = types[logical_type.element_type_id]
            if (logical_type.extent_kind != "origin_remainder" or element.kind != "scalar" or
                    element.c_type != "uint8_t" or spec["permissions"] not in {1, 2, 3}):
                raise BisimulationRefinementError("nullable input admission requires a byte origin-remainder contract")
            spec["nullable_input"] = True
        result[parameter.identity] = spec
    return result


def native_view_selector(spec):
    # The operation's production decoder supplies the selector. Neither a reached
    # source reference nor an authored cut projection may select another origin.
    if spec["permissions"] not in {1, 2, 3}:
        raise BisimulationRefinementError("native cut decoder requires the bound view access")
    return spec["selector"]


def native_view_metadata_relation(capture, spec, extents):
    name = capture.identity
    selector = native_view_selector(spec)
    return (f"({name})->element_width == UINT32_C(1) && "
            f"__CPROVER_spx_native_view_reference_matches(&__CPROVER_spx_local_context_{name}.runtime, "
            f"{machine_reference_expression(f'({name})->base')}, (uint32_t)({extents['address']}), "
            f"(uint64_t)({extents['requested']}), UINT32_C({spec['permissions']}), {selector})")


def native_view_decoder_source():
    return """
static uint32_t __CPROVER_spx_native_view_reference_matches(
    const spx_runtime *runtime, spx_machine_reference_v1 reference,
    uint32_t address, uint64_t requested, uint32_t permissions, const char *selector) {
  spx_machine_reference_v1 expected = {0};
  if (runtime == 0 || runtime->resolve_reference == 0 || requested > UINT32_MAX ||
      runtime->resolve_reference(runtime->context, address, (uint32_t)requested,
          permissions, selector, 0U, 0U, &expected) != SPX_BOUNDARY_OK)
    return 0U;
  return reference.domain == expected.domain && reference.object == expected.object &&
      reference.generation == expected.generation && reference.offset == expected.offset &&
      reference.extent == expected.extent && reference.permissions == expected.permissions;
}
"""
