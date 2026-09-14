"""Fixed shared-image views borrow live storage; they never copy heap contents."""

from ..boundary._canonical import BoundaryModelError
from .component_c_v5 import _c
from .machine_binding import MachineProjectionV1


def checked_state_view(bundle, item, row):
    value = item.value
    pointer = bundle.intent.schema.type_index[value.type_id]
    element = bundle.intent.schema.type_index.get(pointer.body.get("pointee_type_id"))
    permissions = {"read": 1, "write": 2, "read_write": 3}.get(value.access)
    extent = value.extent.get("bytes")
    if (value.interpretation != "view" or value.nullable or
            pointer.kind != "pointer" or element is None or element.kind != "integer" or
            element.body.get("width_bits") != 8 or permissions is None or
            value.extent.get("kind") != "fixed" or not isinstance(extent, int) or
            not 0 < extent <= 0xffffffff):
        raise BoundaryModelError("shared state view requires a fixed nonnullable byte view")
    entry = MachineProjectionV1.parse(row.get("entry"), "shared state view entry").to_payload()
    exit_ = MachineProjectionV1.parse(row.get("exit"), "shared state view exit").to_payload()
    if (entry.get("kind") != "view" or entry.get("at") != "entry" or
            exit_ != {**entry, "at": "exit"} or
            entry.get("extent") != {"kind": "constant", "width": 32, "value": extent} or
            entry.get("requested_extent") != entry.get("extent") or
            entry.get("base", {}).get("kind") != "constant" or
            entry["base"].get("width") != 32 or
            entry.get("authority", {}).get("kind") != "image" or
            entry["authority"].get("lifetime") != "image"):
        raise BoundaryModelError("shared state view requires unchanged fixed image bindings")
    address = entry["base"]["value"]
    if not 0 < address <= 0x100000000 - extent:
        raise BoundaryModelError("shared state view address range overflows IA-32")
    return entry, extent, permissions, address


def state_view_import_lines(*, bundle, item, row, selector, context, runtime,
                            failure="return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"):
    _, extent, permissions, address = checked_state_view(bundle, item, row)
    name = f"component_state_{_c(item.value.identity)}"
    return [
        f"  spx_machine_reference_v1 {name}_reference = {{0}};",
        f"  if ({runtime} == 0 || {runtime}->resolve_reference == 0 ||",
        f"      {runtime}->realize_reference == 0 ||",
        f"      {runtime}->resolve_reference({runtime}->context, UINT32_C({address}),",
        f"          UINT32_C({extent}), UINT32_C({permissions}), {selector}, 0U, 0U,",
        f"          &{name}_reference) != SPX_BOUNDARY_OK ||",
        f"      {name}_reference.object == 0U ||",
        f"      {name}_reference.offset > {name}_reference.extent ||",
        f"      UINT64_C({extent}) > {name}_reference.extent - {name}_reference.offset ||",
        f"      ({name}_reference.permissions & UINT32_C({permissions})) != UINT32_C({permissions}))",
        f"    {failure}",
        f"  const spx_view_v5 {name}_input = {{",
        f"    .base = {{ {name}_reference.domain, {name}_reference.object,",
        f"      {name}_reference.generation, {name}_reference.offset,",
        f"      {name}_reference.extent, {name}_reference.permissions }},",
        f"    .extent = UINT64_C({extent}), .element_width = 1U, .access_context = {runtime},",
        f"    .read = {'spx_component_result_view_read' if permissions & 1 else '0'},",
        f"    .write = {'spx_component_result_view_write' if permissions & 2 else '0'}",
        "  };",
        f"  {context}.state.{_c(item.value.identity)} = {name}_input;",
    ]


def _preserved_view_lines(*, expression, original, name, runtime, permissions, address,
                          failure="return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"):
    # Compare fields, never struct padding. Then check current lifetime and the
    # exact physical binding again, without resetting or copying any bytes.
    fields = ("base.domain", "base.object", "base.generation", "base.offset",
              "base.extent", "base.permissions", "extent", "element_width",
              "context", "read_u8", "write_u8", "access_context", "read", "write")
    return [
        f"  if ({' || '.join(f'{expression}.{field} != {original}.{field}' for field in fields)})",
        f"    {failure}",
        f"  spx_machine_reference_v1 {name}_reference = {{",
        f"    {expression}.base.domain, {expression}.base.object, {expression}.base.generation,",
        f"    {expression}.base.offset, {expression}.base.extent, {expression}.base.permissions",
        "  };",
        f"  uint32_t {name}_word = 0U;",
        f"  if ({runtime} == 0 || {runtime}->realize_reference == 0 ||",
        f"      {runtime}->realize_reference({runtime}->context, &{name}_reference,",
        f"          UINT32_C({permissions}), 0U, 0U, &{name}_word) != SPX_BOUNDARY_OK ||",
        f"      {name}_word != UINT32_C({address}))",
        f"    {failure}",
    ]


def state_view_export_lines(*, bundle, state_projections, context, runtime, **kwargs):
    lines = []
    for item in bundle.interface.state:
        _, _, permissions, address = checked_state_view(bundle, item, state_projections[item.value.identity])
        name = f"component_state_{_c(item.value.identity)}"
        lines.extend(_preserved_view_lines(
            expression=f"{context}.state.{_c(item.value.identity)}", original=f"{name}_input",
            name=f"{name}_output", runtime=runtime, permissions=permissions, address=address, **kwargs,
        ))
    return lines


def checked_state_view_result(*, bundle, value, projection, state_projections):
    """Select the unique shared view whose full descriptor guards the result."""
    row = MachineProjectionV1.parse(projection, "shared state result view").to_payload()
    if (row.get("kind") != "view" or row.get("at") != "exit" or
            row.get("base") != {"kind": "register", "register": "eax", "width": 32, "at": "exit"}):
        raise BoundaryModelError("shared state result view requires an EAX exit binding")
    matches = []
    for item in bundle.interface.state:
        if item.value.interpretation != "view":
            continue
        entry, extent, permissions, address = checked_state_view(bundle, item, state_projections[item.value.identity])
        if (entry["authority"] == row.get("authority") and entry["extent"] == row.get("extent") and
                entry["requested_extent"] == row.get("requested_extent") and
                item.value.type_id == value.type_id and item.value.interpretation == value.interpretation and
                item.value.access == value.access and item.value.extent == value.extent and
                item.value.nullable == value.nullable):
            matches.append((item, permissions, address))
    if len(matches) != 1:
        raise BoundaryModelError("shared state result view requires one exact matching state binding")
    return matches[0]


def state_view_result_lines(*, bundle, value, projection, state_projections, runtime, **kwargs):
    """Encode a returned fixed view bound to exactly one shared-state view.

    The matching image authority and extent select the explicit fixed binding.
    Runtime checks enforce the full descriptor relation, not just equal addresses.
    They remain obligations of the paired proof, not a source-summary theorem.
    """
    item, permissions, address = checked_state_view_result(
        bundle=bundle, value=value, projection=projection, state_projections=state_projections)
    return _preserved_view_lines(
        expression="logical_result", original=f"component_state_{_c(item.value.identity)}_input",
        name="logical_result", runtime=runtime, permissions=permissions, address=address, **kwargs,
    )
