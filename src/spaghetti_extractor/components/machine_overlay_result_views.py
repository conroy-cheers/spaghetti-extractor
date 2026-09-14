"""Returned byte views use live reference resolution, without stack-local contexts."""

from collections.abc import Mapping

from ..boundary._canonical import BoundaryModelError
from .component_c_v5 import _c
from .machine_binding import MachineProjectionV1
from .machine_overlay_boundaries_v5 import authority_selector_expression


def result_view_runtime_helpers(*, proof_codec_symbol=None, input_view_decoder=False, input_reference_encoder=False) -> list[str]:
    """Use the same callbacks in production and proof overlays.

    The access context is the enclosing runtime, not a cached allocation address.
    Copies of a view therefore retain their own reference generation and cannot
    become live again when an allocator reuses the original address.
    """
    from .bisimulation_runtime_dispatch import conditional_write_call
    source = '''
static uint32_t spx_component_result_view_address(
    spx_runtime *runtime, spx_ref_v5 base, uint64_t offset,
    uint32_t width, uint32_t permissions, uint32_t *address) {
  if (runtime == 0 || runtime->realize_reference == 0 || address == 0 ||
      (width != 1U && width != 2U && width != 4U) ||
      base.offset > base.extent || offset > base.extent - base.offset ||
      (uint64_t)width > base.extent - base.offset - offset)
    return 1U;
  spx_machine_reference_v1 reference = {
    base.domain, base.object, base.generation, base.offset + offset,
    base.extent, base.permissions
  };
  if (runtime->realize_reference(runtime->context, &reference, permissions,
          0U, 0U, address) != SPX_BOUNDARY_OK ||
      (uint64_t)*address + width > UINT64_C(4294967296))
    return 1U;
  return 0U;
}

static uint32_t spx_component_result_view_read(
    void *opaque, spx_ref_v5 base, uint64_t offset, uint32_t width,
    uint64_t *result) {
  spx_runtime *runtime = (spx_runtime *)opaque;
  uint32_t address = 0U, fault = 0U;
  if (result == 0 || runtime == 0 || runtime->read == 0 ||
      spx_component_result_view_address(runtime, base, offset, width, 1U, &address))
    return 1U;
  uint32_t value = runtime->read(runtime->context, address, width, &fault);
  if (fault != 0U) return 1U;
  *result = value;
  return 0U;
}

static uint32_t spx_component_result_view_write(
    void *opaque, spx_ref_v5 base, uint64_t offset, uint32_t width,
    uint64_t value) {
  spx_runtime *runtime = (spx_runtime *)opaque;
  uint32_t address = 0U, fault = 0U;
  if (runtime == 0 || runtime->write == 0 ||
      spx_component_result_view_address(runtime, base, offset, width, 2U, &address))
    return 1U;
''' + conditional_write_call() + '''
  return fault == 0U ? 0U : 1U;
}
'''
    if input_view_decoder:
        source += _input_view_decoder_source()
    if input_reference_encoder:
        source += _input_reference_encoder_source()
    if proof_codec_symbol is not None:
        source += _proof_view_codec(proof_codec_symbol)
    return source.splitlines()


def _input_view_decoder_source():
    """Import a nullable remaining-origin input without inventing an extent.

    The pointer's storage must have been read successfully before this call.
    Null describes an empty view, not permission to access address zero. Live
    inputs use the same generation-checking accessors as allocator results.
    """
    return '''
static uint32_t spx_component_input_view_decode(
    spx_runtime *runtime, uint32_t address, uint32_t requested,
    uint32_t permissions, const char *selector, spx_view_v5 *view) {
  if (runtime == 0 || runtime->resolve_reference == 0 || view == 0 ||
      permissions == 0U || permissions > 3U)
    return 1U;
  spx_machine_reference_v1 reference = {0};
  if (runtime->resolve_reference(runtime->context, address, requested,
          permissions, selector, 1U, 0U, &reference) != SPX_BOUNDARY_OK ||
      reference.offset > reference.extent)
    return 1U;
  if (reference.object == 0U) {
    if (address != 0U || reference.domain != 0U || reference.generation != 0U ||
        reference.offset != 0U || reference.extent != 0U || reference.permissions != 0U)
      return 1U;
    *view = (spx_view_v5){0};
    return 0U;
  }
  *view = (spx_view_v5){
    .base = {reference.domain, reference.object, reference.generation,
        reference.offset, reference.extent, reference.permissions},
    .extent = reference.extent - reference.offset, .element_width = 1U,
    .access_context = runtime,
    .read = (permissions & 1U) ? spx_component_result_view_read : 0,
    .write = (permissions & 2U) ? spx_component_result_view_write : 0 };
  return 0U;
}
'''


def checked_nullable_input_projection(projection):
    """Validate the projection shared by native decoding and paired input setup."""
    row = MachineProjectionV1.parse(projection, 'nullable input view').payload
    requested = row.get('requested_extent', {})
    base = row.get('base', {})
    if (row['kind'] != 'view' or row['at'] != 'entry' or
            row['extent'] != {'kind': 'origin_remainder'} or
            requested.get('kind') != 'constant' or requested.get('width') != 32 or
            base.get('kind') not in {'constant', 'register', 'stack'} or base.get('width') != 32 or
            (base['kind'] != 'constant' and base.get('at') != 'entry')):
        raise BoundaryModelError('nullable input view needs an explicit origin-remainder input contract')
    return row


def parameter_exit_projections(operation):
    """Canonical declared destinations; they do not establish a postcondition."""
    from .machine_binding import LogicalMachineValueV1
    result = []
    for row in operation.get('parameters', []):
        if 'exit_projection' not in row:
            continue
        value = LogicalMachineValueV1.parse(row, 'parameter exit transport')
        result.append({'id': value.identity, 'projection': value.exit_projection.to_payload()})
    registers = [row['projection']['register'] for row in result]
    if len(registers) != len(set(registers)):
        raise BoundaryModelError('parameter exit destinations overlap')
    return sorted(result, key=lambda row: row['id'])


def validate_parameter_exit_model(exits, model):
    if not isinstance(exits, list):
        raise ValueError('parameter exit projection inventory is malformed')
    for row in exits:
        if (not isinstance(row, Mapping) or set(row) != {'id', 'projection'} or
                not isinstance(row['id'], str) or not row['id']):
            raise ValueError('parameter exit projection inventory is malformed')
        target = MachineProjectionV1.parse(row['projection'], 'parameter exit projection').payload
        if (target['kind'] != 'register' or target['at'] != 'exit' or target['width'] != 32 or
                target['register'] not in {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'}):
            raise ValueError('parameter exit projection is unsupported')
        required = f"spx-bisimulation-exit-observable:{model['operation_id']}:parameter:{row['id']}"
        if required not in model['required_assertion_descriptions']:
            raise ValueError('parameter exit transport lacks its checked machine output')
    if ([row['id'] for row in exits] != sorted({row['id'] for row in exits}) or
            len({row['projection']['register'] for row in exits}) != len(exits)):
        raise ValueError('parameter exit projection inventory is duplicated')


def checked_parameter_exit_transports(bundle, signature, operation):
    """Bind machine outputs to existing input values without changing the C API."""
    exits = parameter_exit_projections(operation)
    if not exits:
        return []
    values = {value.identity: value for value in signature.parameters}
    types = bundle.intent.schema.type_index
    occupied = set()

    def registers(value):
        if isinstance(value, Mapping):
            if value.get('kind') == 'register':
                occupied.add(value['register'])
            for child in value.values():
                registers(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                registers(child)

    for row in operation.get('results', []):
        if row['projection']['kind'] not in {'register', 'stack'}:
            raise BoundaryModelError('parameter exit transport requires ordinary scalar result storage')
        registers(row['projection'])
    for row in operation.get('state', []):
        registers(row['exit'])
    for row in exits:
        value = values.get(row['id'])
        if (value is None or value.interpretation != 'view' or not value.nullable or
                value.extent['kind'] != 'none' or value.access not in {'read', 'write', 'read_write'}):
            raise BoundaryModelError('parameter exit transport requires a nullable remaining-origin byte input')
        node = types[value.type_id]
        element = types[str(node.body['pointee_type_id'])]
        if element.kind != 'integer' or element.body['width_bits'] != 8 or element.body['signed']:
            raise BoundaryModelError('parameter exit transport requires byte elements')
        if row['projection']['register'] in occupied:
            raise BoundaryModelError('parameter exit destination overlaps result or state storage')
        row['permissions'] = {'read': 1, 'write': 2, 'read_write': 3}[value.access]
    return exits


def parameter_exit_snapshots(exits):
    return [f"  const spx_ref_v5 saved_reference_{_c(row['id'])} = argument_{_c(row['id'])}_view.base;"
            for row in exits]


def parameter_exit_encoding(exits):
    # Validate every saved origin before publishing any parameter machine output.
    return [line for row in exits for line in (
        f"  uint32_t parameter_exit_{_c(row['id'])} = 0U;",
        f"  if (spx_component_input_reference_address(rt, saved_reference_{_c(row['id'])},",
        f"          UINT32_C({row['permissions']}), &parameter_exit_{_c(row['id'])}))",
        '    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };')]


def parameter_exit_stores(exits):
    return [f"  state->{row['projection']['register']} = parameter_exit_{_c(row['id'])};" for row in exits]


def _input_reference_encoder_source():
    """Encode the original borrowed input reference, checking its live generation.

    No contents are reconstructed or granted by this operation. The saved input
    value is independent of descriptor mutations in the authored function.
    """
    return '''
static uint32_t spx_component_input_reference_address(
    spx_runtime *runtime, spx_ref_v5 input, uint32_t permissions, uint32_t *address) {
  if (address == 0 || permissions == 0U || permissions > 3U)
    return 1U;
  if (input.object == 0U) {
    if (input.domain != 0U || input.generation != 0U || input.offset != 0U ||
        input.extent != 0U || input.permissions != 0U)
      return 1U;
    *address = 0U;
    return 0U;
  }
  if (runtime == 0 || runtime->realize_reference == 0 || input.offset > input.extent)
    return 1U;
  spx_machine_reference_v1 reference = {input.domain, input.object, input.generation,
      input.offset, input.extent, input.permissions};
  if (runtime->realize_reference(runtime->context, &reference, permissions,
          0U, 0U, address) != SPX_BOUNDARY_OK || *address == 0U)
    return 1U;
  return 0U;
}
'''


def nullable_input_view_lines(*, value, projection, name, address, selector):
    """The admitted initial scope is a byte view of the resolved remainder."""
    row = checked_nullable_input_projection(projection)
    requested = row['requested_extent']
    if value.extent['kind'] != 'none':
        raise BoundaryModelError('nullable input view needs an explicit origin-remainder input contract')
    permissions = {'read': 1, 'write': 2, 'read_write': 3}.get(value.access)
    if permissions is None:
        raise BoundaryModelError('nullable input view access is unsupported')
    return [
        f'  uint32_t {name}_address = (uint32_t)({address});',
        # A failed pointer-word read returning zero must not become a null view.
        '  if (memory_fault != 0U)',
        '    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };',
        f'  spx_view_v5 {name}_view = {{0}};',
        f'  if (spx_component_input_view_decode(rt, {name}_address,',
        f'          UINT32_C({requested["value"]}), UINT32_C({permissions}), {selector}, &{name}_view))',
        '    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };',
    ]


def _proof_view_codec(symbol):
    """A proof-only observer/constructor in the actual accessor translation unit."""
    import re
    if re.fullmatch(r"__CPROVER_spx_[A-Za-z_][A-Za-z0-9_]*_local_view_codec", symbol) is None:
        raise BoundaryModelError("local view proof codec symbol is malformed")
    fields = ("base.domain", "base.object", "base.generation", "base.offset", "base.extent",
              "base.permissions", "extent", "element_width", "context", "access_context",
              "read_u8", "write_u8", "read", "write")
    equal = " &&\n      ".join(f"view->{field} == expected.{field}" for field in fields)
    restore = "\n    ".join(f"view->{field} = expected.{field};" for field in fields)
    return f'''
/* Mode 2 is the cut's assumed restoration, not an ordinary constructor.
   Stop its rejected paths before merging havoced callback fields back into
   the caller. Modes 0 and 1 must keep reporting failure to their observers. */
static uint32_t {symbol}_reject(uint32_t construct) {{
  if (construct == 2U) __CPROVER_assume(0);
  return 0U;
}}
uint32_t {symbol}(spx_runtime *runtime, spx_view_v5 *view,
    uint32_t address, uint32_t requested, uint64_t visible,
    uint32_t permissions, const char *selector, uint32_t nullable, uint32_t construct) {{
  if (runtime == 0 || runtime->resolve_reference == 0 || view == 0 ||
      permissions == 0U || permissions > 3U || nullable > 1U || construct > 2U)
    return {symbol}_reject(construct);
  spx_machine_reference_v1 reference = {{0}};
  if (runtime->resolve_reference(runtime->context, address, requested, permissions,
          selector, nullable, 0U, &reference) != SPX_BOUNDARY_OK ||
      reference.offset > reference.extent)
    return {symbol}_reject(construct);
  spx_view_v5 expected = {{0}};
  if (reference.object != 0U) {{
    uint64_t remainder = reference.extent - reference.offset;
    if (visible == UINT64_MAX) visible = remainder;
    if (visible > remainder) return {symbol}_reject(construct);
    expected = (spx_view_v5){{
      .base = {{reference.domain, reference.object, reference.generation,
          reference.offset, reference.extent, reference.permissions}},
      .extent = visible, .element_width = 1U, .access_context = runtime,
      .read = (permissions & 1U) ? spx_component_result_view_read : 0,
      .write = (permissions & 2U) ? spx_component_result_view_write : 0 }};
  }}
  /* The cut havocs the complete local object first. Assign fields separately
     so padding remains arbitrary rather than acquiring an invented value. */
  if (construct) {{
    {restore}
    return 1U;
  }}
  return {equal};
}}
'''


def result_view_lines(*, signature, types, projection, authority_selectors,
                      runtime, result_word, failure, finish=()):
    """Decode a whole-origin byte view with its declared fixed/value extent.

    This deliberately does not construct an access context whose lifetime ends
    at the service return, or borrow accessors from an unrelated input view.
    """
    if len(signature.results) != 1:
        raise BoundaryModelError('external service view requires one result')
    result = signature.results[0]
    pointer = types[result.type_id]
    element = types.get(pointer.body.get('pointee_type_id'))
    if (result.interpretation != 'view' or pointer.kind != 'pointer' or
            element is None or element.kind != 'integer' or element.body.get('width_bits') != 8):
        raise BoundaryModelError('external service result view requires byte elements')
    row = MachineProjectionV1.parse(projection, 'external service result view').to_payload()
    if (row['kind'] != 'view' or row['at'] != 'call' or
            row['base'] != {'kind': 'register', 'register': 'eax', 'width': 32, 'at': 'call'} or
            row['extent'] != {'kind': 'origin_remainder'} or
            row['requested_extent'].get('kind') != 'constant'):
        raise BoundaryModelError('external service result view requires a checked EAX origin remainder')
    requested = row['requested_extent']['value']
    permissions = {'read': 1, 'write': 2, 'read_write': 3}.get(result.access)
    if permissions is None or not 0 <= requested <= 0xffffffff:
        raise BoundaryModelError('external service result view access or extent is unsupported')
    extent = result.extent
    if extent['kind'] == 'fixed':
        expected = f"UINT64_C({extent['bytes']})"
    elif extent['kind'] == 'value':
        parameter = next((item for item in signature.parameters if item.identity == extent['value_id']), None)
        scalar = None if parameter is None else types[parameter.type_id]
        if (parameter is None or parameter.interpretation != 'value' or scalar.kind != 'integer' or
                scalar.body.get('signed') is not False or scalar.body.get('width_bits') not in {8, 16, 32}):
            raise BoundaryModelError('external service result view extent requires an unsigned scalar argument')
        expected = f'(uint64_t)logical_{_c(parameter.identity)}'
    else:
        raise BoundaryModelError('external service result view requires a fixed or argument extent')
    selector = authority_selector_expression(row, authority_selectors)
    # A live empty allocation has an identity but no interior byte. Only an
    # explicitly zero-byte projection of an empty result may resolve its end
    # reference. The accessors still require a nonempty span and recheck life.
    one_past = f'(uint32_t)({expected} == UINT64_C(0))' if requested == 0 else 'UINT32_C(0)'
    return [
        '  spx_machine_reference_v1 service_result_reference = {0};',
        f'  if ({runtime}->resolve_reference == 0 ||',
        f'      {runtime}->resolve_reference({runtime}->context, {result_word},',
        f'          UINT32_C({requested}), UINT32_C({permissions}), {selector},',
        f'          UINT32_C({int(result.nullable)}), {one_past}, &service_result_reference) != SPX_BOUNDARY_OK ||',
        '      service_result_reference.offset > service_result_reference.extent) {',
        *failure, '  }',
        '  if (service_result_reference.object == UINT64_C(0)) {',
        *finish, '    return (spx_view_v5){0};', '  }',
        '  uint64_t service_result_extent = service_result_reference.extent - service_result_reference.offset;',
        f'  if (service_result_extent != {expected}) {{', *failure, '  }',
        *finish,
        '  return (spx_view_v5){',
        '    .base = { service_result_reference.domain, service_result_reference.object,',
        '      service_result_reference.generation, service_result_reference.offset,',
        '      service_result_reference.extent, service_result_reference.permissions },',
        '    .extent = service_result_extent, .element_width = UINT32_C(1),',
        f'    .access_context = {runtime},',
        f"    .read = {'spx_component_result_view_read' if permissions & 1 else '0'},",
        f"    .write = {'spx_component_result_view_write' if permissions & 2 else '0'}",
        '  };',
    ]


def uses_result_views(bindings):
    return any(isinstance(row.get('result_projection'), Mapping) and
               row['result_projection'].get('kind') == 'view' for row in bindings)
