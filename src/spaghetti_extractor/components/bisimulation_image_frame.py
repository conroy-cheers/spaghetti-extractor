"""Checked image/private access locality for extending a supplier's world.

This is a necessary frame premise, not allocation admission. Consumers must
also check a disjoint extension of the reference world and preserve its contents,
origins and lifetime history. The ordinary empty-world proof alone cannot do so.
"""

from .bisimulation_exact_frame import (
    PhysicalFrameSpec, MUTABLE_ACTIVE, run_physical_frame_probe, validate_physical_frame,
)
from . import bisimulation_private_frame as private_frame
from dataclasses import replace

FRAME = PhysicalFrameSpec('image_private_access_frame', 'paired-image-private-access-frame-wide-v1',
    '__CPROVER_spx_image_private_access', 'spx-bisimulation-image-private-access-frame',
    '__CPROVER_spx_image_private_access_probe_', 'image-private-access-frame')
ACTIVE = '__CPROVER_spx_image_private_access_active'


def parse_accesses(value):
    if value is None:
        return None
    try:
        return private_frame.parse_stack_writes(value)
    except ValueError as error:
        raise ValueError(str(error).replace('stack write', 'stack access')) from error


def frame_spec(ranges=None):
    if ranges is None:
        return FRAME
    return replace(FRAME, policy='paired-image-private-access-footprint-v1',
        description=FRAME.description + ':' + (private_frame.suffix(ranges) or 'empty'))


def _merged_ranges(ranges):
    result = []
    for offset, size in ranges:
        if result and result[-1][0] + result[-1][1] == offset:
            previous, width = result.pop()
            result.append((previous, width + size))
        else:
            result.append((offset, size))
    return result


def candidate(*, interface, mutable_views, connected, authority, allocations):
    """Select a supplementary probe, without granting a composition rule."""
    return bool(interface.state and mutable_views and not connected and allocations is None
        and authority is not None and authority['rules'] and not authority.get('data_export_anchors')
        and all(row['kind'] == 'image' and row['lifetime'] == 'image'
                and row['locator']['kind'] == 'image_rva' for row in authority['rules']))


def declarations(enabled, image_size, ranges=None):
    if not enabled:
        return ''
    if type(image_size) is not int or image_size <= 0:
        raise ValueError('image/private frame requires a checked image extent')
    spec = frame_spec(ranges)
    private = '((uint64_t)address >= world->private_low && end <= world->private_high)'
    if ranges is not None:
        spans = [f'((int64_t)address >= (int64_t)world->private_anchor + INT64_C({offset}) && '
                 f'(int64_t)end <= (int64_t)world->private_anchor + INT64_C({offset + size}))'
                 for offset, size in _merged_ranges(ranges)]
        private = '(' + private + ' && (' + (' || '.join(spans) or '0U') + '))'
    return f'''
static uint32_t {ACTIVE};
void {FRAME.guard}(uint32_t permitted) {{
  __CPROVER_assert({ACTIVE} == 0U || permitted, "{spec.description}");
}}
static uint32_t spx_proof_image_private_span(
    const spx_proof_world *world, uint32_t address, uint64_t extent) {{
  uint64_t end = (uint64_t)address + extent;
  if (world != &spx_exact_world && world != &spx_source_world) return 0U;
  if (extent > UINT64_C(4294967296) - address) return 0U;
  if (extent == 0U) return 1U;
  return ((uint64_t)address >= SPX_PROOF_IMAGE_BASE &&
      end <= (uint64_t)SPX_PROOF_IMAGE_BASE + UINT64_C({image_size})) ||
      {private};
}}
'''


def access_check(enabled, *, world='world', address='address', extent='width'):
    return (f'  {FRAME.guard}(spx_proof_image_private_span({world}, {address}, {extent}));\n'
            if enabled else '')


def probe_source(enabled, proof_function, private_stack_writes):
    if not enabled:
        return ''
    return f'''
void {FRAME.entry(proof_function)}(void) {{
  {ACTIVE} = 1U;
  {private_frame.activation(private_stack_writes)}{MUTABLE_ACTIVE} = 3U;
  {proof_function}();
}}
'''


def run_probe(*, entry, task, **kwargs):
    if entry.get('mutable_entry_contract', {}).get('result', {}).get('status') != 'satisfied':
        return {}
    return run_physical_frame_probe(spec=frame_spec(parse_accesses(task.get('private_stack_accesses'))),
        task=task, **kwargs)


def validate_frame(value, *, model, shard, **kwargs):
    spec = frame_spec(parse_accesses(model.get('private_stack_accesses')))
    if (shard.get('mutable_entry_contract', {}).get('result', {}).get('status') != 'satisfied'
            or spec.description not in model['required_assertion_descriptions']):
        raise ValueError('image/private access frame lacks its wider entry or required guard')
    validate_physical_frame(value, spec=spec, model=model, shard=shard, **kwargs)


def guarantee(proof, operation):
    """Derive locality only after ordinary proof and auxiliary validation."""
    shards = {(row['operation_id'], row['obligation_id']): row for row in proof['shards']}
    ranges = parse_accesses(operation.get('private_stack_accesses'))
    # A bounded footprint is anchored at a segment's entry. Moving that anchor
    # across internal cuts needs an additional transport theorem before the
    # whole callee may consume it. The first real supplier has one segment.
    if ranges is not None and len(operation['obligation_models']) != 1:
        return False
    return bool(operation['obligation_models']) and all(
        frame_spec(ranges).description in model['required_assertion_descriptions']
        and model.get('private_stack_accesses') == operation.get('private_stack_accesses')
        and shards[(operation['operation_id'], model['obligation_id'])].get(FRAME.field, {}).get(
            'result', {}).get('status') == 'satisfied'
        for model in operation['obligation_models'])


def consumer_private_ranges(operation, domain):
    """Return the checked footprint, or the original wide-window obligation."""
    ranges = parse_accesses(operation.get('private_stack_accesses'))
    if ranges is not None:
        return _merged_ranges(ranges)
    from .bisimulation_support import PROOF_PRIVATE_STACK_BELOW
    return [(-PROOF_PRIVATE_STACK_BELOW, PROOF_PRIVATE_STACK_BELOW + domain['private_high_offset'])]


def consumer_frame_checks(operation, domain, image):
    """Check every declared interval; a hole grants no private memory access."""
    ranges = consumer_private_ranges(operation, domain)
    lines = ['      uint32_t shared_entry = rt->resolve_reference != 0;']
    if not ranges:
        return lines + ['      shared_entry = shared_entry &&',
            f"          spx_proof_image_private_allocation_frame(&spx_exact_world, UINT32_C({image['preferred_base']}), "
            f"UINT64_C({image['image_size']}), UINT64_C(0), UINT64_C(0));"]
    for index, (offset, size) in enumerate(ranges):
        low, high = f'shared_private_low_{index}', f'shared_private_high_{index}'
        lines += [f'      int64_t {low} = (int64_t)call_state.esp + INT64_C({offset});',
                  f'      int64_t {high} = (int64_t)call_state.esp + INT64_C({offset + size});',
                  f'      if ({low} < 0) {low} = 0;', f'      if ({high} < 0) {high} = 0;',
                  f'      if ({low} > INT64_C(4294967296)) {low} = INT64_C(4294967296);',
                  f'      if ({high} > INT64_C(4294967296)) {high} = INT64_C(4294967296);',
                  '      shared_entry = shared_entry &&',
                  f"          spx_proof_image_private_allocation_frame(&spx_exact_world, UINT32_C({image['preferred_base']}), "
                  f"UINT64_C({image['image_size']}), (uint64_t){low}, (uint64_t){high});"]
    return lines


def checked_operations(proof, *, artifacts, runtime_assurance=None):
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(proof, runtime_assurance)
    from pathlib import Path
    shards = {(row['operation_id'], row['obligation_id']): row for row in proof['shards']}
    result = []
    for index, operation in enumerate(proof['models']['operation_models']):
        if not guarantee(proof, operation):
            continue
        for segment, model in enumerate(operation['obligation_models']):
            shard = shards[(operation['operation_id'], model['obligation_id'])]
            validate_frame(shard[FRAME.field], model=model, shard=shard, checker=proof['checker'], runtime_assurance=runtime_assurance,
                artifacts=Path(artifacts) / f'operation-{index:04d}-obligation-{segment:04d}')
        result.append(operation['operation_id'])
    return tuple(result)



def authority_extension(supplier, parent):
    """Keep image identities exact; additional classes must be unrelated heaps."""
    if not isinstance(parent, dict) or parent.get('data_export_anchors'):
        return False
    if any(parent.get(key) != supplier.get(key) for key in ('format', 'machine_backend', 'bindings')):
        return False
    required = {row['id']: row for row in supplier['rules']}
    actual = {row['id']: row for row in parent['rules']}
    if any(actual.get(identity) != rule for identity, rule in required.items()):
        return False
    image_objects = {(row['domain'], row['object']) for row in required.values()}
    return all(row['kind'] == 'external' and row['lifetime'] == 'allocation'
        and row['locator']['kind'] == 'external_allocation'
        and (row['domain'], row['object']) not in image_objects
        for identity, row in actual.items() if identity not in required)


def allocation_frame_source(capacity):
    """Use one universal index witness, without copying or expanding the heap.

    The caller asserts this predicate. A successful assertion covers every
    represented record, including dead ones; the witness is not a program input.
    The predicate neither clears history nor constructs allocation authority.
    """
    return f'''
static uint32_t spx_proof_image_private_allocation_frame(
    const spx_proof_world *world, uint32_t image_base, uint64_t image_size,
    uint64_t private_low, uint64_t private_high) {{
  uint32_t index = spx_nondet_u32();
  if (world != &spx_exact_world && world != &spx_source_world) return 0U;
  if (world->allocation_count > UINT32_C({capacity}) ||
      image_size > UINT64_C(4294967296) - image_base ||
      private_low > private_high || private_high > UINT64_C(4294967296)) return 0U;
  if (index >= world->allocation_count) return 1U;
  const spx_proof_allocation *allocation = &world->allocations[index];
  if (allocation->base == 0U || (uint64_t)allocation->base + allocation->size > UINT64_C(4294967296)) return 0U;
  return !spx_proof_allocation_overlap(allocation->base, allocation->size, image_base, image_size) &&
      !spx_proof_allocation_overlap(allocation->base, allocation->size, private_low, private_high - private_low);
}}
'''
