"""Allocation/release transitions in the existing paired call oracle.

Checked classes support local transitions without final native numbering.
Supplied native inventories additionally check numeric correspondence; normal
provider admission and runtime reference guards remain independent requirements.
"""

from ..external.lifetime_effects import LifetimeEffectError, checked_lifetime_effect as normalize_lifetime_effect
from .bisimulation_lifetime_namespace import checked_lifetime_transitions
from .bisimulation_support import BisimulationRefinementError


def checked_lifetime_effect(payload, *, argument_words):
    try:
        return normalize_lifetime_effect(payload, argument_words=argument_words)
    except LifetimeEffectError as exc:
        raise BisimulationRefinementError(f'proof {exc}') from exc


def allocation_call_fragments(*, specs, authority, inventory, capacity, requirements=None):
    empty = {key: '' for key in ('fields', 'declarations', 'helpers', 'typed_reset', 'typed_apply',
                                 'exact_apply', 'source_apply')}
    transitions = checked_lifetime_transitions(specs, authority=authority, inventory=inventory, requirements=requirements)
    if not transitions:
        return empty
    cases = []
    for transition in transitions:
        spec, effect, family = transition['spec'], transition['effect'], transition['family']
        owner_index = effect['ownership']['owner_argument']
        owner = 'UINT32_C(0)' if owner_index is None else f'call->arguments[{owner_index}]'
        spec_id = spec['spec_id']
        rows = [f'  if (call->spec == UINT32_C({spec_id})) {{']
        if effect['action'] == 'add_result_range':
            producer = transition['producer']
            policy = effect['allocation']
            for guard in policy['argument_masks']:
                condition = f'(call->arguments[{guard["argument_index"]}] & ~UINT32_C({guard["allowed_mask"]})) == UINT32_C(0)'
                rows += _assert(condition, 'allocation-argument-domain')
            if not effect['nullable']:
                rows += ['    if (recording) __CPROVER_assume(call->response_eax != UINT32_C(0));']
            rows += ['    if (call->response_eax == UINT32_C(0)) return;']
            left, right = effect['size_argument'], effect['size_right_argument']
            size = (f'UINT64_C({effect["size_value"]})' if effect['size_kind'] == 'fixed' else
                    f'(uint64_t)call->arguments[{left}] * UINT64_C({effect["size_value"]})' if effect['size_kind'] == 'argument'
                    else f'(uint64_t)call->arguments[{left}] * (uint64_t)call->arguments[{right}]')
            rows += [f'    uint64_t size = {size};']
            rows += _assert(f'size <= UINT64_C(4294967295) && size >= UINT64_C({effect["minimum_size"]})', 'allocation-size')
            rows += _assert(f'world->allocation_count < UINT32_C({capacity})', 'allocation-capacity')
            # The checked native range namespace requires a representable
            # one-past address. This constrains the environment's fresh result;
            # size/capacity and caller-domain obligations above remain assertions.
            rows += ['    if (recording) __CPROVER_assume(call->response_eax <= UINT32_MAX - (uint32_t)size);']
            init = policy['initialization']
            zero = ('UINT32_C(1)' if init['kind'] == 'zero' else 'UINT32_C(0)' if init['kind'] == 'uninitialized' else
                    f'((call->arguments[{init["argument_index"]}] & UINT32_C({init["mask"]})) != UINT32_C(0))')
            rows += [f'    spx_boundary_status status = spx_proof_allocate(world, call->response_eax, (uint32_t)size, UINT32_C({family}), {owner}, {zero});',
                     # Freshness constrains the allocator response, not its caller inputs or model capacity.
                     '    if (recording) __CPROVER_assume(status == SPX_BOUNDARY_OK);']
            rows += _assert('status == SPX_BOUNDARY_OK', 'allocation-response')
            rows += ['    if (recording) {', '      call->allocation_generation = spx_nondet_nonzero_u32();']
            for index in range(capacity):
                rows += [f'      __CPROVER_assume(world->allocation_count <= UINT32_C({index}) ||',
                         f'          world->allocations[{index}].native_generation != call->allocation_generation);']
            rows += ['    }', f'    status = spx_proof_bind_allocation_authority(world, call->response_eax, (uint32_t)size,',
                     f'        UINT32_C({producer["family"]}), {owner}, UINT32_C({producer["selector"]}),',
                     f'        UINT64_C({producer["object"]}), call->allocation_generation);']
            rows += _assert('status == SPX_BOUNDARY_OK', 'allocation-class-binding')
            # Only the checked allocating transition establishes local origin.
            # Bare allocation/binding helpers cannot qualify incoming objects.
            rows += ['    world->allocations[world->allocation_count - UINT32_C(1)].birth_class_selector =',
                     '        world->allocations[world->allocation_count - UINT32_C(1)].native_rule_selector;']
        else:
            release = effect['release']
            for guard in release['argument_equals']:
                rows += _assert(f'call->arguments[{guard["argument_index"]}] == UINT32_C({guard["value"]})', 'release-argument-domain')
            success = {'always': 'UINT32_C(1)', 'eax_zero': '(call->response_eax == UINT32_C(0))',
                       'eax_nonzero': '(call->response_eax != UINT32_C(0))'}[release['success']]
            rows += [f'    spx_boundary_status status = spx_proof_release_allocation(world, call->arguments[{effect["argument"]}],',
                     f'        UINT32_C({family}), {owner}, {success});']
            rows += _assert('status == SPX_BOUNDARY_OK', 'release-live-owner')
        rows += ['    return;', '  }']
        # Repeated exact sites share one behavior and transition, but every site was checked above.
        if not any(previous[0] == spec_id for previous in cases):
            cases.append((spec_id, '\n'.join(rows)))
    helper = '''
static void spx_proof_apply_lifetime_call(spx_proof_world *world, spx_proof_call *call, uint32_t recording) {
''' + '\n'.join(body for _, body in cases) + '''
}
static void spx_proof_typed_apply_lifetime(void) {
  if (spx_proof_typed_lifetime_applied) return;
  spx_proof_call *call = &spx_exact_world.calls[spx_proof_typed_call_position];
  if (!spx_proof_typed_recording) {
    __CPROVER_assert(spx_proof_typed_call_matches, "spx-bisimulation-lifetime-typed-arguments");
    __CPROVER_assume(spx_proof_typed_call_matches);
  }
  spx_proof_apply_lifetime_call(spx_proof_typed_recording ? &spx_exact_world : &spx_source_world,
      call, spx_proof_typed_recording);
  spx_proof_typed_lifetime_applied = UINT32_C(1);
}
'''
    return {'fields': '  uint32_t allocation_generation;',
            'declarations': '''static uint32_t spx_proof_typed_lifetime_applied;
static void spx_proof_apply_lifetime_call(spx_proof_world *, spx_proof_call *, uint32_t);
static void spx_proof_typed_apply_lifetime(void);''',
            'helpers': helper,
            'typed_reset': '  spx_proof_typed_lifetime_applied = UINT32_C(0);',
            'typed_apply': '  spx_proof_typed_apply_lifetime();',
            'exact_apply': '    spx_proof_apply_lifetime_call(&spx_exact_world, call, UINT32_C(1));',
            'source_apply': '    spx_proof_apply_lifetime_call(&spx_source_world, call, UINT32_C(0));'}


def _assert(condition, diagnostic):
    return [f'    __CPROVER_assert({condition}, "spx-bisimulation-lifetime-{diagnostic}");',
            f'    __CPROVER_assume({condition});']
