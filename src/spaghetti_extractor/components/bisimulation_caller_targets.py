"""Captured external target transport for conditional public caller proofs.

Use the existing typed target projection rules. Equality of code words is not
loader/import authority; the enclosing runtime premise remains unverified.
"""
from .bisimulation_service_targets import checked_typed_external_target
from .machine_binding import external_target_sampling


def target_projection(value):
    if value is None:
        raise ValueError('caller target: captured projection is absent')
    return checked_typed_external_target({'provider_kind': 'external_call',
                                         'captured_target_projection': value})


def captured_call_target(call, premise):
    projection = premise.get('captured_target_projection')
    indirect = call['event']['kind'] == 'indirect'
    if indirect != (projection is not None):
        raise ValueError('caller target: an indirect runtime call needs its captured target projection')
    if not indirect:
        if 'target_sampling' in premise:
            raise ValueError('caller target: sampling needs an indirect captured target')
        return None
    value = target_projection(projection)
    call['captured_target_projection'] = value
    sampling = external_target_sampling(premise.get('target_sampling', 'service_call'), has_target=True)
    if 'target_sampling' in premise:
        call['target_sampling'] = sampling
    return value


def native_target_lines(projection, *, sampling='service_call', index=None):
    projection = target_projection(projection)
    external_target_sampling(sampling, has_target=True)
    if sampling == 'operation_entry':
        if type(index) is not int or index < 0:
            raise ValueError('caller target: entry snapshot needs a service index')
        lines = [f'uint32_t captured_target=captured_entry_targets[{index}];']
    elif projection['kind'] == 'register':
        lines = [f'uint32_t captured_target=m->entry->{projection["register"]};']
    else:
        lines = [f'uint64_t target_address=(uint64_t)rt->image_base+{projection["rva"]}U;',
            '__CPROVER_assert(target_address<=UINT64_C(4294967292),"spx-native-target-slot-range");',
            'spx_caller_public_span(&m->memory,(uint32_t)target_address,4U);',
            'uint32_t target_fault=0U;',
            'uint32_t captured_target=spx_caller_read(&m->memory,(uint32_t)target_address,4U,&target_fault);',
            '__CPROVER_assert(target_fault==0U,"spx-native-target-slot-readable");']
    return [*lines,
        '__CPROVER_assert(captured_target!=0U && ev->target_rva==captured_target,"spx-native-captured-target");',
        'm->env->native_target=ev->target_rva;']


def entry_target_lines(projection, *, sampling, index, image_base):
    projection = target_projection(projection)
    external_target_sampling(sampling, has_target=True)
    if projection['kind'] == 'register':
        return [f'captured_entry_targets[{index}]=initial.{projection["register"]};']
    if sampling != 'operation_entry':
        return []
    address = image_base + projection['rva']
    if address > 0xfffffffc:
        raise ValueError('caller target: image target slot wraps')
    return ['{', f'spx_caller_public_span(&m.memory,{address}U,4U);', 'uint32_t target_fault=0U;',
            f'captured_entry_targets[{index}]=spx_caller_read(&m.memory,{address}U,4U,&target_fault);',
            '__CPROVER_assert(target_fault==0U,"spx-entry-target-slot-readable");', '}']


def source_target_lines(projection, *, index, image_base, sampling='service_call'):
    """Read the source side's actual current slot, or its private entry snapshot."""
    projection = target_projection(projection)
    external_target_sampling(sampling, has_target=True)
    if projection['kind'] == 'register' or sampling == 'operation_entry':
        return [f'uint32_t source_target=captured_entry_targets[{index}];']
    address = image_base + projection['rva']
    if address > 0xfffffffc:
        raise ValueError('caller target: image target slot wraps')
    expression = ' | '.join(f'((uint32_t)spx_mutable_byte(e->world,{address+i}U)<<{8*i}U)' for i in range(4))
    return [f'uint32_t source_target={expression};']
