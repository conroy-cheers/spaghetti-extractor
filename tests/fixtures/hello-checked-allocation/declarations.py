"""One manual component owns eight allocation APIs and their shared terminal tail."""
from spaghetti_extractor.components.service_authoring import ServiceDefinition, OperationDefinition, component_interface

B, U = 'allocation_block', 'u32'
TYPES = [dict(id=B, kind='opaque', nominal_id='hello.allocation-block'),
         dict(id=U, kind='integer', width_bits=32, signed=False), dict(id='unit', kind='void')]
# Each row is a reviewed machine entry, exclusive end, supplier, and C signature.
OPERATIONS = {
    'allocate': (0x622d, 0x6241, 0x6628, [('bytes', U)]),
    'allocate_indexed': (0x6241, 0x6255, 0x6925, [('bytes', U)]),
    'resize': (0x6257, 0x6273, 0x8db8, [('block', B), ('bytes', U)]),
    'resize_indexed': (0x6273, 0x628f, 0x692a, [('block', B), ('bytes', U)]),
    'resize_array': (0x628f, 0x62b6, 0x8e10, [('block', B), ('count', U), ('width', U)]),
    'resize_array_indexed': (0x62b8, 0x62df, 0x6934, [('block', B), ('count', U), ('width', U)]),
    'allocate_zeroed': (0x6462, 0x6481, 0x65bc, [('count', U), ('width', U)]),
    'allocate_zeroed_indexed': (0x649c, 0x64bb, 0x692f, [('count', U), ('width', U)]),
}
ALIASES = {'allocate': [(0x6255, 0x6257)], 'resize_array': [(0x62b6, 0x62b8)]}
SHARED = (0x6220, 0x622d)


def boundary():
    services = {name: ServiceDefinition.create(identity='hello.checked.'+name,
        types=TYPES, parameters=params, result=B, resources=[], effects=['hello.checked.'+name],
        outcomes=['return'], nullable_parameters=['block'] if params[0][0] == 'block' else [],
        nullable_result=True, unobserved=[
            'Lower allocator contents, aliases, errno and lifetime are explicit executable adapter premises.'])
        for name, (_, _, _, params) in OPERATIONS.items()}
    services['allocation_failed'] = ServiceDefinition.create(identity='hello.checked.allocation_failed',
        types=TYPES, parameters=[], result='unit', resources=[], effects=['hello.checked.terminal'],
        outcomes=['return'], nonlocal_outcomes=['nomem'], unobserved=[
            'The admitted allocation-failure service never returns; a C handler observes its nonlocal delivery.',
            'Controlled failure delivery does not establish actual CRT process termination.'])
    operations = {name: OperationDefinition(parameters=params, result=B,
        allowed_services=[name, 'allocation_failed'],
        nullable_parameters=['block'] if params[0][0] == 'block' else [])
        for name, (_, _, _, params) in OPERATIONS.items()}
    return component_interface(component_id='checked-allocation', schema_id='checked-allocation',
        types=TYPES, operations=operations, services=services), services
