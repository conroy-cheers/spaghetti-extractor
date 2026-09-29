"""A manual contract for the complete PE32 xpalloc operation, not a heap proof."""
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface

B, C, U = 'allocation_block', 'allocation_count', 'u32'
TYPES = [dict(id=B, kind='opaque', nominal_id='hello.allocation-block'),
         dict(id=C, kind='opaque', nominal_id='hello.allocation-count'),
         dict(id=U, kind='integer', width_bits=32, signed=False),
         dict(id='unit', kind='void')]
PARAMETERS = [('block', B), ('count', C), ('additional', U), ('maximum', U), ('width', U)]


def boundary():
    services = {name: ServiceDefinition.create(identity='hello.allocation.'+name,
        types=TYPES, parameters=params, result=result, resources=[],
        effects=['hello.allocation.'+name], outcomes=['return'], nonlocal_outcomes=['nomem'],
        nullable_parameters=['block'] if name == 'resize' else [],
        unobserved=['Live block/count correspondence and resize contents/lifetimes are adapter premises.',
            'A nonreturning allocation failure is transported by a C handler; actual CRT termination and native admission remain unverified.'])
        for name, params, result in [('resize', [('block', B), ('bytes', U)], B),
                                    ('allocation_failed', [('published_count', U)], 'unit')]}
    interface = component_interface(component_id='allocation-grow', types=TYPES,
        parameters=PARAMETERS, result=B, services=services, nullable_parameters=['block'])
    return interface, services
