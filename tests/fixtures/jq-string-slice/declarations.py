"""String ownership and borrowed contents, using existing jq value transport."""
import copy
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface
from spaghetti_extractor.components.resource_authoring import component_resource_checks

V, U, I, B = 'jv_value', 'u32', 'i32', 'string_bytes'


def definitions(base):
    types = [copy.deepcopy(t) for t in base['schema']['types'] if t['id'] in (V, U, 'unit')]
    types += [dict(id=I, kind='integer', width_bits=32, signed=True),
              dict(id=B, kind='opaque', nominal_id='jq.borrowed-string-bytes')]
    specs = {'contents': ([('value', V), ('bytes', B)], 'unit'),
             'create': ([('value', V), ('start', U), ('length', U)], V),
             'release': ([('value', V)], 'unit'), 'empty': ([], V), 'invalid': ([], V)}
    services = {}
    for name, (params, result) in specs.items():
        roles = [dict(root='parameter', value=n, fields=[],
                      transition='consume' if name == 'release' else 'borrow_shared',
                      kind='jq-reference', domain='libjq') for n, t in params if t == V]
        if result == V:
            roles.append(dict(root='result', value='result', fields=[], transition='produce',
                              kind='jq-reference', domain='libjq'))
        services[name] = ServiceDefinition.create(identity='jq.string.'+name, types=types,
            parameters=params, result=result, resources=roles, effects=['jq.string.'+name],
            outcomes=['return'], nonlocal_outcomes=['nomem'] if name in ('create','empty','invalid') else [],
            unobserved=['Borrowed contents remain valid only while their owner is live; adapters preserve the existing allocation.',
                        'Finite content, alias, lifetime and allocation-failure comparisons are not checked heap summaries.'])
    intent = component_interface(component_id='string-slice', types=types,
        parameters=[('value', V), ('start', I), ('end', I)], result=V, services=services)
    return intent, services


def resources(intent):
    return component_resource_checks(intent,consumes=['value'],produces=['result'],
        resource_kind='jq-reference',provider_domain='libjq',service_id='value-transport',
        interaction_contract_id='string-slice.reference-transfer',instrumented_sides=['source'],
        binding_ids={'parameter.value':'parameter','result.result':'result'},
        unobserved=['Native allocation internals; lifetime of direct borrowed C reads; arbitrary callback behavior.'],
        nonlocal_allowances={'nomem':dict(max_untransferred=1,max_retained=0)})
