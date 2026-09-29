"""Instantiate a checked finite supplier at the actual direct-call boundary."""
from copy import deepcopy

from .bisimulation_call_relations import constant, parameter
from .bisimulation_caller_boundary import BYTES, U32, add, all_of, any_of, eq, le, named, sub, wide, word
from .bisimulation_caller_memory import entry_register
from .bisimulation_native_calls import register, stack_word
from .relation_ir import RelationExpressionV1, RelationSortV1


def require(condition, message):
    if not condition:
        raise ValueError('finite supplier call: ' + message)


def checked_reference_parameter_transport(facts, intent, service_id, boundary, transport, result_transport=None):
    """Map explicit opaque identities to a checked supplier's unsigned tokens.

    Actual source pointers are encoded by the existing checked record relation;
    every native argument, entry premise, memory footprint and outcome is still
    checked at the call. This is neither a pointer cast nor a lifetime grant.
    """
    from .bisimulation_caller_records import checked_record_specification
    from .bisimulation_caller_summary import CALLER_CALL_RULE
    from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
    require(facts['rule'] == CALLER_CALL_RULE, 'reference transport requires a checked finite supplier')
    service = next(s for s in intent.services if s['id'] == service_id)
    actual = intent.schema.signature_index[service['signature_id']].to_payload()
    expected = facts['signature']
    supplier = ComponentInterfaceIntentV1.parse(facts['interface_intent'])
    require(supplier.schema.type_index['u32'].to_payload() ==
            {'id':'u32','kind':'integer','signed':False,'width_bits':32},
            'reference transport supplier token type is not an unsigned 32-bit value')
    require(not service['effect_ids'], 'reference transport needs a service without declared effects')
    spec = checked_record_specification(boundary, compile_component_interface_v5(intent))
    require(spec is not None, 'reference transport needs a checked record relation')
    types = {row['id'] for row in spec['types'] if row.get('representation') == 'identity'}
    def scalar(v):
        return (v['type_id'] == 'u32' and v['interpretation'] == 'value'
                and v['access'] == 'none' and v['extent']['kind'] == 'none'
                and v['provider_domain'] is None and v['resource_kind'] is None)
    def identity(v):
        return (v['type_id'] in types and v['interpretation'] == 'value'
                and v['access'] == 'none' and v['extent']['kind'] == 'none'
                and v['provider_domain'] is None and v['resource_kind'] is None)
    if result_transport is None:
        require(actual['results'] == expected['results'] and all(scalar(v) for v in actual['results']),
                'different supplier/source results need explicit checked result transport')
    else:
        require(result_transport == {'relation':'record-address'} and len(actual['results']) == len(expected['results']) == 1
                and scalar(expected['results'][0]) and identity(actual['results'][0]),
                'result transport needs one unsigned supplier result and one identity-only source result')
    if transport is None:
        require(actual['parameters'] == expected['parameters'] and all(scalar(v) for v in actual['parameters']),
                'different supplier/source parameters need explicit checked parameter transport')
        transport = {p['id']:{'parameter':p['id'],'relation':'scalar'} for p in expected['parameters']}
    require(isinstance(transport, dict) and set(transport) == {p['id'] for p in expected['parameters']},
            'reference transport must bind every supplier parameter')
    actual_parameters = {p['id']: p for p in actual['parameters']}
    parameters = []
    for argument in expected['parameters']:
        row = transport[argument['id']]
        require(scalar(argument),
                'reference transport supplier parameter must be an unsigned scalar token')
        require(isinstance(row, dict) and set(row) == {'parameter','relation'}
                and row['relation'] in {'record-address','scalar'} and row['parameter'] in actual_parameters,
                'reference transport requires an explicit record-address or scalar parameter')
        value = actual_parameters[row['parameter']]
        require(identity(value) if row['relation'] == 'record-address' else scalar(value),
                'reference transport needs an identity without access authority or an unsigned scalar')
        parameters.append(value['id'])
    if any(scalar(v) for v in [*actual['parameters'], *actual['results']]):
        require(intent.schema.type_index['u32'].to_payload() == supplier.schema.type_index['u32'].to_payload(),
                'source scalar transport type differs from the supplier')
    require(len(parameters) == len(set(parameters)) and set(parameters) == set(actual_parameters),
            'reference transport must cover the source parameters one to one')
    return parameters


def instantiate_finite_supplier_call(facts, boundary, native, service, native_memory, bindings, *, argument_parameters=None):
    expected = [(register(a['entry_register']) if 'entry_register' in a else
                 stack_word(a['entry_stack_offset']-4)).to_payload() for a in facts['arguments']]
    parameters = argument_parameters if argument_parameters is not None else [a['id'] for a in facts['arguments']]
    require(native['arguments'] == expected and service['views'] == {} and not service.get('records') and
            service['arguments'] == [parameter(name, U32).to_payload() for name in parameters],
            'logical/native scalar argument correspondence differs')
    require(isinstance(bindings, dict) and set(bindings) == set(facts['parameters']),
            'all quantified contract parameters require explicit call bindings')
    supplied = {name: RelationExpressionV1.parse(raw) for name, raw in bindings.items()}
    require(all(supplied[name].sort == RelationSortV1.parse(sort) for name, sort in facts['parameters'].items()),
            'quantified contract binding sort differs')
    def checked_binding(node):
        # A shared ghost parameter may depend on the enclosing entry or the
        # paired scalar arguments. A side-specific heap/read would silently use
        # the original's bytes to define the source's abstract service effects.
        if node.op == 'logical':
            path = node.attributes['path']
            allowed = {row['id'] for row in boundary['values']} | {
                'argument_'+str(i) for i in range(len(facts['arguments']))}
            require(path['root'] == 'parameter' and not path['fields'] and path['id'] in allowed,
                    'contract binding must use entry values or paired call arguments')
        elif node.op == 'machine':
            place = node.attributes['place']
            require(place['kind'] == 'register' and place['phase'] == 'entry' and place['width'] == 32,
                    'contract binding machine state must be the enclosing entry')
        require(node.sort.kind != 'view' and node.op not in {'byte_read', 'view_address', 'view_extent'},
                'contract binding needs a shared scalar value')
        for argument in node.arguments:
            checked_binding(argument)
    for node in supplied.values():
        checked_binding(node)
    child = sub(register('esp'), constant(4))
    delta = native['entry_stack_delta']-4
    layout_child = (sub if delta < 0 else add)(entry_register('esp'), constant(abs(delta)))
    abi = []
    for i, argument in enumerate(facts['arguments']):
        source = (entry_register(argument['entry_register']) if 'entry_register' in argument else
                  word('entry_memory', add(entry_register('esp'), constant(argument['entry_stack_offset']))))
        abi.append((source, parameter('argument_'+str(i), U32)))
    return_word = word('entry_memory', entry_register('esp'))

    def substitute(raw, *, layout=False):
        node = RelationExpressionV1.parse(raw)
        for source, target in abi:
            if node == source:
                return target
        if node == return_word:
            return constant(boundary['image_base'] + native['event']['return_rva'])
        if node.op == 'machine':
            place = node.attributes['place']
            require(place['kind'] == 'register' and place['phase'] == 'entry' and place['width'] == 32,
                    'entry machine relation is unsupported')
            name = place['selector']['register']
            if name == 'esp':
                return layout_child if layout else child
            require(not layout, 'memory footprint depends on an undeclared per-call machine input')
            return register(name)
        if node.op == 'logical':
            path = node.attributes['path']
            require(path['root'] == 'parameter' and not path['fields'], 'unsupported entry value path')
            if path['id'] == 'entry_memory':
                require(not layout, 'memory footprint needs explicit call-time scalar bindings')
                return parameter('call_memory', BYTES)
            require(path['id'] in supplied, 'entry contract parameter is not bound')
            return supplied[path['id']]
        payload = node.to_payload()
        payload['args'] = [substitute(arg.to_payload(), layout=layout).to_payload() for arg in node.arguments]
        return RelationExpressionV1.parse(payload)

    require(boundary['image_base'] + native['event']['return_rva'] < 2**32, 'pushed return address wraps')
    checks = [named('finite-supplier-call-stack', all_of(le(constant(4), register('esp')),
        le(add(wide(child), constant(facts['stack_delta'], 64)), constant(2**32-1, 64)))),
        named('finite-supplier-image-base', eq(constant(boundary['image_base']), constant(facts['image_base'])))]
    checks.extend(named('finite-supplier-entry-'+row['id'], substitute(row['expression'])) for row in facts['entry_relations'])
    low, high = (substitute(facts[name]) for name in ('private_low', 'private_high'))
    checks.append(named('finite-supplier-output-private-scope', all_of(
        le(wide(RelationExpressionV1.parse(boundary['private_low'])), low),
        le(high, wide(RelationExpressionV1.parse(boundary['private_high']))))))
    for slot in native_memory:
        address = wide(RelationExpressionV1.parse(slot['address']))
        size = slot.get('extent', slot.get('width'))
        for index, (offset, count) in enumerate([(0, 4), *facts['private_writes']]):
            start = (sub if offset < 0 else add)(wide(child), constant(abs(offset), 64))
            separated = any_of(le(add(address, constant(size, 64)), start), le(add(start, constant(count, 64)), address))
            if slot['storage'] == 'private':
                separated = any_of(eq(parameter('private_initialized.'+slot['id'], U32), constant(0)), separated)
            checks.append(named(f'finite-supplier-live-storage-{slot["id"]}-{index}', separated))
    footprint = [{**{key: substitute(row[key], layout=True).to_payload() for key in ('address', 'extent')},
                  'permissions': row['permissions'], 'local_view': None, 'parameter': None, 'at': 'call'}
                 for row in facts['memory']]
    result = deepcopy(native)
    result['requires'] = [*result['requires'], *checks]
    result['normal_return'] = deepcopy(facts['normal_return'])
    return result, footprint
