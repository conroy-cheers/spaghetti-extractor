"""Typed local objects and checked live-object call applicability.

Local storage, source views and supplier footprints are distinct declarations.
The supplier's footprint and ABI come from validated facts; runtime footprints
remain explicitly unverified premises. Neither permits unobserved private writes.
"""
from copy import deepcopy

from .bisimulation_call_relations import constant, expression, parameter
from .bisimulation_caller_boundary import U32, add, all_of, any_of, eq, le, named, sub, wide
from .bisimulation_native_calls import register, stack_word, checked_return, checked_call_sites
from .bisimulation_caller_targets import captured_call_target
from .bisimulation_caller_returned_views import checked_returned_view
from .bisimulation_supplier_facts import check_supplier_service
from .interface_package_v5 import compile_component_interface_v5
from .bisimulation_caller_interface import caller_view_bindings
from .relation_ir import RelationExpressionV1, RelationSortV1


def require(value, message):
    if not value: raise ValueError('caller objects: '+message)


def local_view_definitions(boundary, intent):
    from .bisimulation_caller_records import record_type_ids
    rows = boundary.get('local_views', [])
    require(isinstance(rows, list) and len(rows) <= 32, 'invalid local view inventory')
    bundle = compile_component_interface_v5(intent)
    public = {name for name, _ in caller_view_bindings(bundle, boundary['operation'],record_types=record_type_ids(boundary,bundle))}
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'id', 'type_id', 'address', 'extent', 'permissions'},
                'local view fields differ')
        identity = row['id']
        require(isinstance(identity, str) and identity and identity not in seen | public,
                'duplicate or conflicting local view identity')
        seen.add(identity)
        t = intent.schema.type_index[row['type_id']]
        require(t.kind == 'pointer' and intent.schema.type_index[t.body['pointee_type_id']].kind == 'integer'
                and intent.schema.type_index[t.body['pointee_type_id']].body == {'signed': False, 'width_bits': 8},
                'local view needs a byte pointer type')
        require(type(row['permissions']) is int and row['permissions'] in {1, 2, 3}
                and RelationExpressionV1.parse(row['address']).sort == U32
                and RelationExpressionV1.parse(row['extent']).sort in {U32, RelationSortV1('bitvector', width=64)},
                'local view permissions/address/extent differ')
    return rows


def _parameter_objects(boundary, intent, service):
    """All service parameter views, in generated source parameter order."""
    from .bisimulation_caller_local_records import local_record_definitions
    locals = {r['id']: r for r in local_view_definitions(boundary, intent)}
    records = {r['id']: r for r in local_record_definitions(boundary, compile_component_interface_v5(intent))}
    public = {r['id']: r for r in boundary['views']}
    declaration = next(s for s in intent.services if s['id'] == service['id'])
    signature = intent.schema.signature_index[declaration['signature_id']]
    result = {}
    for value in signature.parameters:
        if value.identity in service.get('records', {}):
            identity = service['records'][value.identity]
            require(identity in records, 'local record mapping is absent')
            record = records[identity]
            result[value.identity] = {k: record[k] for k in ('address', 'extent', 'permissions')}
            result[value.identity].update(local_view=identity, parameter=value.identity)
            continue
        if value.interpretation != 'view': continue
        identity = service['views'][value.identity]
        view = locals.get(identity, public.get(identity))
        require(view is not None, 'service view mapping is absent')
        permission = {'read': 1, 'write': 2, 'read_write': 3}[value.access]
        result[value.identity] = {'address': view['address'], 'extent': view['extent'],
            'permissions': permission, 'local_view': identity if identity in locals else None,
            'parameter': value.identity}
    return result


def instantiate_object_supplier_call(facts, boundary, native, service, native_memory, intent):
    objects = _parameter_objects(boundary, intent, service)
    expected_native = [(register(a['entry_register']) if 'entry_register' in a else
                        stack_word(a['entry_stack_offset']-4)).to_payload() for a in facts['arguments']]
    expected_source = [(expression('view_address', U32,
        parameter(a['id'], RelationSortV1('view', type_id=facts['signature']['parameters'][i]['type_id'])))
        if a['interpretation'] == 'view' else parameter(a['id'], U32)).to_payload()
        for i, a in enumerate(facts['arguments'])]
    require(native['arguments'] == expected_native and service['arguments'] == expected_source,
            'supplier arguments differ from the checked ABI and source projection')
    stack = wide(register('esp')); child = sub(stack, constant(4, 64))
    accesses = facts['private_accesses']; low_offset = min(o for o, n in accesses)
    high_offset = max(o+n for o, n in accesses)
    shift = lambda base, offset: sub(base, constant(-offset, 64)) if offset < 0 else add(base, constant(offset, 64))
    low, high = shift(child, low_offset), shift(child, high_offset)
    checks = [named('supplier-call-object-private-entry', all_of(
        le(constant(4-low_offset, 64), stack), le(high, constant(2**32, 64)),
        le(add(child, constant(facts['stack_delta'], 64)), constant(2**32-1, 64)))),
        named('supplier-call-object-image-base', eq(constant(boundary['image_base']), constant(facts['image_base'])))]
    for i, argument in enumerate(facts['arguments']):
        if argument['interpretation'] != 'view': continue
        view = objects[argument['id']]
        address = RelationExpressionV1.parse(view['address']); extent = wide(RelationExpressionV1.parse(view['extent']))
        checks.append(named('supplier-call-object-argument-'+argument['id'], all_of(
            eq(parameter('argument_'+str(i), U32), address),
            le(constant(argument['minimum_extent'], 64), extent),
            le(add(wide(address), extent), constant(2**32, 64)))))
    footprint = [*objects.values(), *({'address': constant(v['address']).to_payload(),
        'extent': constant(v['extent'], 64).to_payload(), 'permissions': v['permissions'], 'local_view': None, 'parameter': None}
        for _, v in sorted(facts['shared_views'].items()))]
    for claim in facts.get('initializes', []):
        objects[claim['parameter']].setdefault('initializes', []).append(
            {k: claim[k] for k in ('offset', 'extent')})
    for i, view in enumerate(footprint):
        address = wide(RelationExpressionV1.parse(view['address'])); extent = wide(RelationExpressionV1.parse(view['extent']))
        checks.append(named('supplier-call-object-private-separation-'+str(i), any_of(
            le(add(address, extent), low), le(high, address))))
    for slot in native_memory:
        # Public native words can also be observed after the call. Callee stack
        # writes are not sparse-world writes; silently retaining one of these
        # words would lose a real effect just as for private continuation data.
        address = wide(RelationExpressionV1.parse(slot['address']))
        extent = slot['extent'] if slot['storage'] == 'private_bytes' else slot['width']
        for i, (offset, size) in enumerate([(0, 4), *facts['private_writes']]):
            start = shift(child, offset)
            separated = any_of(le(add(address, constant(extent, 64)), start), le(add(start, constant(size, 64)), address))
            if slot['storage'] == 'private':
                separated = any_of(eq(parameter('private_initialized.'+slot['id'], U32), constant(0)), separated)
            checks.append(named(f'supplier-call-object-live-storage-{slot["id"]}-{i}', separated))
    checks.append(named('supplier-call-object-output-private-scope', all_of(
        le(wide(RelationExpressionV1.parse(boundary['private_low'])), low),
        le(high, wide(RelationExpressionV1.parse(boundary['private_high']))))))
    result = deepcopy(native)
    result['normal_return'] = deepcopy(facts['normal_return'])
    result['requires'] = [*result['requires'], *checks]
    return result, footprint


def instantiate_object_definition(contract, selected, facts, intent):
    from .bisimulation_caller_definition import checked_caller_interface
    from .bisimulation_caller_records import record_type_ids
    from .bisimulation_caller_local_records import local_record_definitions
    boundary = selected['boundary']; services = deepcopy(contract['source_services'])
    require(contract['witnesses'] == {} and 'supplier_admission' not in boundary,
            'object supplier premises must be established at the actual call')
    require('objects' not in boundary and all('objects' not in r for r in boundary['services']),
            'service footprints must be derived from checked facts or explicit runtime premises')
    local_view_definitions(boundary, intent)
    checked_caller_interface(intent, selected['operation'], services, local_views=boundary.get('local_views', []),
                            local_records=local_record_definitions(boundary,compile_component_interface_v5(intent)),
                            record_types=record_type_ids(boundary,compile_component_interface_v5(intent)))
    suppliers = facts if 'suppliers' in contract else {contract['service_id']: facts}
    transported = {}
    for identity, supplied in sorted(suppliers.items()):
        requirement = contract.get('suppliers', {}).get(identity, {})
        transport = requirement.get('parameter_transport')
        result_transport = requirement.get('result_transport')
        if transport is None and result_transport is None:
            check_supplier_service(supplied, intent, identity)
        else:
            from .bisimulation_caller_summary_call import checked_reference_parameter_transport
            transported[identity] = checked_reference_parameter_transport(supplied, intent, identity, boundary, transport, result_transport)
    calls = deepcopy(contract['native_calls']); runtime = deepcopy(contract['runtime_contracts'])
    source_index = {r['id']: r for r in services}
    arities = checked_call_sites(calls, set(source_index))
    require(set(suppliers)<=set(source_index) and set(runtime) == set(source_index)-set(suppliers),
            'runtime authority coverage differs')
    require(len(boundary['services']) == len(services) and {r['id'] for r in boundary['services']} == set(source_index),
            'boundary service coverage differs')
    footprints = {}
    for i, call in enumerate(calls):
        require(set(call) == {'id', 'event', 'arguments', 'requires', 'entry_stack_delta'},
                'native guarantees must be derived')
        source = source_index[call['id']]
        if call['id'] in suppliers:
            supplied = suppliers[call['id']]
            require(call['event']['kind'] == 'internal' and call['event']['target_rva'] == supplied['original_entry_rva'],
                    'supplier event target differs')
            from .bisimulation_caller_summary import CALLER_CALL_RULE
            if supplied['rule'] == CALLER_CALL_RULE:
                from .bisimulation_caller_summary_call import instantiate_finite_supplier_call
                calls[i], footprint = instantiate_finite_supplier_call(supplied, boundary, call, source,
                    selected['native_memory'], contract['suppliers'][call['id']].get('bindings', {}),
                    argument_parameters=transported.get(call['id']))
            else:
                calls[i], footprint = instantiate_object_supplier_call(supplied, boundary, call, source, selected['native_memory'], intent)
        else:
            premise = runtime[call['id']]
            require(isinstance(premise, dict) and set(premise)-{'captured_target_projection', 'target_sampling', 'returned_view'} == {'id', 'revision', 'status', 'normal_return',
                'fault', 'normal_excludes', 'requires', 'ensures', 'unverified', 'objects'}
                and premise['status'] == 'unverified' and type(premise['revision']) is int and premise['revision'] > 0
                and all(isinstance(premise[k], str) and premise[k] for k in ('id', 'requires', 'ensures'))
                and isinstance(premise['unverified'], list) and premise['unverified']
                and premise['fault'] == 'none' and premise['normal_excludes'] == [],
                'object runtime service needs an explicit unverified normal-return contract')
            require(call['event']['kind'] in {'internal', 'import', 'indirect'}, 'unsupported runtime event')
            captured_call_target(call,premise)
            checked_returned_view(premise,intent,call['id'])
            call['normal_return'] = checked_return(premise['normal_return'])
            parameters = _parameter_objects(boundary, intent, source); footprint = []; consumed = set()
            require(isinstance(premise['objects'], list), 'runtime footprint must be explicit')
            for view in premise['objects']:
                require(isinstance(view, dict), 'runtime footprint entry is invalid')
                if set(view) == {'parameter'}:
                    require(view['parameter'] in parameters and view['parameter'] not in consumed, 'runtime parameter footprint differs')
                    consumed.add(view['parameter']); footprint.append(parameters[view['parameter']])
                else:
                    require(set(view) == {'address', 'extent', 'permissions'}, 'runtime span fields differ')
                    footprint.append({**view, 'local_view': None, 'parameter': None})
            require(consumed == set(parameters), 'runtime parameter footprint is incomplete')
        previous = footprints.setdefault(call['id'], footprint)
        require(previous == footprint, 'native sites for one service have different object footprints')
    for target in boundary['services']:
        identity = target['id']; footprint = footprints[identity]
        require(not {'arguments', 'fault', 'normal_excludes', 'result_view', 'result_value', 'objects', 'terminal_services', 'captured_target_projection', 'target_sampling', 'returned_view'} & set(target),
                'service outcomes and footprint must be derived')
        require(len(footprint) <= 32, 'unsupported object footprint count')
        target.update(arguments=arities[identity], fault='none', normal_excludes=[], objects=footprint)
        if identity in runtime and runtime[identity].get('captured_target_projection') is not None:
            target['captured_target_projection']=deepcopy(runtime[identity]['captured_target_projection'])
            if 'target_sampling' in runtime[identity]:
                target['target_sampling']=runtime[identity]['target_sampling']
        if identity in runtime and runtime[identity].get('returned_view') is not None:
            target['returned_view']=checked_returned_view(runtime[identity],intent,identity)
        if identity in suppliers and suppliers[identity].get('terminal_services'):
            target['terminal_services'] = deepcopy(suppliers[identity]['terminal_services'])
    authority = {'suppliers': suppliers} if 'suppliers' in contract else {'supplier': facts}
    for kind in ('parameter_transport', 'result_transport'):
        mapped = {name: deepcopy(contract['suppliers'][name][kind])
                  for name in transported if kind in contract['suppliers'][name]}
        if mapped:
            authority[kind] = mapped
    if 'records' in boundary:
        authority['record_lifetime'] = {'status':'unverified', 'lifetime':'operation',
            'requires':['Incoming record and byte objects denote the declared live native storage.',
                        'Services preserve that object inventory and lifetime for the whole operation.',
                        'Partial overlaps between distinct represented fields require another checked relation.'],
            'does_not_establish':['allocation','release','escape','native admission']}
        identities = [row['id'] for row in boundary['records']['types'] if row.get('representation') == 'identity']
        if identities:
            authority['record_lifetime']['requires'][0] = 'Represented storage objects denote the declared live native storage; identity-only references grant no storage.'
            authority['record_lifetime']['requires'][1] = 'Services preserve the represented storage inventory and lifetime; native allocation/release behind identity-only references is not inferred.'
            authority['record_identities'] = {'types': identities, 'relation': 'native-address',
                'checked': ['Null, equality and aliases use canonical zero-size C tokens.',
                            'Service results extend address identities within the checked call bound, preserving aliases with incoming and earlier returned identities.',
                            'Tokens grant no source-readable bytes or native access permission.'],
                'does_not_establish': ['native contents', 'allocation identity', 'generation', 'lifetime', 'native admission']}
    if boundary.get('local_records'):
        authority['local_record_lifetime'] = {'status':'unverified', 'lifetime':'synchronous-call',
            'requires':['Services do not retain local record references after returning.',
                        'Local record storage is separate from public represented objects.'],
            'checked':['Actual C storage is live at each call.', 'Native field contents and exact local aliases.',
                       'Service writes reach the actual C fields before continuation.'],
            'does_not_establish':['escape','asynchronous use','native admission']}
    return boundary, calls, services, {'id': contract['profile'], 'revision': 1, **authority, 'services': runtime,
        'scope': 'Conditional live-object caller only; source local storage is checked at each synchronous call. '
                 'Creation, escape, following-service applicability, native object authority and activation remain unverified.'}
