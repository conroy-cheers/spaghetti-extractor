"""Conditional callable facts from a complete, replayed finite caller theorem.

The theorem's admitted inputs and runtime premises survive abstraction. The
original's checked access inventory supplies a conservative memory footprint;
returned ranges remain broad unless their lifetime rule proves a narrower one.
No source body, query, event count or private algorithm enters the consumed facts.
"""
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_call_evidence import read_json
from .bisimulation_call_relations import constant, expression
from .bisimulation_caller_boundary import U32, eq, field, sub, value, word
from .bisimulation_caller_memory import ENTRY_REGISTERS, entry_register
from .bisimulation_native_calls import checked_return
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from .relation_ir import BOOL_SORT, RelationExpressionV1, RelationSortV1

CALLER_CALL_RULE = 'checked-finite-caller-paired-call-v1'
_READING = ContextVar('finite_caller_supplier_reading', default=frozenset())


def require(condition, message):
    if not condition:
        raise ValueError('caller supplier: ' + message)


def expand_entry(raw, values, *, active=()):
    """Expand named entry definitions, retaining explicit universally bound values."""
    node = RelationExpressionV1.parse(raw)
    if node.op == 'logical':
        path = node.attributes['path']
        require(path['root'] == 'parameter' and not path['fields'], 'unsupported entry path')
        name = path['id']
        if name == 'entry_memory':
            return node
        require(name in values, 'entry value is absent; call-time footprints need a checked enclosing-operation envelope: '+name)
        require(name not in active, 'entry value is recursive: '+name)
        row = values[name]
        require(RelationSortV1.parse(row['sort']) == node.sort, 'entry value sort differs')
        if row['expression'] is None:
            return node
        return expand_entry(row['expression'], values, active=(*active, name))
    payload = node.to_payload()
    payload['args'] = [expand_entry(arg.to_payload(), values, active=active).to_payload() for arg in node.arguments]
    return RelationExpressionV1.parse(payload)


def stack_offset(raw):
    """Recognize the existing unsigned entry-stack address vocabulary."""
    node = RelationExpressionV1.parse(raw)
    if node == entry_register('esp'):
        return 0
    if node.op in {'zero_extend', 'truncate'}:
        return stack_offset(node.arguments[0].to_payload())
    if node.op in {'add', 'sub'} and node.arguments[1].op == 'const':
        offset = stack_offset(node.arguments[0].to_payload())
        if offset is not None:
            amount = node.arguments[1].attributes['value']
            return offset + (amount if node.op == 'add' else -amount)
    return None


def checked_finite_caller_supplier(supplier, required_frame):
    from ..operator.source_operation_call_check import validate_operation_call_result
    supplier = Path(supplier).resolve()
    seen = _READING.get()
    require(supplier not in seen and len(seen) < 32, 'recursive or over-depth supplier evidence')
    token = _READING.set(seen | {supplier})
    try:
        result = read_json(supplier/'caller-comparison/result.json')
        validate_operation_call_result(result, supplier/'caller-comparison')
    finally:
        _READING.reset(token)
    bound = result['proof_key']['bindings']
    boundary = bound['boundary']
    intent = ComponentInterfaceIntentV1.parse(bound['interface_intent'])
    bundle = compile_component_interface_v5(intent)
    operation, = bundle.interface.operations
    signature = intent.schema.signature_index[operation.signature_id].to_payload()
    require(not boundary.get('records'),
            'record supplier needs a checked callable lifetime and enclosing memory transport')
    require(not bundle.interface.state and not boundary.get('local_views') and not boundary['views'],
            'finite supplier state/view representation needs a checked callable transport')
    require(all(v['interpretation'] == 'value' and v['type_id'] == 'u32' for v in signature['parameters'])
            and len(signature['results']) <= 1,
            'finite supplier currently needs unsigned scalar parameters and a void or scalar result')
    outcomes = boundary['outcomes']
    require(len(outcomes) == 1 and outcomes[0]['guard'] == expression('true', BOOL_SORT).to_payload()
            and outcomes[0]['exit']['kind'] == 'return', 'callable supplier needs a proved unconditional normal return')
    require(not any(s.get('terminal_services') for s in boundary['services']),
            'finite terminal traces need an explicit callable outcome rule')
    values = {row['id']: row for row in boundary['values']}
    expand = lambda raw: expand_entry(raw, values)
    entry_memory = 'entry_memory'
    return_target = expand(outcomes[0]['exit']['value'])
    require(return_target == word(entry_memory, entry_register('esp')),
            'normal return must consume the actual incoming call return word')
    arguments = []
    for parameter_value in signature['parameters']:
        name = parameter_value['id']
        require(name in values and values[name]['expression'] is not None, 'source argument has no checked entry binding')
        argument = expand(values[name]['expression'])
        registers = [r for r in ENTRY_REGISTERS if argument == entry_register(r)]
        slots = [row for row in bound['native_memory'] if row['storage'] == 'public' and row['read'] and row.get('width') == 4
                 and argument == word(entry_memory, RelationExpressionV1.parse(row['address']))]
        if registers:
            require(registers[0] != 'esp', 'a stack-pointer value parameter needs explicit call-entry transport')
            arguments.append({'id': name, 'entry_register': registers[0]})
        else:
            require(len(slots) == 1, 'scalar argument needs a complete entry register or stack word')
            offset = stack_offset(slots[0]['address'])
            require(offset is not None and offset >= 4, 'scalar argument stack word is not above the return address')
            arguments.append({'id': name, 'entry_stack_offset': offset})
    assertions = [row['expression'] for row in [*boundary['assertions'], *outcomes[0]['assertions']]]
    preserved = sorted(r for r in ENTRY_REGISTERS if eq(field(r), entry_register(r)).to_payload() in assertions)
    require(isinstance(required_frame, list) and required_frame == sorted(set(required_frame))
            and all(r in ENTRY_REGISTERS for r in required_frame), 'invalid requested scalar frame')
    result_register = None
    if signature['results']:
        require(signature['results'][0]['interpretation'] == 'value' and signature['results'][0]['type_id'] == 'u32',
                'finite supplier result needs a checked unsigned scalar relation')
        matches = [r for r in ENTRY_REGISTERS if eq(value('result'), field(r)).to_payload() in assertions
                   or eq(field(r), value('result')).to_payload() in assertions]
        require(len(matches) == 1, 'scalar result lacks a unique checked machine equality')
        result_register = matches[0]
    stack_delta = outcomes[0]['exit']['stack_delta']
    require(stack_delta >= 4, 'callee return must consume its pushed return word')
    free_values = {name: row['sort'] for name, row in values.items() if row['expression'] is None}
    require(not set(free_values) & {p['id'] for p in signature['parameters']}, 'source parameters cannot be unbound witnesses')
    footprint = []
    private_writes = []
    for row in bound['native_memory']:
        if row['storage'] != 'public':
            offset = stack_offset(row['address'])
            require(offset is not None and row['storage'] == 'private', 'private supplier storage needs scalar stack transport')
            if row['write']:
                private_writes.append([offset, row['width']])
            continue
        offset = stack_offset(row['address'])
        abi_input = row.get('width') == 4 and (offset == 0 or any(a.get('entry_stack_offset') == offset for a in arguments))
        if abi_input:
            require(not row['write'], 'call ABI input storage is writable')
            continue
        footprint.append({'address': expand(row['address']).to_payload(), 'extent': constant(row['width'], 64).to_payload(),
                          'permissions': int(row['read']) | (2 * int(row['write']))})
    for service in boundary['services']:
        require('objects' in service, 'supplier effects need checked object footprints')
        for obj in service['objects']:
            require(obj['local_view'] is None and obj['parameter'] is None and not obj.get('initializes'),
                    'nested object transport needs an explicit callable representation rule')
            footprint.append({k: expand(obj[k]).to_payload() for k in ('address', 'extent')} | {'permissions': obj['permissions']})
        if service.get('returned_view'):
            rule = service['returned_view']
            low, high = expand(boundary['call_private_low']), expand(boundary['call_private_high'])
            footprint.extend([
                {'address': constant(0).to_payload(), 'extent': low.to_payload(), 'permissions': rule['permissions']},
                {'address': expression('truncate', U32, high).to_payload(),
                 'extent': sub(constant(2**32, 64), high).to_payload(), 'permissions': rule['permissions']},
            ])
    # Only exact duplicates are folded. Overlap retains its byte correspondence.
    footprint = sorted({canonical_sha256_v3(row): row for row in footprint}.values(), key=canonical_sha256_v3)
    require(len(footprint) <= 32, 'callable memory footprint needs further decomposition')
    source = bound['original_files']
    original = read_json(Path(result['inputs']['exact'])/'component-exact-c-slice-v1.json')
    facts = {
        'rule': CALLER_CALL_RULE, 'component_id': intent.component_id, 'operation_id': operation.identity,
        'interface_intent': intent.to_payload(), 'signature': signature, 'arguments': arguments,
        'original_entry_rva': boundary['entry'], 'original_transfer_plan_sha256': original['bindings']['executable_transfer_plan_sha256'],
        'original_files': {name: source[name] for name in (f'behavioral-fn-{boundary["entry"]:08x}.c', 'behavioral-support.c', 'state-machine-runtime.h')},
        'native_projection': {'image_views': {}}, 'image_base': boundary['image_base'],
        # The entry renderer admits definedness of *every* initialized logical
        # value, even one absent from explicit admission predicates. Transport
        # those premises too; dropping an unused partial read widens the theorem.
        'entry_relations': [
            *({'id': 'value-defined-'+name, 'expression': eq(expand(row['expression']), expand(row['expression'])).to_payload()}
              for name, row in values.items() if row['expression'] is not None),
            *({'id': row['id'], 'expression': expand(row['expression']).to_payload()} for row in boundary['admission'])],
        'parameters': free_values, 'memory': footprint,
        'private_low': expand(boundary['private_low']).to_payload(), 'private_high': expand(boundary['private_high']).to_payload(),
        'private_writes': sorted(private_writes), 'stack_delta': stack_delta,
        'normal_return': checked_return({'result_field': result_register, 'stack_delta': stack_delta-4,
                                        'preserved_fields': sorted(set(required_frame) & set(preserved))}),
        'runtime_assumptions': deepcopy(bound['runtime_contract']),
    }
    missing = sorted(set(required_frame)-set(preserved))
    requirements = {'rule': CALLER_CALL_RULE, 'status': 'requires-recheck' if missing else 'compatible',
        'required_normal_frame': required_frame, 'available_normal_frame': preserved, 'missing_guarantees': missing,
        'consumed_contract_sha256': canonical_sha256_v3(facts)}
    return facts, {'contract_sha256': canonical_sha256_v3(facts), 'consumer_requirements': requirements,
                   'evidence': {'caller_receipt_sha256': result['receipt_sha256']}}
