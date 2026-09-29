"""Canonical local-buffer consumer of a checked void/register initializer."""
import json
from copy import deepcopy
from dataclasses import replace

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_caller_boundary import (
    U32, BYTES, add, sub, all_of, any_of, eq, le, named, value, wide, field, word, negate,
)
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_memory import entry_register, entry_offset, access, private_bytes
from spaghetti_extractor.components.bisimulation_native_calls import register
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.transfer.model import _Action, _Node, _Transfer, _Call
from tests.unit.components.test_object_initialization import fixture, initializer_transfer


def prepare_caller(root, *, wrong=False, network=False, repeated=False, indirect=None):
    network = network or repeated or indirect is not None
    root.mkdir(parents=True)
    supplier, _, _ = fixture()
    raw = supplier.intent.schema.to_payload()
    scalar = dict(raw['signatures'][0]['parameters'][1], id='input')
    result = dict(scalar, id='result')
    schema = BoundarySchemaV1.create(schema_id='initialization-consumer', types=[*raw['types'],
        {'id': 'run.fn', 'kind': 'function', 'calling_convention': 'cdecl', 'parameter_type_ids': ['u32'],
         'result_type_id': 'u32', 'variadic': False}], signatures=[*raw['signatures'],
        {'id': 'run', 'function_type_id': 'run.fn', 'parameters': [scalar], 'results': [result]}])
    services = ['initialize', 'reinitialize'] if network and not repeated else ['initialize']
    intent = ComponentInterfaceIntentV1.create(component_id='initialization-consumer', schema=schema,
        state=[], services=[{'id': identity, 'signature_id': 'initialize', 'effect_ids': [],
                             'interaction_contract_id': ('initializer' if identity=='initialize' else 'reinitializer')+'.initialize'}
                            for identity in services],
        effects=[], protocol_states=['ready'], initial_protocol_state='ready', operations=[{
            'id': 'run', 'signature_id': 'run', 'pre_states': ['ready'], 'post_states': ['ready'],
            'allowed_service_ids': services, 'effect_ids': [], 'source_values': [scalar, result],
            'projection_entries': [{'source_id': v['id'], 'target': {'root': kind, 'value_id': v['id'], 'fields': []}}
                                   for kind, v in [('parameter', scalar), ('result', result)]],
            'lifecycle_bindings': [], 'lifecycle_additional_roots': {'state': []}, 'checked_interaction_contract_ids': []}])
    (root/'interface').mkdir()
    (root/'interface/component-interface-intent-v1.json').write_text(json.dumps(intent.to_payload()))
    units = [8192, 8193, 8194, 8195] if network else [8192, 8193, 8194]
    ids = [f'semantic-transfer:original-cutpoint-{rva:08x}-{rva+1:08x}' for rva in units]
    call_nodes = tuple(_Node('reg', aux=i) for i in range(8)) + tuple(_Node('flag', aux=i) for i in range(6))
    call = _Call('internal_call', 8193, 0, None, 4096, 8194, None, None, None,
                 tuple(range(8)), tuple(range(8, 14)), (), ())
    ret = (_Node('reg', aux=0), _Node('const', immediate=4), _Node('add32', (0, 1)), _Node('load', (2,), aux=4),
           _Node('reg', aux=7), _Node('const', immediate=8), _Node('add32', (4, 5)), _Node('load', (6,), aux=4),
           _Node('const', immediate=12), _Node('add32', (4, 8)))
    transfers = [
        _Transfer(ids[0], 'a'*64, 'b'*64, 8192,
            (_Node('reg', aux=7), _Node('const', immediate=8), _Node('sub32', (0, 1))), (),
            (*(_Action('eval_word', (i,)) for i in range(3)), _Action('set_reg', (2,), aux=0),
             _Action('set_reg', (2,), aux=7), _Action('outcome_jump', (8193,))), (), ()),
        _Transfer(ids[1], 'a'*64, 'b'*64, 8193, call_nodes, (),
            (*(_Action('eval_word', (i,)) for i in range(14)), _Action('call', (0,)),
             _Action('outcome_jump', (8194,))), (call,), ()),
        _Transfer(ids[-1], 'a'*64, 'b'*64, units[-1], ret, (),
            (*(_Action('eval_word', (i,)) for i in range(len(ret))), _Action('set_reg', (3,), aux=0),
             _Action('set_reg', (9,), aux=7), _Action('outcome_return', (7,))), (), ())]
    suppliers = [initializer_transfer()]
    if network:
        second_nodes = call_nodes + (_Node('const', immediate=4), _Node('add32', (0, 14)), _Node('load', (15,), aux=4))
        second_call = _Call('indirect_call' if indirect else 'internal_call', 8194, 0, 6 if indirect else None,
            0 if indirect else (4096 if repeated else 4352), 8195, None, None, None,
            (0, 1, 2, 16, 4, 5, 6, 7), tuple(range(8, 14)), (), ())
        transfers.insert(2, _Transfer(ids[2], 'a'*64, 'b'*64, 8194, second_nodes, (),
            (*(_Action('eval_word', (i,)) for i in range(len(second_nodes))), _Action('call', (0,)),
             _Action('outcome_jump', (8195,))), (second_call,), ()))
        if not repeated and not indirect:
            suppliers.append(replace(initializer_transfer(),
                identity='semantic-transfer:original-cutpoint-00001100-00001101', rva_start=4352))
    if indirect == 'static_slot':
        entry = transfers[0]
        nodes = (*entry.nodes, _Node('const', immediate=0x400300), _Node('load', (3,), aux=4))
        transfers[0] = replace(entry, nodes=nodes, actions=(
            *(_Action('eval_word', (i,)) for i in range(len(nodes))), _Action('set_reg', (4,), aux=6),
            *entry.actions[3:]))
    write_component_exact_c_slice_v1(component_id=intent.component_id, transfers=[*transfers, *suppliers],
        operations=[{'operation_id': 'run', 'unit_ids': ids, 'entry_rvas': [8192]}], intent=None,
        executable_transfer_plan_sha256='c'*64, summary_entry_rvas=[s.rva_start for s in suppliers], out=root/'exact')
    stack = entry_register('esp')
    low, high = sub(stack, constant(12)), stack
    source = root/'caller.c'
    source.write_text('''#include "portable-component-implementation.h"
#include "portable-component-local-bytes.h"
uint32_t authored_consumer(spx_initialization_consumer_context_v5 *context,uint32_t input){
 uint8_t bytes[8];spx_local_bytes_v5 owner={0};spx_view_v5 view;
 if(spx_local_bytes_open(&owner,bytes,8U,3U,&view))return 0U;
 context->services->initialize(context->services->context,&view,input);
 uint32_t result=0U;
 for(uint32_t i=0;i<4U;i++)result|=(uint32_t)bytes[OFFSET+i]<<(8U*i);
 spx_local_bytes_close(&owner);return result;
}
'''.replace('OFFSET', '4U').replace(' spx_local_bytes_close',
        ''' context->services->reinitialize(context->services->context,&view,result);
 result=0U;
 for(uint32_t i=0;i<4U;i++)result|=(uint32_t)bytes[4U+i]<<(8U*i);
 spx_local_bytes_close''' if network else ' spx_local_bytes_close')
        .replace('reinitialize(', 'initialize(' if repeated else 'reinitialize(')
        .replace('return result;', 'return result ^ 1U;' if wrong else 'return result;'))
    build_component_source_package(lift_unit_id=intent.component_id, files={'caller.c': source},
        shared_inputs={}, operation_symbols={'run': 'authored_consumer'}, out_dir=root/'source')
    contract = {'profile': 'finite-paired-caller-v1', 'component_id': intent.component_id, 'operation_id': 'run',
        'entry_rva': 8192, 'unit_rvas': units, 'service_id': 'initialize', 'required_frame': ['eax'],
        'witnesses': {}, 'runtime_contracts': {},
        'native_memory': [private_bytes('buffer', entry_offset('esp', -8), 8),
                          access('return', stack, read=True)],
        'native_calls': [{'id': 'initialize', 'event': {'kind': 'internal', 'source_rva': 8193,
            'instruction_rva': 8193, 'target_rva': 4096, 'return_rva': 8194, 'call_index': 0,
            'argument_count': 0, 'stack_input_count': 0}, 'entry_stack_delta': -8,
            'arguments': [register('eax').to_payload(), register('edx').to_payload()], 'requires': []}],
        'source_services': [{'id': 'initialize', 'views': {'output': 'local_buffer'}, 'arguments': [
            expression('view_address', U32, parameter('output', BYTES)).to_payload(), parameter('value', U32).to_payload()],
            'diagnostic': 'initialize-arguments'}],
        'boundary': {'image_base': 0x400000, 'private_low': low.to_payload(), 'private_high': high.to_payload(),
            'call_private_low': low.to_payload(), 'call_private_high': high.to_payload(), 'views': [],
            'local_views': [{'id': 'local_buffer', 'type_id': 'bytes', 'address': entry_offset('esp', -8).to_payload(),
                             'extent': constant(8, 64).to_payload(), 'permissions': 3}],
            'private_byte_capacity': 8, 'event_capacity': 8, 'call_capacity': 1,
            'values': [{'id': 'input', 'sort': U32.to_payload(), 'expression': entry_register('edx').to_payload()},
                       {'id': 'return_target', 'sort': U32.to_payload(),
                        'expression': word('entry_memory', stack).to_payload()}],
            'admission': [named('stack-domain', all_of(le(constant(16), stack),
                le(add(wide(stack), constant(4, 64)), constant(0xffffffff, 64))))],
            'services': [{'id': 'initialize', 'before': [], 'count_diagnostic': 'single-initialize', 'maximum_calls': 1}],
            'assertions': [named('result-equivalence', eq(value('result'), field('eax')))],
            'outcomes': [{'id': 'normal', 'guard': expression('true', BOOL_SORT).to_payload(),
                'exit': {'kind': 'return', 'value': value('return_target').to_payload(), 'stack_delta': 4,
                         'diagnostic': 'normal-return'}, 'assertions': []}],
            'context_diagnostic': 'source-context', 'memory_diagnostic': 'public-memory'}}
    if network:
        del contract['service_id'], contract['required_frame']
        contract['suppliers'] = {identity: {'required_frame': ['eax']} for identity in services}
        call = deepcopy(contract['native_calls'][0]); call['id'] = 'initialize' if repeated else 'reinitialize'
        call['event'].update(source_rva=8194, instruction_rva=8194, target_rva=4096 if repeated else 4352, return_rva=8195)
        contract['native_calls'].append(call)
        contract['boundary']['call_capacity'] = 2
        if repeated:
            contract['boundary']['services'][0].update(count_diagnostic='two-initializations', maximum_calls=2)
        else:
            service = deepcopy(contract['source_services'][0]); service['id'] = 'reinitialize'
            service['diagnostic'] = 'reinitialize-arguments'; contract['source_services'].append(service)
            contract['boundary']['services'].append({'id': 'reinitialize', 'before': [],
                'count_diagnostic': 'single-reinitialize', 'maximum_calls': 1})
    if indirect:
        contract['suppliers'] = {'initialize': {'required_frame': ['eax', 'ebp']}}
        contract['native_calls'][1]['event'].update(kind='indirect', target_rva=0)
        projection = {'kind': indirect, 'at': 'entry', 'width': 32,
                      **({'register': 'ebp'} if indirect == 'register' else {'rva': 0x300})}
        contract['runtime_contracts']['reinitialize'] = {
            'id': 'explicit-runtime-initialization', 'revision': 1, 'status': 'unverified',
            'normal_return': {'result_field': None, 'stack_delta': 0, 'preserved_fields': ['eax']},
            'fault': 'none', 'normal_excludes': [], 'objects': [{'parameter': 'output'}],
            'requires': 'A live output object and the selected runtime target.',
            'ensures': 'Writes remain within output; no reference escapes; normal return.',
            'unverified': ['Concrete import identity, service applicability and native lifetime.'],
            'captured_target_projection': projection}
        target = register('ebp', 'entry')
        if indirect == 'static_slot':
            address = constant(0x400300)
            contract['native_memory'].append(access('import-slot', address, read=True))
            contract['boundary']['admission'].append(named('import-slot-outside-stack', any_of(
                le(wide(high), wide(address)), le(constant(0x400304, 64), wide(low)))))
            target = word('entry_memory', address)
        contract['boundary']['admission'].append(named('live-code-target', negate(eq(target, constant(0)))))
    return contract
