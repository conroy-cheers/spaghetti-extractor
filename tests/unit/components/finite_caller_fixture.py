"""A three-level ordinary-C network over mutable, aliasing runtime storage."""
import json

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, U64, add, all_of, any_of, eq, field, le, named, sub, value, wide, word
from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_offset, entry_register
from spaghetti_extractor.components.bisimulation_native_calls import register
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer
from tests.unit.components.returned_caller_fixture import prepare


def protect(contract):
    boundary = contract['boundary']
    low, high = value('protected_low', U64), value('protected_high', U64)
    boundary['values'].extend({'id': name, 'sort': U64.to_payload(), 'expression': None}
                              for name in ('protected_low', 'protected_high'))
    from spaghetti_extractor.components.relation_ir import RelationExpressionV1
    boundary['admission'].append(named('protected-frame', all_of(
        le(low, wide(RelationExpressionV1.parse(boundary['private_low']))),
        le(wide(RelationExpressionV1.parse(boundary['private_high'])), high),
        le(high, constant(2**32, 64)),
        any_of(le(constant(5, 64), low), le(high, constant(2**32-4, 64))))))
    boundary.update(call_private_low=low.to_payload(), call_private_high=high.to_payload())
    boundary['assertions'].append(named('preserved-ebx', eq(field('ebx'), entry_register('ebx'))))
    return contract


def leaf(root, *, edited=False, wrong=False, transfers_out=None):
    contract = protect(prepare(root, variant='wrong' if wrong else 'valid', transfers_out=transfers_out))
    contract['boundary']['event_capacity'] = 8
    if edited:
        source = root/'caller.c'
        source.write_text(source.read_text().replace('(void)a.write(a.access_context,a.base,0U,4U,input);',
            'for(uint32_t i=0U;i<4U;i++) (void)a.write(a.access_context,a.base,i,1U,(input>>(8U*i))&255U);'))
        build_component_source_package(lift_unit_id=contract['component_id'], files={'caller.c': source},
            shared_inputs={}, operation_symbols={'run': 'authored'}, out_dir=root/'source-edited')
    return contract


def parent(root, *, supplier_interface, supplier_transfers, entry=0x3000, callee=0x2000, depth=2, wrong=False, live_slot=False, transfers_out=None):
    root.mkdir(parents=True)
    supplied = json.loads(supplier_interface.read_text())
    schema = BoundarySchemaV1.parse(supplied['schema'])
    component = 'finite-parent-'+str(depth)
    signature = schema.signature_index['run'].to_payload()
    scalar = signature['parameters'][0]
    intent = ComponentInterfaceIntentV1.create(component_id=component, schema=schema, state=[], effects=[],
        services=[{'id': 'child', 'signature_id': 'run', 'effect_ids': [], 'interaction_contract_id': 'checked.child'}],
        protocol_states=['ready'], initial_protocol_state='ready', operations=[{
            'id': 'run', 'signature_id': 'run', 'pre_states': ['ready'], 'post_states': ['ready'],
            'allowed_service_ids': ['child'], 'effect_ids': [], 'source_values': [scalar],
            'projection_entries': [{'source_id': 'input', 'target': {'root': 'parameter', 'value_id': 'input', 'fields': []}}],
            'lifecycle_bindings': [], 'lifecycle_additional_roots': {'state': []}, 'checked_interaction_contract_ids': []}])
    (root/'interface').mkdir()
    (root/'interface/component-interface-intent-v1.json').write_text(json.dumps(intent.to_payload()))
    registers = tuple(_Node('reg', aux=i) for i in range(8))+tuple(_Node('flag', aux=i) for i in range(6))
    units = [entry, entry+1, entry+2]
    transfers = []
    calls = []
    for i, rva in enumerate(units[:2]):
        nodes = registers if i == 0 else (*registers, _Node('const', immediate=1), _Node('add32', (1, 14)))
        argument_node = 15
        writes = []
        if live_slot:
            nodes = (*registers, _Node('const', immediate=4), _Node('sub32', (7, 14)))
            if i:
                nodes += (_Node('load', (15,), aux=4), _Node('const', immediate=1), _Node('add32', (16, 17)))
                argument_node = 18
            else:
                writes.append(_Action('memory_write', (15, 1), aux=4))
        at_call = list(range(8))
        if i: at_call[1] = argument_node
        event = _Call('internal_call', rva, 0, None, callee, rva+1, None, None, None,
                      tuple(at_call), tuple(range(8, 14)), (), ())
        transfers.append(_Transfer(f'semantic-transfer:original-cutpoint-{rva:08x}-{rva+1:08x}',
            'a'*64, 'b'*64, rva, nodes, (),
            (*(_Action('eval_word', (j,)) for j in range(len(nodes))),
             *writes, *([_Action('set_reg', (argument_node,), aux=1)] if i else []),
             _Action('call', (0,)), _Action('outcome_jump', (rva+1,))), (event,), ()))
        calls.append({'id': 'child', 'event': {'kind': 'internal', 'source_rva': rva, 'instruction_rva': rva,
            'target_rva': callee, 'return_rva': rva+1, 'call_index': 0, 'argument_count': 0, 'stack_input_count': 0},
            'entry_stack_delta': 0, 'arguments': [register('ebx').to_payload()], 'requires': []})
    nodes = (_Node('reg', aux=7), _Node('load', (0,), aux=4), _Node('const', immediate=4), _Node('add32', (0, 2)),
             _Node('reg', aux=1), _Node('const', immediate=1), _Node('sub32', (4, 5)))
    transfers.append(_Transfer(f'semantic-transfer:original-cutpoint-{entry+2:08x}-{entry+3:08x}',
        'a'*64, 'b'*64, entry+2, nodes, (),
        (*(_Action('eval_word', (i,)) for i in range(len(nodes))), _Action('set_reg', (6,), aux=1),
         _Action('set_reg', (3,), aux=7), _Action('outcome_return', (1,))), (), ()))
    if transfers_out is not None:
        transfers_out.extend(transfers)
    write_component_exact_c_slice_v1(component_id=component, transfers=[*transfers, *supplier_transfers],
        operations=[{'operation_id': 'run', 'unit_ids': [t.identity for t in transfers], 'entry_rvas': [entry]}],
        intent=None, executable_transfer_plan_sha256='c'*64, summary_entry_rvas=[callee], out=root/'exact')
    source = root/'caller.c'
    source.write_text('#include "portable-component-implementation.h"\n'
        f'void authored(spx_finite_parent_{depth}_context_v5 *context,uint32_t input){{\n'
        ' context->services->child(context->services->context,input);\n'
        f' context->services->child(context->services->context,input+{2 if wrong else 1}U);\n}}\n')
    build_component_source_package(lift_unit_id=component, files={'caller.c': source}, shared_inputs={},
        operation_symbols={'run': 'authored'}, out_dir=root/'source')
    stack = entry_register('esp')
    low, high = sub(wide(stack), constant(4*depth, 64)), add(wide(stack), constant(4, 64))
    contract = {'profile': 'finite-paired-caller-v1', 'component_id': component, 'operation_id': 'run',
        'entry_rva': entry, 'unit_rvas': units,
        'suppliers': {'child': {'required_frame': ['ebx'], 'bindings': {
            name: value(name, U64).to_payload() for name in ('protected_low', 'protected_high')}}},
        'witnesses': {}, 'runtime_contracts': {}, 'native_memory': [access('return', stack, read=True),
            *([access('live', entry_offset('esp', -4), read=True, write=True, storage='private')] if live_slot else [])],
        'native_calls': calls,
        'source_services': [{'id': 'child', 'views': {}, 'arguments': [parameter('input', U32).to_payload()],
                             'diagnostic': 'child-arguments'}],
        'boundary': {'image_base': 0x400000, 'private_low': low.to_payload(), 'private_high': high.to_payload(),
            'call_private_low': low.to_payload(), 'call_private_high': high.to_payload(), 'views': [],
            'event_capacity': 4, 'call_capacity': 2,
            'values': [{'id': 'input', 'sort': U32.to_payload(), 'expression': entry_register('ebx').to_payload()},
                       {'id': 'return_target', 'sort': U32.to_payload(), 'expression': word('entry_memory', stack).to_payload()}],
            'admission': [named('stack-domain', all_of(le(constant(16+4*depth), stack),
                le(wide(stack), constant(0xfffffff0, 64))))],
            'services': [{'id': 'child', 'before': [], 'count_diagnostic': 'child-count', 'maximum_calls': 2}],
            'assertions': [], 'outcomes': [{'id': 'normal', 'guard': expression('true', BOOL_SORT).to_payload(),
                'exit': {'kind': 'return', 'value': value('return_target').to_payload(), 'stack_delta': 4,
                         'diagnostic': 'normal-return'}, 'assertions': []}],
            'context_diagnostic': 'source-context', 'memory_diagnostic': 'public-memory'}}
    return protect(contract)
