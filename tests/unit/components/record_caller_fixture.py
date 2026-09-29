"""Persistent Hello slot/byte records with two calls and mutable aliases.

This small original is an engine fixture. Its C record definitions are the real
quoting consumer's unchanged header; it is not the complete quoting operation.
"""
import json
from pathlib import Path

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, add, all_of, any_of, eq, field, le, named, sub, value, wide, word
from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_register
from spaghetti_extractor.components.bisimulation_native_calls import register
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.service_authoring import signature, value as c_value
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer

HEADER = Path(__file__).parents[2]/'fixtures/hello-quoting-state/slots/quote-objects.h'
SOURCE = '''#include "portable-component-implementation.h"
#include "quote-objects.h"
struct spx_opaque_quote_bytes_v5 *update_slots(spx_record_consumer_context_v5 *context,
    uint32_t input, struct spx_opaque_quote_bytes_v5 *alias) {
  struct spx_opaque_quote_state_v5 *state=context->state.slots;
  struct spx_opaque_quote_table_v5 *table=state->table;
  table->size+=input;
  uint8_t *buffer=(uint8_t *)table->buffer;
  buffer[0]=(uint8_t)(buffer[0]+1U);
  context->services->mutate(context->services->context,table->buffer);
  uint32_t size=table->size;
  uint32_t observed=((uint8_t *)alias)[0];
  context->services->observe(context->services->context,table->buffer,size,observed);
  return table->buffer;
}
'''


def prepare(root, *, source=SOURCE, header=None):
    root.mkdir(parents=True)
    types = [{'id':'u32','kind':'integer','signed':False,'width_bits':32},{'id':'unit','kind':'void'},
        *({'id':'quote_'+name,'kind':'opaque','nominal_id':'hello.quote.'+name} for name in ('bytes','table','state'))]
    signatures = [signature('run',[('input','u32'),('alias','quote_bytes')],'quote_bytes'),
                  signature('mutate',[('buffer','quote_bytes')],'unit'),
                  signature('observe',[('buffer','quote_bytes'),('size','u32'),('observed','u32')],'unit')]
    schema = BoundarySchemaV1.create(schema_id='record-consumer',types=[*types,*(r[0] for r in signatures)],
                                    signatures=[r[1] for r in signatures])
    sig=schema.signature_index['run']; state=c_value('slots','quote_state')
    intent=ComponentInterfaceIntentV1.create(component_id='record-consumer',schema=schema,
        state=[{'value':state,'initial':None}], effects=[], protocol_states=['ready'],initial_protocol_state='ready',
        services=[{'id':name,'signature_id':name,'effect_ids':[],'interaction_contract_id':'runtime.'+name}
                  for name in ('mutate','observe')], operations=[{'id':'run','signature_id':'run',
            'pre_states':['ready'],'post_states':['ready'],'allowed_service_ids':['mutate','observe'],
            'effect_ids':[],'source_values':[v.to_payload() for v in (*sig.parameters,*sig.results)],
            'projection_entries':[{'source_id':v.identity,'target':{'root':kind,'value_id':v.identity,'fields':[]}}
                for kind,values in [('parameter',sig.parameters),('result',sig.results)] for v in values],
            'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[state]},'checked_interaction_contract_ids':[]}])
    (root/'interface').mkdir()
    (root/'interface/component-interface-intent-v1.json').write_text(json.dumps(intent.to_payload()))
    (root/'quote-objects.h').write_text(HEADER.read_text() if header is None else header)
    (root/'update.c').write_text(source)
    build_component_source_package(lift_unit_id=intent.component_id,files={n:root/n for n in ('quote-objects.h','update.c')},
        shared_inputs={},operation_symbols={'run':'update_slots'},out_dir=root/'source')
    registers=tuple(_Node('reg',aux=i) for i in range(8))+tuple(_Node('flag',aux=i) for i in range(6))
    # Globals point at one live slot. Its buffer and the caller's alias can name
    # either live byte object; their original contents are unconstrained.
    nodes=(*registers,_Node('const',immediate=0x180),_Node('load',(14,),aux=4),
        _Node('load',(15,),aux=4),_Node('add32',(16,1)),_Node('const',immediate=4),
        _Node('add32',(15,18)),_Node('load',(19,),aux=4),_Node('load',(20,),aux=1),
        _Node('const',immediate=1),_Node('add32',(21,22)))
    native=[];transfers=[]
    for i,name in enumerate(('mutate','observe')):
        rva=0x2000+i
        if i:
            nodes=(*registers,_Node('const',immediate=0x180),_Node('load',(14,),aux=4),
                _Node('load',(15,),aux=4),_Node('const',immediate=4),_Node('add32',(15,17)),
                _Node('load',(18,),aux=4),_Node('load',(4,),aux=1))
        at_call=list(range(8));at_call[0]=19 if i else 20
        if i:at_call[2]=16;at_call[3]=20
        event=_Call('external_call',rva,0,None,0,rva+1,'fixture.dll',name,None,
                    tuple(at_call),tuple(range(8,14)),(),())
        actions=[*(_Action('eval_word',(j,)) for j in range(len(nodes)))]
        if not i: actions.extend([_Action('memory_write',(15,17),aux=4),_Action('memory_write',(20,23),aux=1)])
        actions += [_Action('call',(0,)),_Action('outcome_jump',(rva+1,))]
        transfers.append(_Transfer(f'semantic-transfer:original-cutpoint-{rva:08x}-{rva+1:08x}',
            'a'*64,'b'*64,rva,nodes,(),tuple(actions),(event,),()))
        native.append({'id':name,'event':{'kind':'import','source_rva':rva,'instruction_rva':rva,'target_rva':0,
            'return_rva':rva+1,'call_index':0,'argument_count':0,'stack_input_count':0,'dll':'fixture.dll','symbol':name},
            'entry_stack_delta':0,'arguments':[register(n).to_payload() for n in (['eax','ecx','edx'] if i else ['eax'])],
            'requires':[]})
    nodes=(_Node('reg',aux=7),_Node('load',(0,),aux=4),_Node('const',immediate=4),_Node('add32',(0,2)),
           _Node('const',immediate=0x204),_Node('load',(4,),aux=4))
    transfers.append(_Transfer('semantic-transfer:original-cutpoint-00002002-00002003','a'*64,'b'*64,0x2002,nodes,(),
        (*(_Action('eval_word',(j,)) for j in range(len(nodes))),_Action('set_reg',(5,),aux=0),
         _Action('set_reg',(3,),aux=7),_Action('outcome_return',(1,))),(),()))
    write_component_exact_c_slice_v1(component_id=intent.component_id,transfers=transfers,
        operations=[{'operation_id':'run','unit_ids':[t.identity for t in transfers],'entry_rvas':[0x2000]}],
        intent=None,executable_transfer_plan_sha256='c'*64,out=root/'exact')
    def span(address,extent,permission):
        return {'address':constant(address).to_payload(),'extent':constant(extent).to_payload(),'permissions':permission}
    runtime={name:{'id':'fixture-'+name,'revision':1,'status':'unverified',
        'normal_return':{'result_field':None,'stack_delta':0,'preserved_fields':['ebp','ebx','edi','esi']},
        'fault':'none','normal_excludes':[],'requires':'Incoming record inventory remains live for the operation.',
        'ensures':'Normal synchronous service; changes only declared bytes; no escaping reference.',
        'unverified':['Concrete service applicability, incoming lifetime, no allocation or release.'],
        'objects':([span(0x200,4,3),span(0x300,1,3),span(0x304,1,3)] if name=='mutate' else
                   [span(0x200,8,1),span(0x300,1,1),span(0x304,1,1)])} for name in ('mutate','observe')}
    def reference(path,**placement):
        return {'path':[path],'kind':'reference','writable':False,'nullable':False,
                'type_id':'quote_table' if path in {'table','initial_table'} else 'quote_bytes',**placement}
    records={'header':'quote-objects.h','lifetime':'operation','types':[
        {'id':'quote_table','extent':8,'fields':[{'path':['size'],'kind':'word','writable':True,'offset':0},
            reference('buffer',offset=4)],'subobjects':[]},
        {'id':'quote_bytes','extent':1,'fields':[],'subobjects':[]}],
        'objects':[{'id':name,'type_id':kind,'count':1,'address':constant(address).to_payload()}
            for name,kind,address in [('table','quote_table',0x200),('buffer-a','quote_bytes',0x300),('buffer-b','quote_bytes',0x304)]],
        'projections':[{'id':'state','type_id':'quote_state','fields':[
            reference('table',address=constant(0x180).to_payload()),
            {'path':['count'],'kind':'word','writable':False,'address':constant(0x184).to_payload()},
            reference('initial_table',value=constant(0x200).to_payload()),
            reference('initial_buffer',value=constant(0x300).to_payload())]}], 'state':{'slots':'state'}}
    stack=entry_register('esp');low=sub(wide(stack),constant(4,64));high=add(wide(stack),constant(4,64))
    contract={'profile':'finite-paired-caller-v1','component_id':intent.component_id,'operation_id':'run',
        'entry_rva':0x2000,'unit_rvas':[0x2000,0x2001,0x2002],'suppliers':{},'witnesses':{},
        'native_memory':[access('return',stack,read=True)],'native_calls':native,'runtime_contracts':runtime,
        'source_services':[{'id':name,'views':{},'arguments':[parameter(p.identity,U32).to_payload()
                           for p in schema.signature_index[name].parameters], 'diagnostic':name+'-arguments'} for name in runtime],
        'boundary':{'image_base':0x400000,'private_low':low.to_payload(),'private_high':high.to_payload(),
            'call_private_low':low.to_payload(),'call_private_high':high.to_payload(),'views':[],'records':records,
            'event_capacity':8,'call_capacity':2,'values':[
                {'id':'input','sort':U32.to_payload(),'expression':entry_register('ebx').to_payload()},
                {'id':'alias','sort':U32.to_payload(),'expression':entry_register('esi').to_payload()},
                {'id':'return_target','sort':U32.to_payload(),'expression':word('entry_memory',stack).to_payload()}],
            'admission':[named('stack-domain',all_of(le(constant(0x500),stack),le(wide(stack),constant(0xfffffff0,64)))),
                named('incoming-table',eq(word('entry_memory',constant(0x180)),constant(0x200))),
                named('incoming-buffer',any_of(*(eq(word('entry_memory',constant(0x204)),constant(a)) for a in (0x300,0x304)))),
                named('incoming-alias',any_of(*(eq(value('alias'),constant(a)) for a in (0x300,0x304))))],
            'services':[{'id':name,'before':[],'count_diagnostic':name+'-count','maximum_calls':1} for name in runtime],
            'assertions':[named('returned-buffer',eq(field('eax'),value('result')))],
            'outcomes':[{'id':'normal','guard':expression('true',BOOL_SORT).to_payload(),
                'exit':{'kind':'return','value':value('return_target').to_payload(),'stack_delta':4,'diagnostic':'normal-return'},
                'assertions':[]}], 'context_diagnostic':'source-context','memory_diagnostic':'public-memory'}}
    (root/'contract.json').write_text(json.dumps(contract))
    return contract
