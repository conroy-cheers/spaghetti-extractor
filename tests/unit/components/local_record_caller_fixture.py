"""Ordinary local quoting-count records passed to a mutable synchronous service."""
import json
from pathlib import Path

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, add, all_of, eq, field, le, named, sub, value, wide, word
from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_offset, entry_register, private_bytes
from spaghetti_extractor.components.bisimulation_native_calls import register
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.service_authoring import signature
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer

HEADER = Path(__file__).parents[2]/'fixtures/hello-quoting-state/slots/quote-objects.h'
SOURCE = '''#include "portable-component-implementation.h"
#include "quote-objects.h"
uint32_t update_count(spx_local_record_consumer_context_v5 *context,uint32_t input){
 struct spx_opaque_quote_word_v5 count={.value=input};
 context->services->mutate(context->services->context,&count,&count);
 return count.value;
}
'''


def prepare(root, *, source=SOURCE, header=None):
    root.mkdir(parents=True)
    rows = [signature('run',[('input','u32')],'u32'),
            signature('mutate',[('count','quote_word'),('alias','quote_word')],'unit')]
    schema = BoundarySchemaV1.create(schema_id='local-record-consumer', types=[
        {'id':'u32','kind':'integer','signed':False,'width_bits':32}, {'id':'unit','kind':'void'},
        {'id':'quote_word','kind':'opaque','nominal_id':'hello.quote.word'}, *(row[0] for row in rows)],
        signatures=[row[1] for row in rows])
    signature_run = schema.signature_index['run']
    intent = ComponentInterfaceIntentV1.create(component_id='local-record-consumer',schema=schema,
        state=[],effects=[],protocol_states=['ready'],initial_protocol_state='ready',
        services=[{'id':'mutate','signature_id':'mutate','effect_ids':[],'interaction_contract_id':'runtime.mutate'}],
        operations=[{'id':'run','signature_id':'run','pre_states':['ready'],'post_states':['ready'],
            'allowed_service_ids':['mutate'],'effect_ids':[],
            'source_values':[v.to_payload() for v in (*signature_run.parameters,*signature_run.results)],
            'projection_entries':[{'source_id':v.identity,'target':{'root':kind,'value_id':v.identity,'fields':[]}}
                for kind,values in [('parameter',signature_run.parameters),('result',signature_run.results)] for v in values],
            'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[]},'checked_interaction_contract_ids':[]}])
    (root/'interface').mkdir()
    (root/'interface/component-interface-intent-v1.json').write_text(json.dumps(intent.to_payload()))
    (root/'quote-objects.h').write_text(HEADER.read_text() if header is None else header)
    (root/'update.c').write_text(source)
    build_component_source_package(lift_unit_id=intent.component_id,
        files={name:root/name for name in ('quote-objects.h','update.c')},shared_inputs={},
        operation_symbols={'run':'update_count'},out_dir=root/'source')
    ids=[f'semantic-transfer:original-cutpoint-{rva:08x}-{rva+1:08x}' for rva in range(0x2000,0x2003)]
    registers=tuple(_Node('reg',aux=i) for i in range(8))+tuple(_Node('flag',aux=i) for i in range(6))
    event=_Call('external_call',0x2001,0,None,0,0x2002,'fixture.dll','mutate',None,
                tuple(range(8)),tuple(range(8,14)),(),())
    entry=(*registers,_Node('const',immediate=8),_Node('sub32',(7,14)))
    finish=(_Node('reg',aux=7),_Node('load',(0,),aux=4),_Node('const',immediate=8),
            _Node('add32',(0,2)),_Node('load',(3,),aux=4),_Node('const',immediate=4),_Node('add32',(3,5)))
    transfers=[
        _Transfer(ids[0],'a'*64,'b'*64,0x2000,entry,(),
            (*(_Action('eval_word',(j,)) for j in range(len(entry))),_Action('memory_write',(15,1),aux=4),
             _Action('set_reg',(15,),aux=0),_Action('set_reg',(15,),aux=2),_Action('set_reg',(15,),aux=7),
             _Action('outcome_jump',(0x2001,))),(),()),
        _Transfer(ids[1],'a'*64,'b'*64,0x2001,registers,(),
            (*(_Action('eval_word',(j,)) for j in range(len(registers))),_Action('call',(0,)),
             _Action('outcome_jump',(0x2002,))),(event,),()),
        _Transfer(ids[2],'a'*64,'b'*64,0x2002,finish,(),
            (*(_Action('eval_word',(j,)) for j in range(len(finish))),_Action('set_reg',(1,),aux=0),
             _Action('set_reg',(6,),aux=7),_Action('outcome_return',(4,))),(),())]
    write_component_exact_c_slice_v1(component_id=intent.component_id,transfers=transfers,
        operations=[{'operation_id':'run','unit_ids':ids,'entry_rvas':[0x2000]}],intent=None,
        executable_transfer_plan_sha256='c'*64,out=root/'exact')
    stack=entry_register('esp');address=entry_offset('esp',-8)
    low=sub(wide(stack),constant(12,64));high=add(wide(stack),constant(4,64))
    contract={'profile':'finite-paired-caller-v1','component_id':intent.component_id,'operation_id':'run',
        'entry_rva':0x2000,'unit_rvas':[0x2000,0x2001,0x2002],'suppliers':{},'witnesses':{},
        'native_memory':[private_bytes('count',address,4),access('return',stack,read=True)],
        'native_calls':[{'id':'mutate','event':{'kind':'import','source_rva':0x2001,'instruction_rva':0x2001,
            'target_rva':0,'return_rva':0x2002,'call_index':0,'argument_count':0,'stack_input_count':0,
            'dll':'fixture.dll','symbol':'mutate'},'entry_stack_delta':-8,
            'arguments':[register('eax').to_payload(),register('ecx').to_payload()],'requires':[]}],
        'runtime_contracts':{'mutate':{'id':'local-record-mutation','revision':1,'status':'unverified',
            'normal_return':{'result_field':None,'stack_delta':0,'preserved_fields':['ebp','ebx','edi','esi']},
            'fault':'none','normal_excludes':[],'requires':'Live local records at the declared addresses.',
            'ensures':'Normal return, only declared bytes changed; no references retained.',
            'unverified':['Concrete service applicability and absence of escaping local references.'],
            'objects':[{'parameter':name} for name in ('count','alias')]}},
        'source_services':[{'id':'mutate','views':{},'records':{'count':'count','alias':'count-alias'},
            'arguments':[parameter(name,U32).to_payload() for name in ('count','alias')],'diagnostic':'mutate-arguments'}],
        'boundary':{'image_base':0x400000,'private_low':low.to_payload(),'private_high':high.to_payload(),
            'call_private_low':low.to_payload(),'call_private_high':high.to_payload(),'views':[],
            'records':{'header':'quote-objects.h','lifetime':'operation','types':[
                {'id':'quote_word','extent':4,'fields':[{'path':['value'],'offset':0,'kind':'word','writable':True}],
                 'subobjects':[]}], 'objects':[],'projections':[],'state':{}},
            'local_records':[{'id':name,'type_id':'quote_word','address':address.to_payload(),'permissions':3}
                             for name in ('count','count-alias')],
            'private_byte_capacity':4,'event_capacity':2,'call_capacity':1,
            'values':[{'id':'input','sort':U32.to_payload(),'expression':entry_register('ebx').to_payload()},
                {'id':'return_target','sort':U32.to_payload(),'expression':word('entry_memory',stack).to_payload()}],
            'admission':[named('stack-domain',all_of(le(constant(16),stack),
                le(wide(stack),constant(0xfffffff0,64))))],
            'services':[{'id':'mutate','before':[],'count_diagnostic':'one-mutation','maximum_calls':1}],
            'assertions':[named('updated-count',eq(field('eax'),value('result')))],
            'outcomes':[{'id':'normal','guard':expression('true',BOOL_SORT).to_payload(),
                'exit':{'kind':'return','value':value('return_target').to_payload(),'stack_delta':4,'diagnostic':'normal-return'},
                'assertions':[]}],'context_diagnostic':'source-context','memory_diagnostic':'public-memory'}}
    (root/'contract.json').write_text(json.dumps(contract))
    return contract
