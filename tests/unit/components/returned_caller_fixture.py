"""A complete void caller with repeated, potentially aliasing borrowed returns."""
import json

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, all_of, any_of, add, eq, le, named, negate, sub, value, wide, word
from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_register
from spaghetti_extractor.components.bisimulation_native_calls import register
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer


def prepare(root, *, variant='valid', transfers_out=None):
    captured = variant == 'captured'
    root.mkdir(parents=True)
    scalar={'id':'input','type_id':'u32','interpretation':'value','nullable':False,'access':'none',
            'extent':{'kind':'none','bytes':None,'value_id':None},'provider_domain':None,'resource_kind':None}
    view={'id':'cell','type_id':'bytes','interpretation':'view','nullable':False,'access':'read_write',
          'extent':{'kind':'fixed','bytes':4,'value_id':None},'provider_domain':None,'resource_kind':None}
    schema=BoundarySchemaV1.create(schema_id='returned-consumer',types=[
        {'id':'u8','kind':'integer','signed':False,'width_bits':8},
        {'id':'u32','kind':'integer','signed':False,'width_bits':32}, {'id':'unit','kind':'void'},
        {'id':'bytes','kind':'pointer','pointee_type_id':'u8','qualifiers':[]},
        {'id':'cell.fn','kind':'function','calling_convention':'cdecl','parameter_type_ids':[],
         'result_type_id':'bytes','variadic':False},
        {'id':'run.fn','kind':'function','calling_convention':'cdecl','parameter_type_ids':['u32'],
         'result_type_id':'unit','variadic':False}],signatures=[
        {'id':'cell','function_type_id':'cell.fn','parameters':[],'results':[view]},
        {'id':'run','function_type_id':'run.fn','parameters':[scalar],'results':[]}])
    intent=ComponentInterfaceIntentV1.create(component_id='returned-consumer',schema=schema,state=[],
        services=[{'id':name,'signature_id':sig,'effect_ids':[],'interaction_contract_id':'runtime.'+name}
                  for name,sig in [('cell','cell'),('observe','run')]],effects=[],
        protocol_states=['ready'],initial_protocol_state='ready',operations=[{
            'id':'run','signature_id':'run','pre_states':['ready'],'post_states':['ready'],
            'allowed_service_ids':['cell','observe'],'effect_ids':[],'source_values':[scalar],
            'projection_entries':[{'source_id':'input','target':{'root':'parameter','value_id':'input','fields':[]}}],
            'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[]},'checked_interaction_contract_ids':[]}])
    (root/'interface').mkdir()
    (root/'interface/component-interface-intent-v1.json').write_text(json.dumps(intent.to_payload()))
    registers=tuple(_Node('reg',aux=i) for i in range(8))+tuple(_Node('flag',aux=i) for i in range(6))
    transfers=[];calls=[];units=list(range(0x2000,0x2004))
    for i,rva in enumerate(units[:3]):
        name='observe' if i==2 else 'cell'
        nodes=registers+((_Node('load',(0,),aux=4),) if i==2 else ())
        if captured and i==0:
            nodes += (_Node('const',immediate=0x400300),_Node('load',(14,),aux=4))
        registers_at_call = list((14,*range(1,8)) if i==2 else range(8))
        if captured and i==0: registers_at_call[4]=15
        indirect = captured and i<2
        event=_Call('indirect_call' if indirect else 'external_call',rva,0,
            (15 if i==0 else 4) if indirect else None,0,rva+1,
            None if indirect else 'fixture.dll',None if indirect else name,None,
            tuple(registers_at_call),tuple(range(8,14)),(),())
        actions=[*(_Action('eval_word',(n,)) for n in range(len(nodes)))]
        if captured and i==0: actions.append(_Action('set_reg',(15,),aux=4))
        if i==1:actions.append(_Action('memory_write',(0,1),aux=4))
        actions.extend([_Action('call',(0,)),_Action('outcome_jump',(rva+1,))])
        transfers.append(_Transfer(f'semantic-transfer:original-cutpoint-{rva:08x}-{rva+1:08x}',
            'a'*64,'b'*64,rva,nodes,(),tuple(actions),(event,),()))
        calls.append({'id':name,'event':{'kind':'indirect' if indirect else 'import','source_rva':rva,'instruction_rva':rva,
            'target_rva':0,'return_rva':rva+1,'call_index':0,'argument_count':0,'stack_input_count':0,
            **({} if indirect else {'dll':'fixture.dll','symbol':name})},'entry_stack_delta':0,
            'arguments':[register('eax').to_payload()] if i==2 else [],'requires':[]})
    nodes=(_Node('reg',aux=7),_Node('load',(0,),aux=4),_Node('const',immediate=4),_Node('add32',(0,2)))
    transfers.append(_Transfer('semantic-transfer:original-cutpoint-00002003-00002004','a'*64,'b'*64,0x2003,nodes,(),
        (*(_Action('eval_word',(n,)) for n in range(4)),_Action('set_reg',(3,),aux=7),
         _Action('outcome_return',(1,))),(),()))
    if transfers_out is not None:
        transfers_out.extend(transfers)
    write_component_exact_c_slice_v1(component_id=intent.component_id,transfers=transfers,
        operations=[{'operation_id':'run','unit_ids':[t.identity for t in transfers],'entry_rvas':[0x2000]}],
        intent=None,executable_transfer_plan_sha256='c'*64,out=root/'exact')
    code='''#include "portable-component-implementation.h"
void authored(spx_returned_consumer_context_v5 *context,uint32_t input){
 spx_view_v5 a=context->services->cell(context->services->context);
 (void)a.write(a.access_context,a.base,0U,4U,input);
 spx_view_v5 b=context->services->cell(context->services->context);
 uint64_t observed=0U;
 (void)b.read(b.access_context,b.base,0U,4U,&observed);
 context->services->observe(context->services->context,(uint32_t)observed);
}
'''
    if variant=='stale':code=code.replace('uint64_t observed=0U;',
        'uint64_t observed=0U; (void)a.read(a.access_context,a.base,0U,4U,&observed);')
    if variant=='wrong':code=code.replace('4U,input);','4U,input ^ 1U);')
    (root/'caller.c').write_text(code)
    build_component_source_package(lift_unit_id=intent.component_id,files={'caller.c':root/'caller.c'},
        shared_inputs={},operation_symbols={'run':'authored'},out_dir=root/'source')
    stack=entry_register('esp');low=sub(wide(stack),constant(4,64));high=add(wide(stack),constant(4,64))
    runtime={name:{'id':'fixture-'+name,'revision':1,'status':'unverified',
        'normal_return':{'result_field':'eax' if name=='cell' else None,'stack_delta':0,
            'preserved_fields':['ebp','ebx','edi','esi']},'fault':'none','normal_excludes':[],
        'objects':[],'requires':'Same runtime state; normal synchronous calls.',
        'ensures':'Preserves current public bytes; no escaping reference.',
        'unverified':['Runtime applicability and borrowed range lifetime.']} for name in ('cell','observe')}
    runtime['cell']['returned_view']={'contents':'current-memory','lifetime':'until-next-call','private_frame':'disjoint'}
    contract = {'profile':'finite-paired-caller-v1','component_id':intent.component_id,'operation_id':'run',
        'entry_rva':0x2000,'unit_rvas':units,'suppliers':{},'witnesses':{},'runtime_contracts':runtime,
        'native_memory':[access('return',stack,read=True)],'native_calls':calls,
        'source_services':[{'id':name,'views':{},'arguments':[parameter('input',U32).to_payload()] if name=='observe' else [],
                            'diagnostic':name+'-arguments'} for name in ('cell','observe')],
        'boundary':{'image_base':0x400000,'private_low':low.to_payload(),'private_high':high.to_payload(),
            'call_private_low':low.to_payload(),'call_private_high':high.to_payload(),'views':[],
            'event_capacity':3,'call_capacity':3,'values':[
                {'id':'input','sort':U32.to_payload(),'expression':entry_register('ebx').to_payload()},
                {'id':'return_target','sort':U32.to_payload(),'expression':word('entry_memory',stack).to_payload()}],
            'admission':[named('stack-domain',all_of(le(constant(16),stack),
                le(wide(stack),constant(0xfffffff0,64))))],
            'services':[{'id':name,'before':[],'count_diagnostic':name+'-count','maximum_calls':count}
                        for name,count in [('cell',2),('observe',1)]],
            'assertions':[],'outcomes':[{'id':'normal','guard':expression('true',BOOL_SORT).to_payload(),
                'exit':{'kind':'return','value':value('return_target').to_payload(),'stack_delta':4,
                        'diagnostic':'normal-return'},'assertions':[]}],
            'context_diagnostic':'source-context','memory_diagnostic':'public-memory'}}
    if captured:
        slot=constant(0x400300)
        runtime['cell'].update(target_sampling='operation_entry',
            captured_target_projection={'kind':'static_slot','at':'entry','width':32,'rva':0x300})
        contract['native_memory'].append(access('import-slot',slot,read=True))
        contract['boundary']['admission'].extend([
            named('import-slot-outside-stack',any_of(le(high,wide(slot)),le(constant(0x400304,64),low))),
            named('nonnull-import-target',negate(eq(word('entry_memory',slot),constant(0))))])
    return contract
