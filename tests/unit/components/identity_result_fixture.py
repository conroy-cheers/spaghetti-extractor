"""Body-independent returned identities, publication and repeated aliases."""
import json

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, add, all_of, any_of, eq, field, le, named, sub, value, wide, word
from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_register
from spaghetti_extractor.components.bisimulation_native_calls import register
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.service_authoring import signature
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer


REGISTERS = tuple(_Node('reg',aux=i) for i in range(8))+tuple(_Node('flag',aux=i) for i in range(6))


def transfer(rva, nodes, actions, calls=()):
    return _Transfer(f'semantic-transfer:original-cutpoint-{rva:08x}-{rva+1:08x}',
        'a'*64,'b'*64,rva,nodes,(),tuple([*(_Action('eval_word',(i,)) for i in range(len(nodes))),*actions]),tuple(calls),())


def call(rva, *, callee=None):
    event = _Call('external_call' if callee is None else 'internal_call',rva,0,None,callee or 0,rva+1,
        'fixture.dll' if callee is None else None,'allocate' if callee is None else None,None,
        tuple(range(8)),tuple(range(8,14)),(),())
    description = {'id':'allocate','event':{'kind':'import' if callee is None else 'internal',
        'source_rva':rva,'instruction_rva':rva,'target_rva':callee or 0,'return_rva':rva+1,
        'call_index':0,'argument_count':0,'stack_input_count':0,
        **({'dll':'fixture.dll','symbol':'allocate'} if callee is None else {})},
        'entry_stack_delta':0,'arguments':[register('ebx').to_payload()],'requires':[]}
    return event, description


def prepare(root, *, parent=False, edited=False, wrong=False, dereference=False, supplier_transfers=()):
    root.mkdir(parents=True)
    component = 'identity-parent' if parent else 'identity-leaf'
    rows = [signature('run',[('input','u32')],'u32'),signature('allocate',[('input','u32')],'buffer' if parent else 'u32')]
    if parent:
        rows[1][1]['results'][0]['nullable'] = True
    schema = BoundarySchemaV1.create(schema_id=component, types=[
        {'id':'u32','kind':'integer','signed':False,'width_bits':32},
        {'id':'buffer','kind':'opaque','nominal_id':'fixture.buffer'},
        {'id':'cell','kind':'opaque','nominal_id':'fixture.cell'},
        *[r[0] for r in rows]], signatures=[r[1] for r in rows])
    state = {'id':'cell','type_id':'cell','interpretation':'value','nullable':False,'access':'none',
        'extent':{'kind':'none','bytes':None,'value_id':None},'provider_domain':None,'resource_kind':None}
    run = schema.signature_index['run']
    intent = ComponentInterfaceIntentV1.create(component_id=component,schema=schema,
        state=[{'value':state,'initial':None}] if parent else [],effects=[],
        services=[{'id':'allocate','signature_id':'allocate','effect_ids':[],'interaction_contract_id':'runtime.allocate'}],
        protocol_states=['ready'],initial_protocol_state='ready',operations=[{
            'id':'run','signature_id':'run','pre_states':['ready'],'post_states':['ready'],
            'allowed_service_ids':['allocate'],'effect_ids':[],
            'source_values':[p.to_payload() for p in (*run.parameters,*run.results)],
            'projection_entries':[{'source_id':p.identity,'target':{'root':kind,'value_id':p.identity,'fields':[]}}
                for kind,values in [('parameter',run.parameters),('result',run.results)] for p in values],
            'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[state] if parent else []},
            'checked_interaction_contract_ids':[]}])
    (root/'interface').mkdir();(root/'interface/component-interface-intent-v1.json').write_text(json.dumps(intent.to_payload()))
    entry = 0x3000 if parent else 0x2000
    event, native = call(entry,callee=0x2000 if parent else None)
    transfers = [transfer(entry,REGISTERS,[_Action('call',(0,)),_Action('outcome_jump',(entry+1,))],[event])]
    native_calls = [native]
    if parent:
        event,native = call(entry+1,callee=0x2000)
        transfers.append(transfer(entry+1,REGISTERS,
            [_Action('memory_write',(4,0),aux=4),_Action('call',(0,)),_Action('outcome_jump',(entry+2,))],[event]))
        native_calls.append(native)
    end=entry+len(transfers)
    nodes=(*REGISTERS,_Node('load',(7,),aux=4),_Node('const',immediate=4),_Node('add32',(7,15)))
    actions=[_Action('set_reg',(16,),aux=7),_Action('outcome_return',(14,))]
    if parent:
        nodes+=(_Node('load',(4,),aux=4),_Node('eq',(17,0)),_Node('const',immediate=0),
                _Node('eq',(17,19)),_Node('const',immediate=2),_Node('mul32',(20,21)),_Node('add32',(18,22)))
        actions.insert(0,_Action('set_reg',(23,),aux=0))
    transfers.append(transfer(end,nodes,actions))
    write_component_exact_c_slice_v1(component_id=component,transfers=[*transfers,*supplier_transfers],
        operations=[{'operation_id':'run','unit_ids':[t.identity for t in transfers],'entry_rvas':[entry]}],
        intent=None,executable_transfer_plan_sha256='c'*64,summary_entry_rvas=[0x2000] if parent else [],out=root/'exact')
    header='struct spx_opaque_buffer_v5;\nstruct spx_opaque_cell_v5 {struct spx_opaque_buffer_v5 *buffer;};\n'
    code='#include "portable-component-implementation.h"\n#include "objects.h"\n'
    code+=f'uint32_t authored(spx_{component.replace("-","_")}_context_v5 *context,uint32_t input){{\n'
    if parent:
        code+='struct spx_opaque_buffer_v5 *first=context->services->allocate(context->services->context,input);\n'
        code+='context->state.cell->buffer=first;\n'
        code+='struct spx_opaque_buffer_v5 *second=context->services->allocate(context->services->context,input);\n'
        code+='return (context->state.cell->buffer==second)+2U*(first==0);\n'
        if wrong:code=code.replace('cell->buffer=first','cell->buffer=0')
        if dereference:code=code.replace('return (context',
            'if(second){uint8_t byte=*((uint8_t *)second);(void)byte;}\nreturn (context')
    else:
        code+='uint32_t result=context->services->allocate(context->services->context,input);\n'
        if edited:code+='if(result==0U)return 0U;\n'
        code+='return result;\n'
    code+='}\n';(root/'caller.c').write_text(code);(root/'objects.h').write_text(header)
    build_component_source_package(lift_unit_id=component,files={n:root/n for n in ('caller.c','objects.h')},
        shared_inputs={},operation_symbols={'run':'authored'},out_dir=root/'source')
    stack=entry_register('esp');low=sub(wide(stack),constant(8 if parent else 4,64));high=add(wide(stack),constant(4,64))
    contract={'profile':'finite-paired-caller-v1','component_id':component,'operation_id':'run',
        'entry_rva':entry,'unit_rvas':[t.rva_start for t in transfers],
        'suppliers':{'allocate':{'required_frame':['ebx','esi'],'result_transport':{'relation':'record-address'}}} if parent else {},
        'witnesses':{},'runtime_contracts':{} if parent else {'allocate':{
            'id':'fixture-address-result','revision':1,'status':'unverified',
            'normal_return':{'result_field':'eax','stack_delta':0,'preserved_fields':['ebx','esi']},
            'fault':'none','normal_excludes':[],'objects':[],
            'requires':'Same runtime state and synchronous normal outcome.',
            'ensures':'An arbitrary unsigned result; public bytes are preserved.',
            'unverified':['Runtime applicability; no allocation or lifetime guarantee.']}},
        'native_memory':[access('return',stack,read=True)],'native_calls':native_calls,
        'source_services':[{'id':'allocate','views':{},'arguments':[parameter('input',U32).to_payload()],
                            'diagnostic':'allocation-argument'}],
        'boundary':{'image_base':0x400000,'private_low':low.to_payload(),'private_high':high.to_payload(),
            'call_private_low':low.to_payload(),'call_private_high':high.to_payload(),'views':[],
            'event_capacity':4,'call_capacity':2 if parent else 1,
            'values':[{'id':'input','sort':U32.to_payload(),'expression':entry_register('ebx').to_payload()},
                {'id':'return_target','sort':U32.to_payload(),'expression':word('entry_memory',stack).to_payload()}],
            'admission':[named('stack-domain',all_of(le(constant(64 if parent else 32),stack),le(stack,constant(0xfffffff0))))],
            'services':[{'id':'allocate','before':[],'count_diagnostic':'allocate-count','maximum_calls':2 if parent else 1}],
            'assertions':[named('result',eq(value('result'),field('eax'))),
                *[named('preserved-'+r,eq(field(r),entry_register(r))) for r in ('ebx','esi')]],
            'outcomes':[{'id':'normal','guard':expression('true',BOOL_SORT).to_payload(),
                'exit':{'kind':'return','value':value('return_target').to_payload(),'stack_delta':4,
                        'diagnostic':'normal-return'},'assertions':[]}],
            'context_diagnostic':'source-context','memory_diagnostic':'public-memory'}}
    if parent:
        address=entry_register('esi')
        contract['boundary']['admission'].append(named('cell-domain',all_of(le(constant(1),address),
            le(address,constant(0xfffffff0)),any_of(le(add(wide(address),constant(4,64)),low),le(high,wide(address))))))
        contract['boundary']['records']={'header':'objects.h','lifetime':'operation',
            'types':[{'id':'buffer','extent':0,'fields':[],'subobjects':[],'representation':'identity'},
                {'id':'cell','extent':4,'fields':[{'path':['buffer'],'kind':'reference','type_id':'buffer',
                    'nullable':True,'offset':0,'writable':True}],'subobjects':[]}],
            'objects':[{'id':'cell','type_id':'cell','count':1,'address':address.to_payload()},
                {'id':'old','type_id':'buffer','count':1,'address':word('entry_memory',address).to_payload()}],
            'projections':[],'state':{'cell':'cell'}}
    return contract,transfers
