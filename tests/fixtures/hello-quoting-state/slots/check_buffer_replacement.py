"""Check Hello's real release -> allocation -> publication continuation.

This retains actual transfers and source statements. The free supplier is checked;
allocation is an explicit conditional runtime premise, not an allocation/lifetime
theorem. Entry applicability and composition with the complete quoter remain open.
"""
import argparse
import json
from pathlib import Path
import shutil
import time
from unittest.mock import patch

from prepare import interface
from record_layout import record_types
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, add, all_of, any_of, choose, eq, field, le, named, negate, sub, value, wide, word
from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_register
from spaghetti_extractor.components.bisimulation_native_calls import stack_word
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.service_authoring import signature
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent


def check(retained,supplier,out):
    started=time.monotonic();out.mkdir(parents=True)
    inventory=json.loads((retained/'inventory.json').read_text());plan=Path(inventory['plan'])
    assert sha256_file(plan)==inventory['plan_sha256']
    _,transfers=load_executable_transfer_plan(plan,require_complete=False)
    units=[0x4fc3,0x4fcf,0x4fd3,0x4fdf];original=[t for t in transfers if t.rva_start in units]
    assert len(original)==4
    full=interface();function,sig=signature('replace',[('slot','quote_table'),('size','u32'),('buffer','quote_bytes')],'quote_bytes')
    sig['parameters'][2]['nullable']=True;sig['results'][0]['nullable']=True
    schema=BoundarySchemaV1.create(schema_id='quote-replacement',types=[*[t.to_payload() for t in full.schema.types],function],
        signatures=[*[s.to_payload() for s in full.schema.signatures],sig])
    selected=[s for s in full.services if s['id'] in {'release_buffer','allocate_buffer'}]
    intent=ComponentInterfaceIntentV1.create(component_id='quote-buffer-replacement',schema=schema,
        state=[],effects=[],services=selected,protocol_states=['ready'],initial_protocol_state='ready',operations=[{
            'id':'replace','signature_id':'replace','pre_states':['ready'],'post_states':['ready'],
            'allowed_service_ids':[s['id'] for s in selected],'effect_ids':[],
            'source_values':[*sig['parameters'],*sig['results']],
            'projection_entries':[{'source_id':p['id'],'target':{'root':kind,'value_id':p['id'],'fields':[]}}
                for kind,values in [('parameter',sig['parameters']),('result',sig['results'])] for p in values],
            'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[]},'checked_interaction_contract_ids':[]}])
    (out/'interface').mkdir();write_json(out/'interface/component-interface-intent-v1.json',intent.to_payload())
    write_component_exact_c_slice_v1(component_id=intent.component_id,transfers=transfers,
        operations=[{'operation_id':'replace','unit_ids':[t.identity for t in original],'entry_rvas':[units[0]]}],
        intent=None,executable_transfer_plan_sha256=sha256_file(plan),summary_entry_rvas=[0x1b34,0x6255],out=out/'exact')
    fragments=['services->release_buffer(environment, buffer);',
        'buffer = services->allocate_buffer(environment, size);','slot->buffer = buffer;']
    for fragment in fragments:assert (HERE/'quote-slots.c').read_text().count(fragment)==1
    source='''#include "portable-component-implementation.h"
#include "quote-objects.h"
struct spx_opaque_quote_bytes_v5 *replace_buffer(spx_quote_buffer_replacement_context_v5 *context,
    struct spx_opaque_quote_table_v5 *slot,uint32_t size,struct spx_opaque_quote_bytes_v5 *buffer){
const spx_quote_buffer_replacement_services_v5 *services=context->services;
void *environment=services->context;
'''+ '\n'.join(fragments)+'\nreturn buffer;\n}\n'
    (out/'region.c').write_text(source);shutil.copyfile(HERE/'quote-objects.h',out/'quote-objects.h')
    build_component_source_package(lift_unit_id=intent.component_id,
        files={n:out/n for n in ('region.c','quote-objects.h')},shared_inputs={},
        operation_symbols={'replace':'replace_buffer'},out_dir=out/'source')
    stack=entry_register('esp');slot=entry_register('edi')
    low=sub(wide(stack),constant(64,64));high=add(wide(stack),constant(56,64));end=add(wide(slot),constant(8,64))
    slot_first=le(end,low)
    first_low=choose(slot_first,wide(slot),low);first_high=choose(slot_first,end,high)
    second_low=choose(slot_first,low,wide(slot));second_high=choose(slot_first,high,end)
    spans=[(constant(0),first_low),(expression('truncate',U32,first_high),sub(second_low,first_high)),
           (expression('truncate',U32,second_high),sub(constant(2**32,64),second_high))]
    calls=[]
    for t in original:
        for c in t.calls:
            identity={0x1b34:'release_buffer',0x6255:'allocate_buffer'}[c.target_rva]
            calls.append({'id':identity,'event':{'kind':'internal','source_rva':t.rva_start,
                'instruction_rva':c.instruction_rva,'target_rva':c.target_rva,'return_rva':c.return_rva,
                'call_index':c.call_index,'argument_count':len(c.argument_nodes),'stack_input_count':len(c.stack_inputs)},
                'entry_stack_delta':0,'arguments':[stack_word(0).to_payload()],'requires':[]})
    types=[row for row in record_types() if row['id'] in {'quote_bytes','quote_table'}]
    types[0].update(representation='identity',extent=0)
    contract={'profile':'finite-paired-caller-v1','component_id':intent.component_id,'operation_id':'replace',
        'entry_rva':units[0],'unit_rvas':units,
        'suppliers':{'release_buffer':{'required_frame':['ebp','ebx','edi','esi'],
            'bindings':{'protected_low':first_low.to_payload(),'protected_high':second_high.to_payload()},
            'parameter_transport':{'allocation_token':{'parameter':'buffer','relation':'record-address'}}}},
        'witnesses':{},'runtime_contracts':{'allocate_buffer':{
            'id':'hello-xcharalloc-normal-return','revision':1,'status':'unverified',
            'normal_return':{'result_field':'eax','stack_delta':0,'preserved_fields':['ebp','ebx','edi','esi']},
            'fault':'none','normal_excludes':[],
            'objects':[{'address':address.to_payload(),'extent':extent.to_payload(),'permissions':3} for address,extent in spans],
            'requires':'A synchronous normal allocation call preserving this live slot and continuation frame.',
            'ensures':'Related unsigned result and corresponding arbitrary memory effects outside the protected slot and frame.',
            'unverified':['Actual allocator applicability, allocation failure/nonreturn outcomes, heap lifetime and native admission.']}},
        'native_memory':[access('argument',stack,read=True,write=True,storage='private'),
            access('saved_size',add(stack,constant(52)),read=True,write=True,storage='private'),
            access('incoming_argument',add(stack,constant(40)),read=True)],
        'native_calls':calls,
        'source_services':[{'id':name,'views':{},'arguments':[parameter(param,U32).to_payload()],
            'diagnostic':name+'-argument'} for name,param in [('release_buffer','buffer'),('allocate_buffer','size')]],
        'boundary':{'image_base':0x400000,'private_low':low.to_payload(),'private_high':high.to_payload(),
            'call_private_low':low.to_payload(),'call_private_high':high.to_payload(),'views':[],
            'records':{'header':'quote-objects.h','lifetime':'operation','types':types,
                'objects':[{'id':'slot','type_id':'quote_table','count':1,'address':slot.to_payload()},
                    {'id':'buffer','type_id':'quote_bytes','count':1,'address':value('buffer').to_payload()}],
                'projections':[],'state':{}},'event_capacity':12,'call_capacity':2,
            'values':[{'id':name,'sort':U32.to_payload(),'expression':entry_register(reg).to_payload()}
                for name,reg in [('buffer','esi'),('size','edx'),('slot','edi')]],
            'admission':[named('stack-domain',all_of(le(constant(256),stack),le(stack,constant(0xffffff00)))),
                named('slot-domain',all_of(le(constant(1),slot),le(slot,constant(0xfffffff0)),
                    any_of(le(end,low),le(high,wide(slot))))),
                named('slot-buffer',eq(word('entry_memory',add(slot,constant(4))),value('buffer'))),
                named('stack-import-separation',any_of(le(high,constant(0x4321e4,64)),le(constant(0x4321e8,64),low))),
                named('nonnull-errno-target',negate(eq(word('entry_memory',constant(0x4321e4)),constant(0))))],
            'services':[{'id':name,'before':[],'count_diagnostic':name+'-count','maximum_calls':1}
                        for name in ('release_buffer','allocate_buffer')],
            'assertions':[named('returned-buffer',eq(value('result'),field('eax'))),
                named('continued-buffer',eq(value('result'),field('esi'))),
                named('saved-size',eq(value('private.saved_size'),value('size'))),
                named('continued-size',eq(field('edx'),value('size'))),
                named('continued-argument',eq(field('ecx'),word('entry_memory',add(stack,constant(40))))),
                *[named('preserved-'+r,eq(field(r),entry_register(r))) for r in ('ebp','ebx','edi')]],
            'outcomes':[{'id':'next','guard':expression('true',BOOL_SORT).to_payload(),
                'exit':{'kind':'fallthrough','rva':0x4fec,'diagnostic':'publication-continuation'},'assertions':[]}],
            'context_diagnostic':'replacement-context','memory_diagnostic':'replacement-public-memory'}}
    write_json(out/'caller-contract.json',contract);preparation_seconds=time.monotonic()-started
    def prepare(source,output):
        result=write_component_source_check(target_id='gnu-hello',component_id=intent.component_id,
            interface_package=out/'interface',source_package=source,out=output,
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('i686-w64-mingw32-gcc')))
        assert result['status']=='complete',result
    prepare(out/'source',out/'preparation')
    def invoke(name,source=None,preparation=None,previous=None):
        folder=out/name;begin=time.monotonic();phases=[]
        status=write_component_source_call_check(target_id='gnu-hello',component_id=intent.component_id,
            preparation=preparation or out/'preparation',exact=out/'exact',supplier={'release_buffer':supplier},
            contract=contract,source_package=source or out/'source',interface_package=out/'interface',
            out=folder/'feedback',workspace=folder/'work',goto_cc=Path(shutil.which('goto-cc')),
            cbmc=Path(shutil.which('cbmc')),smt_solver=None,unwind=16,timeout_seconds=90,previous=previous,timings=phases)
        result=json.loads((folder/'feedback/caller-comparison/result.json').read_text())
        row={'status':status['status'],'seconds':time.monotonic()-begin,'phases':phases,'reuse':result['reuse'],
            'result':str(folder/'feedback/caller-comparison/result.json'),
            'sha256':sha256_file(folder/'feedback/caller-comparison/result.json')}
        write_json(folder/'validation.json',row);print(json.dumps({'case':name,**row}),flush=True)
        return status,result,row
    status,baseline,positive=invoke('positive');assert status['status']=='complete',baseline['checks']
    with patch('subprocess.run',side_effect=AssertionError('reuse invoked tools')),patch.object(
            checker,'render_caller_boundary',side_effect=AssertionError('reuse generated model')):
        status,reused,reuse=invoke('reuse',previous=out/'positive/feedback')
    assert status['status']=='complete' and reused['proof_key']==baseline['proof_key'] and reused['proof_files']==baseline['proof_files']
    assert reused['reuse']=={'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0}
    (out/'wrong.c').write_text(source.replace('slot->buffer = buffer;','slot->buffer = 0;'))
    build_component_source_package(lift_unit_id=intent.component_id,
        files={'region.c':out/'wrong.c','quote-objects.h':out/'quote-objects.h'},shared_inputs={},
        operation_symbols={'replace':'replace_buffer'},out_dir=out/'wrong-source')
    prepare(out/'wrong-source',out/'wrong-preparation')
    status,result,negative=invoke('wrong-publication',out/'wrong-source',out/'wrong-preparation')
    assert status['status']=='violated',result['checks']
    report={'status':'pass','authorizing':False,'whole_component_complete':False,'scope':__doc__,
        'preparation_seconds':preparation_seconds,'seconds':time.monotonic()-started,
        'positive':positive,'reuse':reuse,'wrong_publication':negative,
        'inputs':{str(p):sha256_file(p) for p in [plan,retained/'inventory.json',HERE/'quote-slots.c',HERE/'quote-objects.h',
            HERE/'prepare.py',HERE/'record_layout.py',Path(__file__),supplier/'caller-comparison/result.json']},
        'remaining':['Region entry applicability and following quote/errno/return composition.',
            'Actual allocation outcomes/effects, native lifetimes and growing arrays.',
            'Complete quoting theorem and native admission.']}
    write_json(out/'validation.json',report)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('retained',type=Path);parser.add_argument('supplier',type=Path);parser.add_argument('out',type=Path)
    args=parser.parse_args();check(args.retained.resolve(),args.supplier.resolve(),args.out.resolve())
