"""Check the actual quoting free-call region with an absent checked supplier.

This proof-only projection is not a replacement component or a complete quoting
theorem. Its incoming register/stack relation and the supplier's runtime premises
remain conditional; the original transfer and source call are retained exactly.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import shutil
import time
from unittest.mock import patch

from prepare import interface
from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, add, all_of, any_of, eq, field, le, named, negate, sub, value, wide, word
from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_register
from spaghetti_extractor.components.bisimulation_native_calls import stack_word
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.relation_ir import BOOL_SORT
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan
from spaghetti_extractor.util import sha256_file, write_json

HERE=Path(__file__).resolve().parent


def check(retained, supplier, out):
    started=time.monotonic();out.mkdir(parents=True)
    inventory=json.loads((retained/'inventory.json').read_text())
    plan=Path(inventory['plan']);assert sha256_file(plan)==inventory['plan_sha256']
    _,transfers=load_executable_transfer_plan(plan,require_complete=False)
    original,=[t for t in transfers if t.rva_start==0x4fc3]
    call,=original.calls
    assert call.target_rva==0x1b34 and call.return_rva==0x4fcf and call.instruction_rva==0x4fca
    full=interface();service=next(s for s in full.services if s['id']=='release_buffer')
    signature=full.schema.signature_index[service['signature_id']]
    intent=ComponentInterfaceIntentV1.create(component_id='quote-release-region',schema=full.schema,
        state=[],effects=[],services=[service],protocol_states=['ready'],initial_protocol_state='ready',
        operations=[{'id':'release-region','signature_id':service['signature_id'],'pre_states':['ready'],
            'post_states':['ready'],'allowed_service_ids':['release_buffer'],'effect_ids':[],
            'source_values':[p.to_payload() for p in signature.parameters],
            'projection_entries':[{'source_id':p.identity,'target':{'root':'parameter','value_id':p.identity,'fields':[]}}
                                  for p in signature.parameters],
            'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[]},'checked_interaction_contract_ids':[]}])
    (out/'interface').mkdir();write_json(out/'interface/component-interface-intent-v1.json',intent.to_payload())
    write_component_exact_c_slice_v1(component_id=intent.component_id,transfers=transfers,
        operations=[{'operation_id':'release-region','unit_ids':[original.identity],'entry_rvas':[0x4fc3]}],
        intent=None,executable_transfer_plan_sha256=sha256_file(plan),summary_entry_rvas=[0x1b34],out=out/'exact')
    fragment='services->release_buffer(environment, buffer);'
    assert (HERE/'quote-slots.c').read_text().count(fragment)==1
    source=('#include "portable-component-implementation.h"\n'
        'void release_region(spx_quote_release_region_context_v5 *context,struct spx_opaque_quote_bytes_v5 *buffer){\n'
        'const spx_quote_release_region_services_v5 *services=context->services;\n'
        'void *environment=services->context;\n'+fragment+'\n}\n')
    (out/'region.c').write_text(source);shutil.copyfile(HERE/'quote-objects.h',out/'quote-objects.h')
    build_component_source_package(lift_unit_id=intent.component_id,
        files={name:out/name for name in ('region.c','quote-objects.h')},shared_inputs={},
        operation_symbols={'release-region':'release_region'},out_dir=out/'source')
    stack=entry_register('esp');low=sub(wide(stack),constant(64,64));high=add(wide(stack),constant(56,64))
    contract={'profile':'finite-paired-caller-v1','component_id':intent.component_id,'operation_id':'release-region',
        'entry_rva':0x4fc3,'unit_rvas':[0x4fc3],
        'suppliers':{'release_buffer':{'required_frame':['ebp','ebx','edi','esi'],
            'bindings':{'protected_low':low.to_payload(),'protected_high':high.to_payload()},
            'parameter_transport':{'allocation_token':{'parameter':'buffer','relation':'record-address'}}}},
        'witnesses':{},'runtime_contracts':{},
        'native_memory':[access('argument',stack,read=True,write=True,storage='private'),
                         access('saved_edx',add(stack,constant(52)),read=True,write=True,storage='private')],
        'native_calls':[{'id':'release_buffer','event':{'kind':'internal','source_rva':0x4fc3,
            'instruction_rva':0x4fca,'target_rva':0x1b34,'return_rva':0x4fcf,'call_index':0,
            'argument_count':0,'stack_input_count':2},'entry_stack_delta':0,
            'arguments':[stack_word(0).to_payload()],'requires':[]}],
        'source_services':[{'id':'release_buffer','views':{},'arguments':[parameter('buffer',U32).to_payload()],
                            'diagnostic':'actual-release-buffer-identity'}],
        'boundary':{'image_base':0x400000,'private_low':low.to_payload(),'private_high':high.to_payload(),
            'call_private_low':low.to_payload(),'call_private_high':high.to_payload(),'views':[],
            'records':{'header':'quote-objects.h','lifetime':'operation',
                'types':[{'id':'quote_bytes','extent':0,'fields':[],'subobjects':[],'representation':'identity'}],
                'objects':[{'id':'buffer','type_id':'quote_bytes','count':1,'address':value('buffer').to_payload()}],
                'projections':[],'state':{}},
            'event_capacity':8,'call_capacity':1,
            'values':[{'id':'buffer','sort':U32.to_payload(),'expression':entry_register('esi').to_payload()}],
            'admission':[named('release-stack-domain',all_of(le(constant(256),stack),le(stack,constant(0xffffff00)))),
                named('release-stack-import-separation',any_of(le(high,constant(0x4321e4,64)),
                    le(constant(0x4321e8,64),low))),
                named('release-nonnull-errno-target',negate(eq(word('entry_memory',constant(0x4321e4)),constant(0))))],
            'services':[{'id':'release_buffer','before':[],'count_diagnostic':'release-call-count','maximum_calls':1}],
            'assertions':[named('release-saved-continuation-word',eq(value('private.saved_edx'),entry_register('edx'))),
                *[named('release-preserved-'+r,eq(field(r),entry_register(r))) for r in ('ebp','ebx','edi','esi')]],
            'outcomes':[{'id':'next','guard':expression('true',BOOL_SORT).to_payload(),
                'exit':{'kind':'fallthrough','rva':0x4fcf,'diagnostic':'release-normal-continuation'},'assertions':[]}],
            'context_diagnostic':'release-source-context','memory_diagnostic':'release-public-memory'}}
    write_json(out/'caller-contract.json',contract)
    prepare_time=time.monotonic()-started

    def prepare(source_package,output):
        result=write_component_source_check(target_id='gnu-hello',component_id=intent.component_id,
            interface_package=out/'interface',source_package=source_package,out=output,
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('i686-w64-mingw32-gcc')))
        assert result['status']=='complete',result

    prepare(out/'source',out/'preparation')
    def invoke(name,*,source_package=None,preparation=None,previous=None,definition=None):
        phases=[];begin=time.monotonic();folder=out/name
        status=write_component_source_call_check(target_id='gnu-hello',component_id=intent.component_id,
            preparation=preparation or out/'preparation',exact=out/'exact',supplier={'release_buffer':supplier},
            contract=definition or contract,source_package=source_package or out/'source',interface_package=out/'interface',
            out=folder/'feedback',workspace=folder/'work',goto_cc=Path(shutil.which('goto-cc')),
            cbmc=Path(shutil.which('cbmc')),smt_solver=None,unwind=16,timeout_seconds=60,previous=previous,timings=phases)
        result=json.loads((folder/'feedback/caller-comparison/result.json').read_text())
        row={'status':status,'seconds':time.monotonic()-begin,'phases':phases,'reuse':result['reuse'],
             'result':str(folder/'feedback/caller-comparison/result.json'),
             'sha256':sha256_file(folder/'feedback/caller-comparison/result.json')}
        write_json(folder/'validation.json',row);print(json.dumps({'case':name,**row}),flush=True)
        return status,result,row

    status,baseline,positive=invoke('positive');assert status['status']=='complete',baseline['checks']
    with patch('subprocess.run',side_effect=AssertionError('reuse invoked a tool')),patch.object(
            checker,'render_caller_boundary',side_effect=AssertionError('reuse generated a model')):
        status,reused,reuse=invoke('reuse',previous=out/'positive/feedback')
    assert status['status']=='complete' and reused['proof_key']==baseline['proof_key'] and reused['proof_files']==baseline['proof_files']
    assert reused['reuse']=={'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0}
    wrong=source.replace(fragment,'(void)buffer;\nservices->release_buffer(environment, 0);')
    (out/'wrong.c').write_text(wrong)
    build_component_source_package(lift_unit_id=intent.component_id,files={'region.c':out/'wrong.c','quote-objects.h':out/'quote-objects.h'},
        shared_inputs={},operation_symbols={'release-region':'release_region'},out_dir=out/'wrong-source')
    prepare(out/'wrong-source',out/'wrong-preparation')
    status,result,negative=invoke('wrong-reference',source_package=out/'wrong-source',preparation=out/'wrong-preparation')
    assert status['status']=='violated' and 'spx-paired-call-arguments' in json.dumps(result['checks'])
    incompatible=deepcopy(contract);del incompatible['suppliers']['release_buffer']['parameter_transport']
    with patch('subprocess.run',side_effect=AssertionError('incompatible interface invoked tools')):
        status,result,rejected=invoke('missing-transport',definition=incompatible)
    assert status['status']=='incomplete' and result['reuse']['compiler_runs']==0
    overlap=deepcopy(contract);overlap['boundary']['admission'].pop(1)
    status,result,overlapping=invoke('missing-stack-separation',definition=overlap)
    assert status['status']=='violated' and 'spx-caller-private-view-separation' in json.dumps(result['checks'])
    missing_target=deepcopy(contract);missing_target['boundary']['admission'].pop()
    status,result,target_rejected=invoke('missing-errno-target',definition=missing_target)
    assert status['status']=='violated' and 'finite-supplier-entry-nonnull-errno-target' in json.dumps(result['checks'])
    report={'status':'pass','authorizing':False,'activation_authorized':False,'whole_component_complete':False,
        'scope':__doc__,'preparation_seconds':prepare_time,'seconds':time.monotonic()-started,
        'positive':positive,'reuse':reuse,'wrong_reference':negative,'missing_transport':rejected,
        'missing_stack_separation':overlapping,
        'missing_errno_target':target_rejected,
        'inputs':{str(p):sha256_file(p) for p in [plan,retained/'inventory.json',HERE/'quote-slots.c',
            HERE/'quote-objects.h',HERE/'prepare.py',Path(__file__),supplier/'caller-comparison/result.json']},
        'remaining':['Incoming region applicability, private stack/import-slot separation, resolved errno target and complete quoting coverage.',
            'Native allocation/release lifetime and CRT/TLS applicability.',
            'Transport into the following allocation/quoting regions and native admission.']}
    write_json(out/'validation.json',report)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('retained',type=Path);parser.add_argument('supplier',type=Path);parser.add_argument('out',type=Path)
    args=parser.parse_args();check(args.retained.resolve(),args.supplier.resolve(),args.out.resolve())
