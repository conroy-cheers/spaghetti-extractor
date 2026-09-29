"""Check the real growth-call cut and ordinary C local-count transport.

This is an entry-to-growth relation check, not a complete caller theorem. The
original starts at 0x4eb3 and stops at either xpalloc call. The complete authored C
runs to the same call. The existing borrowed-view rule transports errno storage;
a proof-only assertion observes the saved local value. Growth semantics, later
regions, general region composition and native admission stay open.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_caller_local_records import LocalRecordBinding, local_record_runtime
from spaghetti_extractor.components.bisimulation_caller_records import record_type_check_source
from spaghetti_extractor.components.bisimulation_compilation import workspace_compile_command
from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence
from spaghetti_extractor.components.bisimulation_caller_returned_views import returned_view_runtime
from spaghetti_extractor.components.bisimulation_paired_calls import paired_call_runtime
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import compile_component_interface_v5
from spaghetti_extractor.util import sha256_file

from prepare import interface
from record_layout import local_count, record_types, relation

HERE = Path(__file__).resolve().parent
MODEL = r'''
#include "behavioral-c.h"
#include "portable-component-implementation.h"
#include "quote-objects.h"
@LOCAL_RUNTIME@
static void check_saved_errno(uint32_t);
#include "quote-slots.c"
@MEMORY_RUNTIME@
@PAIRED_RUNTIME@
static struct spx_mutable_world left,right;
static struct spx_paired_trace calls;
@RETURNED_RUNTIME@
spx_step_result spx_sub_00004eb3(spx_runtime *,spx_machine_state *,uint32_t);
static uint32_t stack_base,old_count,index_value,table_address,captured_site,errno_address,errno_target;
static uint32_t argument_word,size_word,options_word,native_errno_calls;
static uint32_t native_arguments[5];
/* The prefix accesses fourteen complete, disjoint 32-bit stack words. Every access
 * checks its width/address; no byte access or partial alias is abstracted away. */
static uint32_t original_words[14],initialized[14];
static struct spx_opaque_quote_table_v5 initial_slot,other_slot;
static uint8_t entry_byte(void *context,uint32_t address,uint8_t fallback){
 (void)context;
 if(address>=0x420050U && address<0x420054U)return (uint8_t)(table_address>>(8U*(address-0x420050U)));
 if(address>=0x42005cU && address<0x420060U)return (uint8_t)(old_count>>(8U*(address-0x42005cU)));
 if(address>=0x4321e4U && address<0x4321e8U)return (uint8_t)(errno_target>>(8U*(address-0x4321e4U)));
 return fallback;
}
static uint32_t public_word(struct spx_mutable_world *world,uint32_t address){
 uint32_t value=0U;for(uint32_t i=0U;i<4U;i++)value|=(uint32_t)spx_mutable_byte(world,address+i)<<(8U*i);
 return value;
}
static uint32_t native_slot(uint32_t address,uint32_t width){
 __CPROVER_assert(width==4U,"growth-stack-word-width");
 if(address==stack_base)return 0U;
 if(address==stack_base+4U)return 1U;
 if(address==stack_base+8U)return 2U;
 if(address==stack_base+12U)return 3U;
 if(address==stack_base+16U)return 4U;
 if(address==stack_base+76U)return 5U;
 if(address==stack_base+40U)return 6U;
 if(address==stack_base+44U)return 7U;
 if(address==stack_base+48U)return 8U;
 if(address==stack_base+92U)return 9U;
 if(address==stack_base+96U)return 10U;
 if(address==stack_base+100U)return 11U;
 if(address==stack_base+104U)return 12U;
 if(address==stack_base+112U)return 13U;
 __CPROVER_assert(0,"growth-stack-word-coverage");__CPROVER_assume(0);return 0U;
}
static uint32_t native_read(void *context,uint32_t address,uint32_t width,uint32_t *fault){
 (void)context;__CPROVER_assert(width==4U,"growth-native-read-width");
 if(address==0x420050U || address==0x42005cU || address==0x4321e4U ||
    spx_returned_native_access(address,width,1U)){*fault=0U;return public_word(&left,address);}
 uint32_t slot=native_slot(address,width);
 __CPROVER_assert(initialized[slot],"growth-initialized-word");
 *fault=0U;return original_words[slot];
}
static void native_write(void *context,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 (void)context;uint32_t slot=native_slot(address,width);
 original_words[slot]=value;initialized[slot]=1U;*fault=0U;
}
static spx_call_status native_call(spx_runtime *runtime,const spx_call_event *event,
 const spx_machine_state *input,spx_machine_state *output){
 (void)runtime;*output=*input;uint32_t fault;
 if(event->kind==SPX_CALL_INDIRECT){
  __CPROVER_assert(!native_errno_calls && event->source_rva==0x4ec6U && event->target_rva==errno_target &&
   input->esp==stack_base,"growth-entry-errno-call");
  native_errno_calls++;spx_returned_begin(0U);
  const struct spx_returned_exclusion excluded[]={{calls.private_low,calls.private_high}};
  spx_returned_candidate(errno_address,4U,excluded,1U);
  uint32_t args[1]={0U};
  struct spx_paired_outcome outcome=spx_paired_invoke(&calls,&left,0U,0U,args,0U,
   (struct spx_paired_outcome){errno_address,0U});
  spx_returned_grant(0U,outcome.value,4U,3U);output->eax=outcome.value;
  spx_machine_state volatile_state;output->ecx=volatile_state.ecx;output->edx=volatile_state.edx;
  output->cf=volatile_state.cf&1U;output->zf=volatile_state.zf&1U;output->of=volatile_state.of&1U;
  output->sf=volatile_state.sf&1U;output->pf=volatile_state.pf&1U;output->df=volatile_state.df&1U;
  return SPX_CALL_OK;
 }
 spx_returned_begin(0U);
 __CPROVER_assert(!captured_site && event->kind==SPX_CALL_INTERNAL_DIRECT && event->target_rva==0x63acU &&
  (event->source_rva==0x4f1bU || event->source_rva==0x504cU),"growth-exact-call-cut");
 captured_site=event->source_rva;
 for(uint32_t i=0;i<5U;i++)native_arguments[i]=native_read(0,input->esp+4U*i,4U,&fault);
 /* Checker stop marker at the call boundary; no xpalloc outcome is assumed. */
 return SPX_CALL_NONLOCAL;
}
spx_call_status spx_invoke_call(spx_runtime *runtime,const spx_call_event *event,
 const spx_machine_state *input,spx_machine_state *output){return native_call(runtime,event,input,output);}
static spx_view_v5 source_errno(void *environment){(void)environment;
 spx_returned_begin(1U);uint32_t args[1]={0U};
 struct spx_paired_outcome outcome=spx_paired_invoke(&calls,&right,1U,0U,args,0U,
  (struct spx_paired_outcome){0U,0U});
 spx_returned_grant(1U,outcome.value,4U,3U);return spx_returned_source_view(outcome.value);
}
static void check_saved_errno(uint32_t value){
 uint32_t fault;__CPROVER_assert(value==native_read(0,stack_base+48U,4U,&fault),"growth-saved-errno");
}
static struct spx_opaque_quote_table_v5 *source_grow(void *environment,
 struct spx_opaque_quote_table_v5 *table,struct spx_opaque_quote_word_v5 *count,
 uint32_t additional,uint32_t maximum){
 (void)environment;
 spx_returned_begin(1U);spx_paired_finish(&calls);
 __CPROVER_assert(native_errno_calls==1U,"growth-errno-trace");
 uint32_t address=table==0?0U:(table==&initial_slot?0x420054U:table_address);
 __CPROVER_assert(captured_site!=0U && native_arguments[0]==address &&
  native_arguments[1]==stack_base+@COUNT_OFFSET@U && native_arguments[2]==additional &&
  native_arguments[3]==maximum && native_arguments[4]==8U,"growth-call-arguments");
 uint8_t bytes[4];spx_local_record_pack_quote_word(count,bytes);
 for(uint32_t j=0;j<4U;j++)
  __CPROVER_assert(bytes[j]==(uint8_t)(original_words[5]>>(8U*j)),"growth-incoming-count-contents");
 /* The same arbitrary service byte outcome must reach both representations. */
 uint32_t changed;original_words[5]=changed;
 for(uint32_t j=0;j<4U;j++)bytes[j]=(uint8_t)(changed>>(8U*j));
 spx_local_record_unpack_quote_word(count,bytes);uint32_t fault;
 __CPROVER_assert(count->value==native_read(0,stack_base+76U,4U,&fault),"growth-count-writeback");
 __CPROVER_assume(0);return 0;
}
static void admit(void){
 __CPROVER_assume(stack_base>=4U && stack_base<=0xffffff80U && old_count<=index_value && index_value<0x7fffffffU);
 __CPROVER_assume(errno_target!=0U);
 __CPROVER_assume(stack_base+116U<=0x420050U || stack_base>=0x420054U);
 __CPROVER_assume(stack_base+116U<=0x42005cU || stack_base>=0x420060U);
 __CPROVER_assume(stack_base+116U<=0x4321e4U || stack_base>=0x4321e8U);
}
void check_admission(void){uint32_t a,b,c,d;stack_base=a;old_count=b;index_value=c;errno_target=d;admit();
 __CPROVER_assert(0,"growth-entry-witness");}
void check_growth(void){
 uint32_t a,b,c,d,e,f,g,h,i;stack_base=a;old_count=b;index_value=c;table_address=d;errno_address=e;errno_target=f;
 argument_word=g;size_word=h;options_word=i;admit();
 left.read_representation=entry_byte;right.read_representation=entry_byte;
 calls.private_low=stack_base;calls.private_high=(uint64_t)stack_base+116U;
 original_words[13]=options_word;initialized[13]=1U;
 spx_machine_state machine;machine.esp=stack_base+108U;machine.eax=index_value;
 machine.edx=argument_word;machine.ecx=size_word;
 spx_runtime runtime={0};runtime.read=native_read;runtime.write=native_write;runtime.external_call_fallback=native_call;
 spx_step_result stop=spx_sub_00004eb3(&runtime,&machine,0x4eb3U);
 __CPROVER_assert(stop.kind==SPX_NONLOCAL && captured_site!=0U,"growth-region-reaches-call");
 __CPROVER_assert(original_words[6]==argument_word && original_words[7]==size_word && machine.ebx==options_word,
  "growth-preserved-inputs");
 spx_paired_begin_source(&calls);
 struct spx_opaque_quote_state_v5 state={0};state.count=old_count;state.initial_table=&initial_slot;
 state.table=table_address==0?0:(table_address==0x420054U?&initial_slot:&other_slot);
 spx_quote_slots_services_v5 services={0};services.errno_cell=source_errno;services.grow_slots=source_grow;
 spx_quote_slots_context_v5 context={0};context.services=&services;context.state.slots=&state;
 struct spx_opaque_quote_bytes_v5 *source_argument;
 struct spx_opaque_quote_options_v5 *source_options;
 (void)quote_slots(&context,index_value,source_argument,size_word,source_options);
 __CPROVER_assert(0,"growth-source-must-reach-cut");
}
'''


def check(retained, out, *, wrong_count=False, wrong_offset=False, wrong_errno=False):
    started=time.monotonic()
    out.mkdir(parents=True)
    manifest = json.loads((retained/'component-exact-c-slice-v1.json').read_text())
    assert len(manifest['root_unit_ids']) == 40 and manifest['root_unit_ids'] == manifest['root_context_unit_ids']
    inputs = {}
    for row in manifest['files']:
        path = retained/row['path']; assert sha256_file(path) == row['sha256']
        inputs[str(path)] = row['sha256']; shutil.copyfile(path, out/row['path'])
    bundle = compile_component_interface_v5(interface())
    for name, text in render_component_c_headers_v5(bundle, {'quote':'quote_slots'}).items():
        (out/name).write_text(text)
    for name in ('quote-slots.c','quote-objects.h'):
        inputs[str(HERE/name)] = sha256_file(HERE/name); shutil.copyfile(HERE/name,out/name)
    if wrong_count:
        path=out/'quote-slots.c';text=path.read_text();before='new_count = { state->count }'
        assert text.count(before)==1;path.write_text(text.replace(before,'new_count = { state->count ^ 1U }'))
    source=out/'quote-slots.c';text=source.read_text()
    marker='uint32_t saved_errno = read_word(services->errno_cell(environment));'
    assert text.count(marker)==1
    checked=marker.replace('));', ')) ^ 1U;') if wrong_errno else marker
    source.write_text(text.replace(marker,checked+'\n    check_saved_errno(saved_errno);'))
    preparation_seconds=time.monotonic()-started;model_started=time.monotonic()
    layout = next(row for row in record_types() if row['id']=='quote_word')
    helper = local_record_runtime({'count':LocalRecordBinding('quote_word','0U','4U',3,layout)})
    model=MODEL.replace('@LOCAL_RUNTIME@','\n'.join(helper)).replace('@COUNT_OFFSET@','75' if wrong_offset else '76')
    model=model.replace('@MEMORY_RUNTIME@','\n'.join(sparse_mutable_memory_runtime(1,representation_hooks=True)))
    model=model.replace('@PAIRED_RUNTIME@','\n'.join(paired_call_runtime(1,argument_capacity=1)))
    model=model.replace('@RETURNED_RUNTIME@','\n'.join(returned_view_runtime(1)))
    (out/'pair.c').write_text(model)
    (out/'record-types.c').write_text(record_type_check_source({'records':relation([])},bundle))
    _write_cbmc_stdint(out/'stdint.h');(out/'stddef.h').write_text('typedef unsigned int size_t;\n#define NULL ((void *)0)\n')
    model_seconds=time.monotonic()-model_started
    compiler=Path(shutil.which('goto-cc'));checker=Path(shutil.which('cbmc'));compilation=[]
    for mode,files,entry,model in [('--i386-linux',['record-types.c'],'spx_check_record_types','record-types.goto'),
            ('--i386-win32',['pair.c','behavioral-support.c','behavioral-fn-00004eb3.c'],'check_growth','model.goto')]:
        command=[str(compiler),mode,'-nostdinc','-I','.',*files,'--function',entry,'-o',model]
        start=time.monotonic();result=subprocess.run(workspace_compile_command(command,out),capture_output=True,text=True)
        compilation.append({'command':command,'seconds':time.monotonic()-start,'exit_code':result.returncode,'stderr':result.stderr})
        (out/'compilation.json').write_text(json.dumps(compilation,indent=2));assert result.returncode==0,result.stderr
    evidence=CbmcQueryEvidence(model=out/'model.goto',compiler=compiler,checker=checker,output=out/'query-evidence')
    queries={}
    for name,entry in [('admission','check_admission'),('growth','check_growth')]:
        start=time.monotonic();result=run_cbmc_properties(command=[str(checker),'model.goto','--function',entry,*checker_options(90,None)],
            cwd=out,timeout_seconds=60,query_evidence=evidence,output_prefix=out/name)
        queries[name]={'result':result,'seconds':time.monotonic()-start}
    record={'scope':__doc__,'authorizing':False,'activation_authorized':False,'whole_component_complete':False,
        'queries':queries,'compilation':compilation,'seconds':time.monotonic()-started,
        'phases':{'preparation':preparation_seconds,'model':model_seconds,
                  'compiler':sum(row['seconds'] for row in compilation),
                  'solver':sum(row['seconds'] for row in queries.values()),'native_link':0},
        'entry_relation':{'rva':0x4eb3,'eax':'slot_index','edx':'argument','ecx':'argument_size',
                          'entry_stack_4':'options','esp':'call stack plus 108',
                          'admission':'nonwrapping stack disjoint from three global words; count <= index < INT_MAX; nonnull captured errno target'},
        'runtime_premises':['errno returns normally with unchanged public memory and callee-saved registers.',
                            'Returned errno span is four current bytes, nonnull, nonwrapping and outside the private frame.'],
        'local_record':local_count(),'wrong_count':wrong_count,'wrong_offset':wrong_offset,'wrong_errno':wrong_errno,
        'inputs':{**inputs,**{str(HERE/name):sha256_file(HERE/name) for name in ['check_growth_count.py','record_layout.py','prepare.py']}}}
    (out/'validation.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({name:{'status':row['result']['status'],'seconds':row['seconds']} for name,row in queries.items()}),flush=True)
    assert queries['admission']['result']['status']=='violated'
    assert queries['admission']['result']['source']['comment']=='growth-entry-witness'
    assert queries['growth']['result']['status']==('violated' if wrong_count or wrong_offset or wrong_errno else 'satisfied')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('retained',type=Path);parser.add_argument('out',type=Path)
    parser.add_argument('--wrong-count',action='store_true');parser.add_argument('--wrong-offset',action='store_true')
    parser.add_argument('--wrong-errno',action='store_true')
    args=parser.parse_args();check(args.retained.resolve(),args.out.resolve(),wrong_count=args.wrong_count,
        wrong_offset=args.wrong_offset,wrong_errno=args.wrong_errno)
