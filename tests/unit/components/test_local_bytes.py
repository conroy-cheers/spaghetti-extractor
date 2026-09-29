"""Scoped C storage crosses generated V5 services with checked live contents."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import expression, parameter
from spaghetti_extractor.components.bisimulation_caller_interface import source_service_adapters
from spaghetti_extractor.components.bisimulation_caller_memory import U32
from spaghetti_extractor.components.bisimulation_local_bytes import LocalBytesBinding
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_paired_calls import paired_call_runtime
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.relation_ir import RelationSortV1

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def value(name, access=None):
    return {'id':name,'type_id':'bytes' if access else 'u32',
        'interpretation':'view' if access else 'value','nullable':False,'access':access or 'none',
        'extent':{'kind':'fixed' if access else 'none','bytes':8 if access else None,'value_id':None},
        'provider_domain':None,'resource_kind':None}


def bundle():
    signatures=[{'id':name,'function_type_id':name+'.fn','parameters':params,'results':[value('result')]}
        for name,params in [('run',[value('seed')]),('mutate',[value('bytes','read_write')]),
                           ('observe',[value('bytes','read')])]]
    types=[{'id':'u8','kind':'integer','signed':False,'width_bits':8},
        {'id':'u32','kind':'integer','signed':False,'width_bits':32},
        {'id':'bytes','kind':'pointer','pointee_type_id':'u8','qualifiers':[]}]
    types += [{'id':s['function_type_id'],'kind':'function','calling_convention':'cdecl',
        'parameter_type_ids':[v['type_id'] for v in s['parameters']],'result_type_id':'u32','variadic':False}
        for s in signatures]
    schema=BoundarySchemaV1.create(schema_id='local-bytes',types=types,signatures=signatures)
    params,results=signatures[0]['parameters'],signatures[0]['results']
    operation={'id':'run','signature_id':'run','pre_states':['ready'],'post_states':['ready'],
        'effect_ids':[],'allowed_service_ids':['mutate','observe'],'checked_interaction_contract_ids':[],
        'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[]},'source_values':params+results,
        'projection_entries':[{'source_id':v['id'],'target':{'root':root,'value_id':v['id'],'fields':[]}}
            for root,values in [('parameter',params),('result',results)] for v in values]}
    return compile_component_interface_v5(ComponentInterfaceIntentV1.create(component_id='local-bytes',
        schema=schema,state=[],operations=[operation],effects=[],services=[
            {'id':name,'signature_id':name,'effect_ids':[],'interaction_contract_id':'test.'+name}
            for name in ('mutate','observe')],protocol_states=['ready'],initial_protocol_state='ready'))


CALLER = '''#include "portable-component-implementation.h"
#include "portable-component-local-bytes.h"
uint32_t authored(spx_local_bytes_context_v5 *context,uint32_t seed) {
  uint8_t bytes[8];
  for(uint32_t i=0U;i<8U;i++) bytes[i]=(uint8_t)(seed+i);
  spx_local_bytes_v5 owner={0};spx_view_v5 view;
  if(spx_local_bytes_open(&owner,bytes,8U,3U,&view)) return UINT32_MAX;
  context->services->mutate(context->services->context,&view);
  /* EDIT */
  uint32_t result=context->services->observe(context->services->context,&view);
  uint8_t byte=0U;
  if(spx_view_read_u8(&view,7U,&byte)) return UINT32_MAX;
  spx_local_bytes_close(&owner);
  return result+byte;
}
'''


class LocalBytesTests(unittest.TestCase):
    def write(self, root, *, source=CALLER, cbmc=True):
        for name,text in render_component_c_headers_v5(bundle(),{'run':'authored'}).items():
            (root/name).write_text(text)
        if cbmc:
            _write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t; typedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
        (root/'caller.c').write_text(source)
        (root/'runtime.c').write_text('#include "portable-component.h"\n'+spx_portable_reference_runtime_v5_source())

    def check(self, *, edit='', callback_edit='', failures=()):
        view=parameter('bytes',RelationSortV1('view',type_id='bytes'))
        definitions=[{'id':name,'views':{'bytes':'scratch'},
            'arguments':[expression('view_address',U32,view).to_payload()],'diagnostic':name+'-view'}
            for name in ('mutate','observe')]
        adapters,names=source_service_adapters(bundle(),'run',definitions,
            callbacks={'mutate':'mutate','observe':'observe'},
            local_views={'scratch':LocalBytesBinding('bytes','100U','8U',3)})
        code='\n'.join(['#include "portable-component-implementation.h"',
            '#include "portable-component-local-bytes.h"',*sparse_mutable_memory_runtime(1),
            *paired_call_runtime(2,argument_capacity=1,object_capacity=1,object_byte_capacity=8),
            'static struct spx_paired_trace trace;',
            'struct environment {struct spx_mutable_world *world;};',
            '''static uint32_t mutate(struct environment *e,uint32_t address,struct spx_paired_object *objects,uint32_t count){
 uint32_t args[1]={address};
 struct spx_paired_outcome result=spx_paired_invoke(&trace,e->world,1U,0U,args,1U,
    (struct spx_paired_outcome){0U,0U},objects,count);
 return result.value;
}
static uint32_t observe(struct environment *e,uint32_t address,struct spx_paired_object *objects,uint32_t count){
 uint32_t args[1]={address};
 return spx_paired_invoke(&trace,e->world,1U,1U,args,1U,
    (struct spx_paired_outcome){0U,0U},objects,count).value;
}''',adapters,
            '''void check(void){
 uint32_t seed,probe,a,b;uint8_t bytes[8];
 for(uint32_t i=0U;i<8U;i++)bytes[i]=(uint8_t)(seed+i);
 struct spx_mutable_world left={0},right={0};trace.probe=probe;
 struct spx_paired_object objects[1]={{100U,3U,1U,8U,bytes}};
 uint32_t args[1]={100U};
 spx_paired_invoke(&trace,&left,0U,0U,args,1U,(struct spx_paired_outcome){a,0U},objects,1U);
 objects[0].permissions=1U;
 spx_paired_invoke(&trace,&left,0U,1U,args,1U,(struct spx_paired_outcome){b,0U},objects,1U);
 uint32_t expected=b+bytes[7];
 spx_paired_begin_source(&trace);struct environment env={&right};
 spx_local_bytes_services_v5 services={.context=&env,.mutate=MUTATE,.observe=OBSERVE};
 spx_local_bytes_context_v5 context={.services=&services,.protocol_state=SPX_LOCAL_BYTES_PROTOCOL_READY};
 uint32_t actual=authored(&context,seed);
 spx_paired_finish(&trace);
 __CPROVER_assert(actual==expected,"local-caller-result");
}'''.replace('MUTATE',names['mutate']).replace('OBSERVE',names['observe'])])
        if callback_edit:
            code=code.replace('uint32_t result=mutate(e,arg0,local_objects,1U);',
                'uint32_t result=mutate(e,arg0,local_objects,1U);'+callback_edit)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.write(root,source=CALLER.replace('/* EDIT */',edit))
            (root/'check.c').write_text(code)
            compiler=shutil.which('goto-cc')
            checker=shutil.which('cbmc')
            self.assertIsNotNone(compiler)
            self.assertIsNotNone(checker)
            p=subprocess.run([compiler,'--i386-win32','-nostdinc','-I','.',
                'check.c','caller.c','runtime.c','--function','check','-o','model.goto'],
                cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(p.returncode,0,p.stderr)
            p=subprocess.run([checker,'model.goto','--function','check','--json-ui','--unwind','10',
                '--unwinding-assertions','--bounds-check','--pointer-check','--signed-overflow-check',
                '--undefined-shift-check'],cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(p.returncode,10 if failures else 0,p.stdout[-2000:]+p.stderr)
            rows=[r for block in json.loads(p.stdout) for r in block.get('result',[])]
            self.assertTrue(rows)
            actual={r['description'] for r in rows if r['status']=='FAILURE'}
            self.assertTrue(set(failures)<=actual,(failures,actual))
            if not failures:
                self.assertEqual(actual,set())

    def test_local_c_array_keeps_current_bytes_across_generated_service_adapters(self):
        self.check()

    def test_corrupt_bytes_and_closed_views_reject_at_the_next_service(self):
        self.check(edit='bytes[7]^=1U;',failures=('spx-paired-object-current-memory',))
        self.check(edit='spx_local_bytes_close(&owner);',failures=('spx-source-local-view-correspondence',))

    def test_forged_hooks_stale_generation_and_short_backing_reject(self):
        self.check(edit='view.read=0;',failures=('spx-source-local-view-correspondence',))
        self.check(edit='view.base.generation++;',failures=('spx-source-local-view-correspondence',))
        self.check(edit='uint8_t short_bytes[1]={0};owner.bytes=short_bytes;',
                   failures=('spx-source-local-bytes-live',))

    def test_service_cannot_change_the_local_owner_or_descriptor(self):
        self.check(callback_edit='((spx_local_bytes_v5 *)p0->access_context)->permissions=1U;',
                   failures=('spx-source-local-owner-frame',))

    def test_host_callbacks_share_the_actual_runtime_and_check_generations_bounds_and_aliases(self):
        code='''#include "portable-component-local-bytes.h"
#include <assert.h>
int main(void){
 uint8_t bytes[8]={0};spx_local_bytes_v5 owner={0},other={0};
 spx_view_v5 all,alias,readonly,old,empty,other_view;uint64_t value=0;int64_t distance=0;
 assert(spx_local_bytes_open(&owner,bytes,8,3,&all)==0);
 assert(spx_local_bytes_open(&owner,bytes,8,3,&old)!=0);
 assert(spx_local_bytes_view(&owner,2,4,3,&alias)==0);
 assert(spx_local_bytes_view(&owner,2,4,1,&readonly)==0);
 assert(alias.write(alias.access_context,alias.base,0,4,0xabcdef12U)==0);
 assert(all.read(all.access_context,all.base,2,4,&value)==0 && value==0xabcdef12U);
 assert(spx_ref_difference(alias.base,all.base,&distance)==0 && distance==2);
 assert(spx_view_write_u8(&readonly,0,7)!=0);
 assert(spx_local_bytes_write(readonly.access_context,readonly.base,0,1,7)!=0);
 assert(spx_local_bytes_read(all.access_context,all.base,UINT64_MAX,1,&value)!=0);
 assert(spx_local_bytes_view(&owner,8,0,1,&empty)==0);
 assert(spx_view_read_u8(&empty,0,(uint8_t *)&value)!=0);
 assert(spx_local_bytes_view(&owner,8,1,1,&empty)!=0);
 assert(spx_local_bytes_open(&other,bytes,8,1,&other_view)==0);
 assert(spx_ref_difference(other_view.base,all.base,&distance)==SPX_REF_WRONG_ORIGIN);
 old=all;spx_local_bytes_close(&owner);
 assert(spx_local_bytes_read(old.access_context,old.base,0,1,&value)==SPX_REF_EXPIRED);
 assert(spx_local_bytes_open(&owner,bytes,8,3,&all)==0);
 assert(spx_local_bytes_read(old.access_context,old.base,0,1,&value)==SPX_REF_EXPIRED);
 return 0;
}'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.write(root,cbmc=False)
            (root/'check.c').write_text(code)
            p=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror','-I',str(root),
                str(root/'check.c'),str(root/'runtime.c'),'-o',str(root/'check')],capture_output=True,text=True,timeout=60)
            self.assertEqual(p.returncode,0,p.stderr)
            p=subprocess.run([str(root/'check')],capture_output=True,text=True,timeout=30)
            self.assertEqual(p.returncode,0,p.stderr)
