"""Returned service views retain current bytes and their original live storage.

These small adapter checks use hand-defined interfaces, not supplier certificates
or the reserved third consumer. The public caller rule must still derive the
result mapping from validated supplier facts before enabling this transport.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import expression, parameter
from spaghetti_extractor.components.bisimulation_caller_interface import source_service_adapters, source_view_storage_runtime
from spaghetti_extractor.components.bisimulation_caller_memory import U32
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.components.relation_ir import RelationSortV1
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT={'fixtures':('compiler','cbmc')}


def value(name, *, view=False):
    return {'id':name,'type_id':'bytes' if view else 'u32',
        'interpretation':'view' if view else 'value','nullable':False,
        'access':'read_write' if view else 'none',
        'extent':{'kind':'fixed' if view else 'none','bytes':500 if view else None,'value_id':None},
        'provider_domain':None,'resource_kind':None}


def bundle(*, result_change=None):
    result=value('result',view=True)
    if result_change:result.update(result_change)
    signatures=[{'id':name,'function_type_id':name+'.fn','parameters':params,'results':[res]}
        for name,params,res in [('get',[value('id')],result),
            ('consume',[value('text',view=True)],value('reply')),
            ('run',[value('buffer',view=True)],value('reply'))]]
    types=[{'id':'u8','kind':'integer','signed':False,'width_bits':8},
        {'id':'u32','kind':'integer','signed':False,'width_bits':32},
        {'id':'bytes','kind':'pointer','pointee_type_id':'u8','qualifiers':[]}]
    types.extend({'id':s['function_type_id'],'kind':'function','calling_convention':'cdecl',
        'parameter_type_ids':[v['type_id'] for v in s['parameters']],
        'result_type_id':s['results'][0]['type_id'],'variadic':False} for s in signatures)
    schema=BoundarySchemaV1.create(schema_id='returned-caller',types=types,signatures=signatures)
    params=signatures[2]['parameters'];results=signatures[2]['results']
    operation={'id':'run','signature_id':'run','pre_states':['ready'],'post_states':['ready'],
        'effect_ids':[],'allowed_service_ids':['consume','get'],'checked_interaction_contract_ids':[],
        'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[]},
        'source_values':params+results,'projection_entries':[
            {'source_id':v['id'],'target':{'root':root,'value_id':v['id'],'fields':[]}}
            for root,values in [('parameter',params),('result',results)] for v in values]}
    return compile_component_interface_v5(ComponentInterfaceIntentV1.create(component_id='returned-caller',
        schema=schema,state=[],operations=[operation],effects=[],services=[
            {'id':name,'signature_id':name,'effect_ids':[],'interaction_contract_id':'test.'+name}
            for name in ('consume','get')],protocol_states=['ready'],initial_protocol_state='ready'))


def adapters(b=None, *, mapping=None):
    return source_service_adapters(b or bundle(),'run',[
        {'id':'get','views':{},'arguments':[parameter('id',U32).to_payload()],'diagnostic':'get-views'},
        {'id':'consume','views':{'text':'buffer'},'arguments':[expression('view_address',U32,
            parameter('text',RelationSortV1('view',type_id='bytes'))).to_payload()],'diagnostic':'consume-view'}],
        callbacks={'get':'get_callback','consume':'consume_callback'},
        result_views={'get':'buffer'} if mapping is None else mapping)


class ReturnedCallerViewTests(unittest.TestCase):
    def check_c(self, *, mutation='', body='', failures=(), extent=500):
        b=bundle();code,names=adapters(b)
        source='\n'.join(['#include "portable-component-implementation.h"',
            '#include "state-machine-runtime.h"',*sparse_mutable_memory_runtime(4),
            *_view_runtime_helpers(need_read=True,need_write=True),spx_portable_reference_runtime_v5_source(),
            'static struct spx_mutable_world right;',
            'struct environment {spx_view_v5 views[1];uint32_t count;};',
            'static spx_view_v5 expected_views[1];',*source_view_storage_runtime(1)])
        source+='''
static uint32_t get_callback(struct environment *e,uint32_t id){
 (void)id;spx_mutable_event(&right,100U,500U,0U,1U,e->count++);
 MUTATION
 return 100U;
}
static uint32_t consume_callback(struct environment *e,uint32_t address){
 (void)e;__CPROVER_assert(address==100U,"following-service-address");return 7U;
}
'''.replace('MUTATION',mutation)+code
        source+='''
void check(void){
 struct spx_mutable_domain domain={&right,100U,EXTENT,3U};
 spx_runtime rt={.context=&domain,.read=spx_mutable_read,.write=spx_mutable_write};
 spx_component_view_context storage={&rt,100U,EXTENT,3U};
 struct environment env={.views={{.base={1U,2U,3U,0U,EXTENT,3U},
  .extent=EXTENT,.element_width=1U,.context=&storage,.access_context=&storage,
  .read_u8=spx_component_view_read,.write_u8=spx_component_view_write,
  .read=spx_component_view_read_span,.write=spx_component_view_write_span}}};
 expected_views[0]=env.views[0];
 view_storage[0]=(struct spx_caller_view_storage){&storage,&rt,&domain,100U,EXTENT,3U};
 spx_view_v5 old=env.views[0];
 uint32_t offset;uint8_t byte;
 __CPROVER_assume(offset<500U);
 uint8_t before=spx_mutable_byte(&right,100U+offset);
 spx_view_v5 first=GET(&env,31U);
 BODY
}
'''.replace('EXTENT',str(extent)+'U').replace('GET',names['get']).replace('BODY',body.replace('GET',names['get']).replace('CONSUME',names['consume']))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);_write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t; typedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
            for name,text in render_component_c_headers_v5(b,{'run':'authored'}).items():(root/name).write_text(text)
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            (root/'pair.c').write_text(source)
            compiler,checker=shutil.which('goto-cc'),shutil.which('cbmc')
            self.assertIsNotNone(compiler);self.assertIsNotNone(checker)
            compiled=subprocess.run([compiler,'--i386-win32','-nostdinc','-I','.',
                'pair.c','--function','check','-o','model.goto'],cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            checked=subprocess.run([checker,'model.goto','--function','check','--json-ui','--unwind','5',
                '--unwinding-assertions','--bounds-check','--pointer-check','--signed-overflow-check',
                '--undefined-shift-check'],cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(checked.returncode,10 if failures else 0,checked.stdout[-2000:]+checked.stderr)
            rows=[r for block in json.loads(checked.stdout) for r in block.get('result',[])]
            self.assertTrue(rows)
            self.assertEqual({r['description'] for r in rows if r['status']=='FAILURE'},set(failures))
            self.assertTrue(all(r['status'] in {'SUCCESS','FAILURE'} for r in rows))

    def test_old_and_returned_aliases_read_current_bytes_across_two_calls(self):
        self.check_c(body='''
 __CPROVER_assert(spx_view_read_u8(&old,offset,&byte)==0U &&
  byte==__CPROVER_uninterpreted_service_byte(0U,100U+offset),"old-alias-current-first");
 __CPROVER_assert(spx_view_read_u8(&first,offset,&byte)==0U &&
  byte==__CPROVER_uninterpreted_service_byte(0U,100U+offset),"returned-current-first");
 spx_view_v5 second=GET(&env,32U);
 __CPROVER_assert(spx_view_read_u8(&first,offset,&byte)==0U &&
  byte==__CPROVER_uninterpreted_service_byte(1U,100U+offset),"old-return-current-second");
 __CPROVER_assert(spx_caller_same_view(&old,&second),"same-live-reference");
 __CPROVER_assert(CONSUME(&env,&first)==7U,"following-service-result");
''')

    def test_no_stale_or_zero_contents_are_inferred_from_the_returned_address(self):
        self.check_c(body='''
 spx_view_read_u8(&first,offset,&byte);
 __CPROVER_assert(byte==before,"stale-byte");
 __CPROVER_assert(byte==0U,"invented-zero");
''',failures=('stale-byte','invented-zero'))

    def test_wrong_native_address_and_backing_storage_reject(self):
        self.check_c(mutation='return 101U;',failures=('spx-source-returned-view-address',))
        self.check_c(mutation='view_storage[0].domain->world=0;',failures=('spx-source-returned-view-storage',))
        self.check_c(mutation='view_storage[0].runtime->context=0;',failures=('spx-source-returned-view-storage',))
        self.check_c(mutation='e->views[0].base.generation++;',failures=('spx-source-returned-view-frame',))
        self.check_c(extent=501,failures=('spx-source-returned-view-extent',))

    def test_following_service_rejects_forged_returned_descriptor(self):
        self.check_c(body='first.base.generation++;CONSUME(&env,&first);',failures=('consume-view',))

    def test_unsupported_results_and_unchecked_mappings_reject(self):
        for mapping in ({},{'get':'missing'},{'get':'buffer','consume':'buffer'}):
            with self.subTest(mapping=mapping):
                with self.assertRaises(ValueError):adapters(mapping=mapping)
        for change in ({'nullable':True},{'access':'read'},
                {'extent':{'kind':'nul_terminated','bytes':None,'value_id':None}}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):adapters(bundle(result_change=change))
