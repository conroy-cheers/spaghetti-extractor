"""Public optional shared-service assurance is separate from finite comparison."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.commands.component_review import _interface
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.util import write_json
from tests.unit.components import test_comparison as base
from tests.unit.components.test_shared_source_contracts import small_bundle,FIXTURE

TESTKIT={'fixtures':('compiler','cbmc'),'commands':('component check',),
         'resources':('tests/fixtures/hand-defined-boundaries/resource-text',)}


def shared_package(root):
    root.mkdir(parents=True,exist_ok=True)
    interface=root/'interface.json';write_json(interface,small_bundle().intent.to_payload())
    author=root/'author.c';author.write_text((FIXTURE/'resource-text.c').read_text().replace('500U','8U'))
    source=root/'source'
    build_component_source_package(lift_unit_id='resource-text',files={'author.c':author},shared_inputs={},
        operation_symbols={'get':'resource_text'},out_dir=source)
    driver=root/'driver.c'
    driver.write_text('''#include <stdio.h>
#include <string.h>
#include "portable-component-implementation.h"
static uint32_t read_module(void *p,spx_ref_v1 r,uint64_t o,uint32_t n,uint64_t *v) {
  (void)p;(void)r;(void)o;(void)n;*v=1;return 0;
}
static uint32_t load(void *p,uint32_t module,uint32_t id,const spx_view_v5 *buffer,uint32_t maximum) {
  (void)p;(void)module;(void)id;(void)maximum;
  ((unsigned char *)buffer->context)[0]=42;return 0;
}
int main(int argc,char **argv) {
  if(argc!=2) return 2;
  unsigned char bytes[8]={0};
  spx_resource_text_services_v5 services={0};services.load_string=load;
  spx_resource_text_context_v5 context={0};context.services=&services;
  context.state.module.read=read_module;context.state.module.extent=4;context.state.module.base.object=1;
  context.state.buffer.context=bytes;context.state.buffer.extent=8;context.state.buffer.base.object=2;
  spx_view_v5 result;
  if(!strcmp(argv[1],"original")) {load(0,1,1,&context.state.buffer,8);result=context.state.buffer;}
  else result=resource_text(&context,1);
  printf("{\\"object\\":%u,\\"extent\\":%u,\\"byte\\":%u}\\n",(unsigned)result.base.object,(unsigned)result.extent,bytes[0]);
  return 0;
}
''')
    package=root/'package'
    prepare_comparison_package(interface_package=interface,source_package=source,target_id='fixture',component_id='resource-text',
        adapter_files={'driver.c':driver},include_files={},link_files={},runtime_files={},original_files=['adapters/driver.c'],
        oracle_kind='fixture',cases=[{'id':'load','arguments':[]}],observation_fields=['object','extent','byte'],
        assumptions=['fixed shared views; modeled synchronous service footprint; access-failure transport excluded'],
        scope='local shared-view example; one synthetic execution is not original equivalence',
        compiler=Path(shutil.which('cc')),runner=None,server=None,output=package,
        local_shared_contract={'relation_intent':json.loads((FIXTURE/'relation.json').read_text()),
                               'maximum_calls':1,'maximum_memory_events':1})
    return package


class PracticalSharedContractTests(unittest.TestCase):
    command=base.ComponentComparisonTests.command

    def setUp(self):
        if not all(shutil.which(t) for t in ('cc','goto-cc','goto-instrument','cbmc')):
            self.skipTest('compiler/CBMC fixture unavailable')
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.package=shared_package(self.root/'fixture')

    def check(self,name,*arguments):
        output=self.root/name
        code,text=self.command('check','fixture','resource-text','--comparison-package',str(self.package),
            '--output',str(output),'--local-contracts',*arguments)
        return code,text,output,load_comparison_result(output)

    def test_shared_property_reuse_and_changed_premise_are_bound(self):
        code,text,first,result=self.check('baseline')
        self.assertEqual(code,0,text)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['formal_check']['status'],'proved',result['formal_check']['result'])
        self.assertEqual(result['formal_check']['kind'],'shared-memory-service-contracts')
        self.assertFalse(result['authorizing'])
        code,text,_,again=self.check('reused','--reuse-comparison',str(first))
        self.assertEqual(code,0,text)
        self.assertTrue(all(n==0 for n in again['work_counts'].values()))
        self.assertEqual(again['formal_check']['work_counts'],{'compiler':0,'model':0,'solver':0})
        path=self.package/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['local_shared_contract']['maximum_calls']=2;write_json(path,plan)
        code,text,_,changed=self.check('changed','--reuse-comparison',str(first))
        self.assertEqual(code,0,text)
        self.assertEqual(changed['formal_check']['status'],'proved')
        self.assertGreater(changed['formal_check']['work_counts']['solver'],0)
        self.assertNotEqual(changed['formal_check']['binding'],result['formal_check']['binding'])

    def test_unsampled_wrong_returned_alias_is_a_local_disproof(self):
        source=self.package/'source/author.c'
        source.write_text(source.read_text().replace('return context->state.buffer;',
            'if(id==7U) { return context->state.module; } return context->state.buffer;'))
        code,text,_,result=self.check('wrong')
        self.assertEqual(code,2,text)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['formal_check']['status'],'disproved',result['formal_check']['result'])

    def test_unsupported_protocol_premise_reports_unavailable_without_solver_work(self):
        path=self.package/'interface.json';payload=copy.deepcopy(json.loads(path.read_text()))
        payload['protocol']['states'].append('other')
        write_json(path,_interface(payload).to_payload())
        code,text,_,result=self.check('unsupported')
        self.assertEqual(code,0,text)
        self.assertEqual(result['formal_check']['status'],'unavailable')
        self.assertIn('one protocol state',text)
        self.assertEqual(result['formal_check']['work_counts'],{'compiler':0,'model':0,'solver':0})
