"""State declarations travel through real authoring, execution, reuse and export."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

from spaghetti_extractor.cli import main
from spaghetti_extractor.components.comparison_package import prepare_comparison_package, load_comparison_package
from spaghetti_extractor.components.comparison_run import run_comparison
from spaghetti_extractor.components.comparison_composition import contract_identity
from spaghetti_extractor.components.comparison_dependencies import install_dependency, replace_dependency_packages
from spaghetti_extractor.components.service_authoring import component_interface
from spaghetti_extractor.components.state_ownership import checked_state_owners, check_state_owner_selection
from spaghetti_extractor.components.source_dialect import practical_source_profile
from spaghetti_extractor.components.source_handoff import load_source_export
from spaghetti_extractor.candidate.source_export import export_comparison_sources

TESTKIT = {'fixtures': ('compiler',), 'commands': ('component start',)}


class StatefulComponentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.owner = dict(id='fixture.counter', scope='module-instance', sources=['component.c'],
                          thread_state='none', reset='process-restart',
                          lifetime='One counter shared by both caller contexts until process exit.')

    def prepare(self, name='counter'):
        root=self.root/name;root.mkdir()
        interface=component_interface(component_id=name, services={},
            types=[dict(id='u32',kind='integer',width_bits=32,signed=False)],
            parameters=[('step','u32')], result='u32')
        (root/'interface.json').write_text(json.dumps(interface.to_payload()))
        (root/'state.json').write_text(json.dumps([self.owner]))
        (root/'component.c').write_text('#include "portable-component-implementation.h"\n'
            'static uint32_t counter;\n'
            f'uint32_t lifted_{name}_run(spx_{name}_context_v5 *ctx, uint32_t step) '
            '{ (void)ctx; counter += step; return counter; }\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(['component','start','fixture',name,'--interface-intent',str(root/'interface.json'),
                '--state-owners',str(root/'state.json'),'--source-file','source/component.c='+str(root/'component.c'),
                '--output',str(root/'authoring')]),0)
        self.assertIn('fixture.counter',(root/'authoring/BOUNDARY.md').read_text())
        inputs=runpy.run_path(str(root/'authoring/prepare.py'))['source_inputs']()
        (root/'original.c').write_text('static unsigned counter; unsigned original(unsigned step) { counter+=step; return counter; }\n')
        (root/'driver.c').write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
            '#include "portable-component-implementation.h"\nunsigned original(unsigned);\n'
            f'int main(int argc,char **argv) {{ spx_{name}_context_v5 contexts[2]={{0}}; unsigned a=0,b=0; '
            f'if(argc!=3)return 2; unsigned step=(unsigned)atoi(argv[2]); '
            f'if(!strcmp(argv[1],"source")){{ a=lifted_{name}_run(&contexts[0],step); '
            f'b=lifted_{name}_run(&contexts[1],step); }}else{{a=original(step);b=original(step);}} '
            'printf("{\\"values\\":[%u,%u]}\\n",a,b);return 0;}\n')
        package=root/'package'
        prepare_comparison_package(**inputs,adapter_files={'driver.c':root/'driver.c','original.c':root/'original.c'},
            include_files={},link_files={},runtime_files={},original_files=['adapters/original.c'],
            oracle_kind='retained-c',cases=[dict(id='one',arguments=['1']),dict(id='seven',arguments=['7'])],
            observation_fields=['values'],assumptions=['Two distinct caller contexts share one process counter.'],
            scope='Repeated calls and fresh process scenarios',compiler=Path(shutil.which('cc')),
            runner=None,server=None,output=package)
        return package

    def check(self, package, name, **options):
        plan,_=load_comparison_package(package)
        output=self.root/name
        result=run_comparison(package=package,output=output,target_id='fixture',component_id=plan['component_id'],**options)
        return result,output

    def test_module_state_survives_calls_exports_and_local_edits(self):
        package=self.prepare();result,first=self.check(package,'first')
        self.assertEqual(result['status'],'match',result)
        self.assertEqual(result['source_profile']['status'],'satisfied')
        self.assertEqual(result['source_profile']['proof_profile']['status'],'incomplete')
        report=export_comparison_sources(comparisons=[first],target_id='fixture',output=self.root/'export')
        self.assertEqual(report['components']['counter']['contract']['state_owners'],[self.owner])
        load_source_export(self.root/'export')
        self.assertIn('fixture.counter',(self.root/'export/components/counter/README.md').read_text())
        edited=package/'source/component.c'
        edited.write_text(edited.read_text().replace('counter += step','counter = step + counter'))
        result,second=self.check(package,'edited',reuse_previous=first)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],1)
        result,_=self.check(package,'cached',reuse_previous=second)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['execution'],0)
        edited.write_text(edited.read_text().replace('counter = step + counter','counter = step'))
        result,_=self.check(package,'defect',reuse_previous=second)
        self.assertEqual(result['status'],'mismatch')

    def test_undeclared_storage_still_blocks_execution_and_changes_contract(self):
        package=self.prepare();plan,_=load_comparison_package(package)
        declared=contract_identity(package,plan)
        del plan['state_owners'];(package/'comparison-plan.json').write_text(json.dumps(plan))
        self.assertNotEqual(contract_identity(package,plan),declared)
        result,_=self.check(package,'undeclared')
        self.assertEqual(result['status'],'source-profile-failed')
        self.assertEqual(result['work_counts']['execution'],0)

    def test_duplicate_providers_are_rejected_by_export(self):
        first=self.prepare();_,a=self.check(first,'a')
        second=self.prepare('other');_,b=self.check(second,'b')
        with self.assertRaisesRegex(ValueError,'multiple providers'):
            export_comparison_sources(comparisons=[a,b],target_id='fixture',output=self.root/'invalid')
        self.assertFalse((self.root/'invalid').exists())

    def test_selected_provider_shares_state_and_requires_review_for_lifecycle_change(self):
        supplier=self.prepare();caller=self.prepare('caller')
        bridge=self.root/'bridge.c'
        bridge.write_text('#include "portable-component-implementation.h"\n'
            'uint32_t shared_counter(uint32_t step) { spx_counter_context_v5 context={0}; '
            'return lifted_counter_run(&context,step); }\n')
        dependency=install_dependency(output=caller,identity='counter',package=supplier,
            adapters={'bridge.c':bridge})
        plan,_=load_comparison_package(caller)
        del plan['state_owners'];plan['dependencies']=[dependency]
        (caller/'comparison-plan.json').write_text(json.dumps(plan))
        (caller/'source/component.c').write_text('#include "portable-component-implementation.h"\n'
            'uint32_t shared_counter(uint32_t);\n'
            'uint32_t lifted_caller_run(spx_caller_context_v5 *ctx,uint32_t step) '
            '{ (void)ctx;return shared_counter(step); }\n')
        result,_=self.check(caller,'consumer')
        self.assertEqual(result['status'],'match',result)
        self.assertEqual(result['source_profiles']['counter']['state_owners'],[self.owner])
        # Same function signature, different lifecycle premise: existing callers
        # must use the boundary refinement path before adopting it.
        changed,_=load_comparison_package(supplier)
        changed['state_owners'][0]['lifetime']='A distinct instance is created per invocation.'
        (supplier/'comparison-plan.json').write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError,'state_owners'):
            replace_dependency_packages(caller,plan,{'counter':supplier})
        retained,_=load_comparison_package(caller)
        self.assertEqual(retained['dependencies'][0]['state_owners'],[self.owner])

    def test_unavailable_inspection_and_invalid_state_declarations_fail_closed(self):
        proof=dict(component_id='counter',bindings={},status='incomplete',issues=[])
        rows=[dict(source='component.c',status='incomplete',diagnostic='inspector unavailable')]
        self.assertEqual(practical_source_profile(proof,rows,state_owners=[self.owner])['status'],'incomplete')
        with self.assertRaisesRegex(ValueError,'not an authored'):
            checked_state_owners([self.owner],sources=['different.c'])
        with self.assertRaisesRegex(ValueError,'process-restart'):
            checked_state_owners([{**self.owner,'reset':'zero-memory'}])
        with self.assertRaisesRegex(ValueError,'multiple providers'):
            check_state_owner_selection({'one':[self.owner],'two':[self.owner]})
