"""Selected bodies use separate generated interfaces and invalidate consumers."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.comparison_dependencies import install_dependency
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.components.source import build_component_source_package
from tests.unit.components import test_comparison as base

TESTKIT = {'fixtures': ('compiler',), 'commands': ('component start','component check','component status'),
           'resources': ('tests/fixtures/jq-array-concat','tests/fixtures/jq-array-append')}


class ComparisonDependencyTests(unittest.TestCase):
    setUp = base.ComponentComparisonTests.setUp
    command = base.ComponentComparisonTests.command
    check = base.ComponentComparisonTests.check

    def supplier(self):
        source=self.root/'supplier.c'
        source.write_text('#include "portable-component-implementation.h"\n'
            'spx_jv_value_v2 lifted_array_append(spx_array_append_context_v5 *ctx, spx_jv_value_v2 a, spx_jv_value_v2 b) {'
            '(void)ctx; (void)a; return b; }\n')
        package=self.root/'supplier-source'
        build_component_source_package(lift_unit_id='array-append',files={'append.c':source},shared_inputs={},
            operation_symbols={'run':'lifted_array_append'},out_dir=package)
        driver=self.root/'supplier-driver.c';driver.write_text('int main(void) { return 0; }\n')
        supplier=self.root/'supplier'
        prepare_comparison_package(interface_package=Path(__file__).parents[2]/'fixtures/jq-array-append',
            source_package=package,target_id='fixture',component_id='array-append',adapter_files={'driver.c':driver},
            include_files={},link_files={},runtime_files={},original_files=['adapters/driver.c'],oracle_kind='fixture',
            cases=[{'id':'setup','arguments':[]}],observation_fields=['value'],assumptions=['synthetic value transport'],
            scope='fixture dependency packaging only',compiler=Path(shutil.which('cc')),runner=None,server=None,output=supplier)
        return supplier

    def select(self,supplier):
        bridge=self.root/'bridge.c'
        bridge.write_text('#include "portable-component-implementation.h"\n'
            'uint32_t fixture_supplier(uint32_t value) { spx_jv_value_v2 a={0}, b={0}; b.metadata=value;'
            'return lifted_array_append(0,a,b).metadata; }\n')
        row=install_dependency(output=self.package,identity='array-append',package=supplier,adapters={'bridge.c':bridge})
        path=self.package/'comparison-plan.json';plan=json.loads(path.read_text());plan['dependencies']=[row]
        path.write_text(json.dumps(plan))
        source=self.package/'source/component.c'
        source.write_text('#include <stdint.h>\nextern uint32_t fixture_supplier(uint32_t);\n'+source.read_text().replace(
            'a.metadata += b.metadata','a.metadata += fixture_supplier(b.metadata)'))

    def test_separate_headers_supplier_edit_and_integration_invalidation(self):
        supplier=self.supplier();self.select(supplier)
        code,text,baseline=self.check(self.package,'baseline')
        self.assertEqual(code,0,text)
        result=load_comparison_result(baseline)
        self.assertEqual(set(result['source_profiles']),{'array-concat','array-append'})
        self.assertNotIn('dependencies/array-append/adapters/driver.c',result['input_sha256s'])
        before={str(p.relative_to(self.package)):p.read_bytes() for p in self.package.rglob('*') if p.is_file()}
        with patch('subprocess.Popen',side_effect=AssertionError('preview must not execute tools')):
            code,text=self.command('status','fixture','array-concat','--comparison-package',str(self.package),
                '--reuse-comparison',str(baseline),'--json')
            focused_code,focused_text=self.command('status','fixture','array-append',
                '--comparison-result',str(baseline),'--json')
            self.assertEqual(focused_code,0,focused_text)
            focused=json.loads(focused_text)
            self.assertEqual(focused['component_id'],'array-append')
            self.assertEqual(focused['comparison_entry'],'array-concat')
            self.assertEqual(focused['cases'][0]['service_scope']['status'],'unavailable')
            self.assertEqual(focused['replay_command'][:5],['spaghetti-extractor','component','check','fixture','array-concat'])
        self.assertEqual(code,0,text)
        unchanged=json.loads(text)['comparison_changes']
        self.assertEqual(unchanged['execution_reuse']['status'],'eligible-after-source-checks')
        self.assertTrue(all(row['status']=='reusable' for row in unchanged['compilation']))
        self.assertEqual(unchanged['affected_consumers'],[])
        source=supplier/'source/append.c';source.write_text(source.read_text().replace('return b;','b.metadata += 1U; return b;'))
        with patch('subprocess.Popen',side_effect=AssertionError('preview must not execute tools')):
            code,text=self.command('status','fixture','array-concat','--comparison-package',str(self.package),
                '--dependency-package','array-append='+str(supplier),'--reuse-comparison',str(baseline),'--json')
        self.assertEqual(code,0,text)
        preview=json.loads(text)['comparison_changes']
        self.assertEqual(preview['execution_reuse']['status'],'recheck-required')
        compiling=[row['source'] for row in preview['compilation'] if row['status']=='compile-required']
        self.assertEqual(compiling,['dependencies/array-append/source/append.c'])
        self.assertEqual(preview['affected_consumers'],['array-append','array-concat'])
        self.assertTrue(all(not row['contract_changes'] for row in preview['components']))
        self.assertEqual(before,{str(p.relative_to(self.package)):p.read_bytes() for p in self.package.rglob('*') if p.is_file()})
        code,text,out=self.check(self.package,'changed','--dependency-package','array-append='+str(supplier),
            '--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'mismatch')
        self.assertIn('dependencies/array-append/source/append.c',result['reuse']['changed_inputs'])
        self.assertEqual(result['work_counts']['compiler'],len(compiling))
        self.assertEqual(result['reuse']['changed_inputs'],preview['execution_reuse']['changed_inputs'])

    def test_start_retains_selected_supplier_and_local_caller_without_execution(self):
        supplier=self.supplier();self.select(supplier)
        current=self.root/'current'
        self.assertEqual(self.command('start','fixture','array-concat','--comparison-package',str(self.package),
            '--output',str(current))[0],0)
        caller=current/'source/component.c';caller.write_text(caller.read_text()+'\n/* local caller edit */\n')
        source=supplier/'source/append.c'
        source.write_text(source.read_text().replace('return b;','b.metadata += 1U; return b;'))
        draft=self.root/'selected'
        with patch('subprocess.run',side_effect=AssertionError('preparation must not compile or execute')):
            code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
                '--reuse-source',str(current),'--dependency-package','array-append='+str(supplier),'--output',str(draft))
        self.assertEqual(code,0,text)
        self.assertIn('selected suppliers retained: array-append',text)
        self.assertEqual((draft/'source/component.c').read_bytes(),caller.read_bytes())
        self.assertEqual((draft/'dependencies/array-append/source/append.c').read_bytes(),source.read_bytes())
        # The subsequent check uses the stored choice without another selection
        # flag. Matching declarations never established this body's correctness.
        code,text,out=self.check(draft,'selected-check')
        self.assertEqual(code,2,text)
        self.assertEqual(load_comparison_result(out)['cases'][0]['observations'],
            {'original':{'value':5},'source':{'value':6}})

    def test_open_supplier_focus_reuses_only_its_c_and_keeps_consumer_scope(self):
        supplier=self.supplier();self.select(supplier)
        caller=self.package/'source/component.c'
        caller.write_text(caller.read_text()+'\n/* preserve the current caller */\n')
        current_caller=caller.read_bytes()
        work=self.root/'focused'
        with patch('subprocess.run',side_effect=AssertionError('opening an editor must not execute')):
            code,text=self.command('start','fixture','array-append','--comparison-package',str(self.package),
                '--output',str(work))
        self.assertEqual(code,0,text)
        self.assertIn('editing selected component array-append; retained consumer check: array-concat',text)
        self.assertIn('component check fixture array-append',text)
        self.assertEqual(json.loads((work/'comparison-plan.json').read_text())['component_id'],'array-concat')
        self.assertIn('Component workspace: array-concat',(work/'generated/workspace.md').read_text())
        self.assertIn('Component workspace: array-append',(work/'dependencies/array-append/generated/workspace.md').read_text())
        editor=json.loads((work/'compile_commands.json').read_text())
        self.assertTrue(all('/dependencies/array-append/' in row['file'] for row in editor))
        # A reused workspace can contain stale or unrelated caller edits. Only
        # the focused supplier travels back into the current consumer selection.
        (work/'source/component.c').write_text('unrelated caller work must not be imported\n')
        source=work/'dependencies/array-append/source/append.c'
        source.write_text(source.read_text().replace('return b;','b.metadata += 1U; return b;'))
        reopened=self.root/'focused-reopened'
        code,text=self.command('start','fixture','array-append','--comparison-package',str(self.package),
            '--reuse-source',str(work),'--output',str(reopened))
        self.assertEqual(code,0,text)
        self.assertEqual((reopened/'source/component.c').read_bytes(),current_caller)
        self.assertEqual((reopened/'dependencies/array-append/source/append.c').read_bytes(),source.read_bytes())
        history=self.root/'focused-checks'
        check=['check','fixture','array-append','--comparison-package',str(reopened),'--history',str(history)]
        code,text=self.command(*check)
        self.assertEqual(code,2,text)
        self.assertIn('checking selected component array-append through enclosing comparison array-concat',text)
        result=load_comparison_result((history/'latest').resolve())
        self.assertEqual(result['component_id'],'array-concat')
        self.assertEqual(result['cases'][0]['observations'],
            {'original':{'value':5},'source':{'value':6}})
        self.assertIn('component check fixture array-concat',text)  # exact consumer replay
        repaired=reopened/'dependencies/array-append/source/append.c'
        repaired.write_bytes((self.package/'dependencies/array-append/source/append.c').read_bytes())
        code,text=self.command(*check,'--json')
        self.assertEqual(code,0,text)
        self.assertEqual(json.loads(text)['component_id'],'array-concat')
        # Changing the focused name does not create a different history or
        # weaken the engine's consumer identity/reuse checks.
        code,text=self.command('check','fixture','array-concat','--comparison-package',str(reopened),
            '--history',str(history),'--json')
        self.assertEqual(code,0,text)
        self.assertEqual(json.loads(text)['work_counts'],dict(compiler=0,execution=0,link=0,model=0,solver=0))
        absent=self.root/'absent-output'
        code,text=self.command('check','fixture','absent','--comparison-package',str(reopened),'--output',str(absent))
        self.assertEqual(code,2,text);self.assertIn('selected components:',text)
        self.assertFalse(absent.exists())

    def test_same_signature_changed_contract_and_unknown_dependency_reject(self):
        supplier=self.supplier();self.select(supplier)
        path=supplier/'comparison-plan.json';plan=json.loads(path.read_text());plan['assumptions'].append('new restriction')
        path.write_text(json.dumps(plan))
        before={str(p.relative_to(self.package)):p.read_bytes() for p in self.package.rglob('*') if p.is_file()}
        code,text=self.command('status','fixture','array-concat','--comparison-package',str(self.package),
            '--dependency-package','array-append='+str(supplier),'--json')
        self.assertEqual(code,0,text)
        report=json.loads(text)['dependency_proposals'][0]
        self.assertEqual(report['status'],'changed')
        self.assertEqual(report['compatibility'],'not-evaluated')
        self.assertEqual(report['changes'],[dict(field='assumptions',previous=['synthetic value transport'],
            proposed=['synthetic value transport','new restriction'])])
        self.assertEqual(before,{str(p.relative_to(self.package)):p.read_bytes() for p in self.package.rglob('*') if p.is_file()})
        draft=self.root/'rejected-draft'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
            '--dependency-package','array-append='+str(supplier),'--output',str(draft))
        self.assertEqual(code,2,text);self.assertIn('dependency contract changed',text)
        self.assertFalse(draft.exists())
        self.assertEqual(before,{str(p.relative_to(self.package)):p.read_bytes() for p in self.package.rglob('*') if p.is_file()})
        code,text,_=self.check(self.package,'contract','--dependency-package','array-append='+str(supplier))
        self.assertEqual(code,2,text);self.assertIn('dependency contract changed',text)
        self.assertIn('new restriction',text)
        code,text,_=self.check(self.package,'unknown','--dependency-package','unselected='+str(supplier))
        self.assertEqual(code,2,text);self.assertIn('absent from this comparison',text)
        code,text=self.command('status','fixture','array-concat','--dependency-package','array-append='+str(supplier))
        self.assertEqual(code,2,text);self.assertIn('requires --comparison-package',text)

    def test_refined_supplier_domain_exposes_actual_caller_assumption(self):
        supplier=self.supplier()
        path=supplier/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['input_domain']={'words':['value'],'constraints':[{'argument_index':0,'minimum':0,'maximum':10}]}
        path.write_text(json.dumps(plan));self.select(supplier)
        bridge=self.package/'dependencies/array-append/bridges/bridge.c'
        bridge.write_text(bridge.read_text().replace('#include "portable-component-implementation.h"',
            '#include "portable-component-implementation.h"\n#include "comparison-input-domain.h"').replace(
            'return lifted_array_append', 'uint32_t words[]={value}; if(!spx_comparison_admit_input(words,1)) exit(77); return lifted_array_append'))
        code,text,baseline=self.check(self.package,'baseline-domain');self.assertEqual(code,0,text)
        plan['input_domain']['constraints'][0]['maximum']=0;path.write_text(json.dumps(plan))
        code,text,_=self.check(self.package,'needs-refinement','--dependency-package','array-append='+str(supplier))
        self.assertEqual(code,2,text);self.assertIn('dependency contract changed',text)
        selection=self.package/'comparison-plan.json';current=json.loads(selection.read_text())
        current['dependencies'][0]['input_domain']=plan['input_domain'];selection.write_text(json.dumps(current))
        code,text,out=self.check(self.package,'refined-domain','--dependency-package','array-append='+str(supplier),
            '--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text);self.assertIn('assumption-violated',text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(result['cases'][0]['domain_events']['source'],{'component_id':'array-append','words':[2]})
        self.assertEqual(result['refinement']['domain_changes']['array-append']['relation'],'narrowed')

    def test_supplier_compiled_storage_prevents_execution(self):
        supplier=self.supplier();self.select(supplier)
        source=supplier/'source/append.c';source.write_text(source.read_text()+'\nvolatile int invalid_global;\n')
        code,text,out=self.check(self.package,'profile','--dependency-package','array-append='+str(supplier))
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'source-profile-failed')
        self.assertEqual(result['source_profiles']['array-append']['status'],'incomplete')
        self.assertGreater(result['work_counts']['compiler'],0)
        self.assertEqual(result['work_counts']['execution'],0)

    def test_editor_commands_select_each_components_generated_header(self):
        supplier=self.supplier();self.select(supplier)
        draft=self.root/'draft'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),'--output',str(draft))
        self.assertEqual(code,0,text)
        commands=json.loads((draft/'compile_commands.json').read_text())
        by_file={Path(row['file']).relative_to(draft).as_posix():row for row in commands}
        self.assertIn(str(draft/'generated'),by_file['source/component.c']['arguments'])
        arguments=by_file['dependencies/array-append/source/append.c']['arguments']
        self.assertIn(str(draft/'dependencies/array-append/generated'),arguments)
        self.assertNotIn(str(draft/'generated'),arguments)
        adapter=by_file['dependencies/array-append/bridges/bridge.c']
        self.assertIn(str(draft/'dependencies/array-append/generated'),adapter['arguments'])
        syntax=subprocess.run(adapter['arguments'],cwd=adapter['directory'],capture_output=True,text=True)
        self.assertEqual(syntax.returncode,0,syntax.stderr)
        guide=(draft/'generated/workspace.md').read_text()
        neighbor=(draft/'dependencies/array-append/generated/workspace.md').read_text()
        self.assertIn('../dependencies/array-append/generated/workspace.md',guide)
        self.assertIn('../source/append.c',neighbor)
        self.assertIn('../../../generated/workspace.md',neighbor)
        self.assertIn('not exhaustive admitted inputs or per-neighbor test evidence',neighbor)
