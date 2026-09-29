"""Actual compiled local comparisons retain failures and enforce input scope."""
from __future__ import annotations

import json
from pathlib import Path
import shlex
import shutil
from unittest.mock import patch

from spaghetti_extractor.components.comparison_package import prepare_comparison_package,load_comparison_package,retained_comparison_environment
from spaghetti_extractor.components.comparison_run import first_difference,load_comparison_result,comparison_result_identity

TESTKIT = {'fixtures':('compiler',),'commands':('component start','component check','component status'),
           'resources':('tests/fixtures/jq-array-concat',)}


from .comparison_fixture import ComparisonFixture

class ComponentComparisonTests(ComparisonFixture):


    def test_history_reuses_latest_and_retains_discrepancies_through_repair(self):
        code,text,seed=self.check(self.package,'initial-check')
        self.assertEqual(code,0,text)
        history=self.root/'checks'
        args=['check','fixture','array-concat','--comparison-package',str(self.package),'--history',str(history),
              '--history-baseline',str(seed)]
        code,text=self.command(*args)
        self.assertEqual(code,0,text);self.assertIn('history latest:',text)
        baseline=(history/'latest').resolve()
        self.assertEqual(load_comparison_result(baseline)['work_counts'],dict(compiler=0,execution=0,link=0,model=0,solver=0))
        baseline_receipt=(baseline/'comparison-result.json').read_bytes()
        seed.rename(self.root/'moved-initial-check')  # Later checks use their own history, not the initial location.
        code,text=self.command(*args,'--json')
        self.assertEqual(code,0,text)
        self.assertEqual(json.loads(text)['work_counts'],dict(compiler=0,execution=0,link=0,model=0,solver=0))
        self.assertNotEqual((history/'latest').resolve(),baseline)
        source=self.package/'source/component.c';original=source.read_bytes()
        source.write_bytes(original.replace(b'a.metadata += b.metadata',b'a.metadata += b.metadata+1U'))
        code,text=self.command(*args)
        self.assertEqual(code,2,text)
        wrong=(history/'latest').resolve();result=load_comparison_result(wrong)
        self.assertEqual(result['status'],'mismatch');self.assertEqual(result['work_counts']['compiler'],1)
        wrong_receipt=(wrong/'comparison-result.json').read_bytes()
        replay=shlex.split(next(line.partition('replay: ')[2] for line in text.splitlines() if 'replay: ' in line))
        self.assertIn(str(wrong/'inputs'),replay)
        self.assertNotIn(str(history/'latest'),replay)
        source.write_bytes(original)
        code,text=self.command(*args)
        self.assertEqual(code,0,text)
        repaired=(history/'latest').resolve()
        self.assertEqual(load_comparison_result(repaired)['work_counts']['compiler'],1)
        self.assertEqual((baseline/'comparison-result.json').read_bytes(),baseline_receipt)
        self.assertEqual((wrong/'comparison-result.json').read_bytes(),wrong_receipt)
        code,text=self.command(*replay[2:])
        self.assertEqual(code,2,text);self.assertIn('comparison=mismatch',text)
        self.assertEqual((history/'latest').resolve(),repaired)

    def test_history_separates_components_and_serializes_checks_without_losing_latest(self):
        from spaghetti_extractor.operator.comparison_history import comparison_history
        history=self.root/'checks'
        options=dict(history=history,package=self.package,target='fixture',component='array-concat')
        with self.assertRaisesRegex(ValueError,'aborted preparation'):
            with comparison_history(**options):
                with self.assertRaisesRegex(ValueError,'another check is using'):
                    with comparison_history(**options):self.fail('two checks claimed one history')
                raise ValueError('aborted preparation')
        self.assertFalse((history/'latest').is_symlink())
        args=['check','fixture','array-concat','--comparison-package',str(self.package),'--history',str(history)]
        code,text=self.command(*args);self.assertEqual(code,0,text)
        before=(history/'latest').resolve()
        with self.assertRaisesRegex(ValueError,'another target/component'):
            with comparison_history(**{**options,'component':'another'}):self.fail('mixed component history')
        with self.assertRaisesRegex(ValueError,'outside the editable input'):
            with comparison_history(**{**options,'history':self.package/'checks'}):self.fail('nested input/output')
        # Preparation errors leave the last terminal result available for reuse.
        code,text=self.command(*args,'--case','absent-case')
        self.assertEqual(code,2,text)
        self.assertEqual((history/'latest').resolve(),before)
        self.assertEqual(load_comparison_result(before)['status'],'match')

    def test_later_compiler_error_is_visible_after_successful_verbose_output(self):
        driver=self.root/'broken-driver.c'
        driver.write_text((self.root/'driver.c').read_text()+'\n#error operator_adapter_compile_failure\n')
        package=self.root/'broken-package'
        prepare_comparison_package(interface_package=Path(__file__).parents[2]/'fixtures/jq-array-concat',
            source_package=self.root/'source',target_id='fixture',component_id='array-concat',
            adapter_files={'driver.c':driver},include_files={},link_files={},runtime_files={},
            original_files=['adapters/driver.c'],oracle_kind='fixture',
            cases=[dict(id='three',arguments=['3'])],observation_fields=['value'],
            assumptions=['synthetic compiler diagnostic fixture'],scope='visible compilation failure',
            compiler=Path(shutil.which('cc')),runner=None,server=None,output=package)
        code,text,output=self.check(package,'broken-check')
        self.assertEqual(code,2)
        self.assertEqual(load_comparison_result(output)['status'],'compile-failed')
        self.assertTrue((output/'build/compile-0.stderr').read_text().strip())
        self.assertTrue((output/'build/unit-0.o').is_file())
        self.assertIn('operator_adapter_compile_failure',text)
        self.assertIn('compile-1.stderr',text)


    def test_direct_source_inputs_cannot_override_a_bound_source_package(self):
        from spaghetti_extractor.components.comparison_package import _comparison_source

        for files,symbols,message in [({},None,'choose a source package'),
                                      (None,{'run':'other'},'choose a source package')]:
            with self.subTest(files=files,symbols=symbols),self.assertRaisesRegex(ValueError,message):
                with _comparison_source(component_id='array-concat',source_package=self.root/'source',
                        source_files=files,operation_symbols=symbols):
                    self.fail('accepted conflicting source inputs')
        for files,symbols in [(None,None),({'component.c':self.authored},None)]:
            with self.subTest(files=files),self.assertRaisesRegex(ValueError,'require explicit operation symbols'):
                with _comparison_source(component_id='array-concat',source_package=None,
                        source_files=files,operation_symbols=symbols):
                    self.fail('accepted incomplete direct source inputs')

    def test_source_refactor_preserves_boundary_and_oracle_without_repreparation(self):
        from spaghetti_extractor.components.comparison_package import revise_comparison_package
        from spaghetti_extractor.components.comparison_composition import contract_identity
        from spaghetti_extractor.util import sha256_file

        code,text,baseline=self.check(self.package,'before-refactor')
        self.assertEqual(code,0,text)
        plan,_=load_comparison_package(self.package)
        original=(self.package/'source/component.c').read_text()
        (self.package/'operator-notes.txt').write_text('keep the reviewed setup')
        sources={'run.c':original.replace('a.metadata += b.metadata','a.metadata = local_sum(a.metadata,b.metadata)').replace(
            '#include "portable-component-implementation.h"','#include "portable-component-implementation.h"\n#include "sum.h"'),
            'sum.h':'#include <stdint.h>\nuint32_t local_sum(uint32_t a,uint32_t b);\n',
            'sum.c':'#include "sum.h"\nuint32_t local_sum(uint32_t a,uint32_t b) { return a+b; }\n'}
        authored=self.root/'refactor-source';authored.mkdir()
        for name,contents in sources.items():(authored/name).write_text(contents)
        sources={name:authored/name for name in sources}
        revised=self.root/'refactored'
        revise_comparison_package(package=self.package,output=revised,source_files=sources)
        current,_=load_comparison_package(revised)
        self.assertEqual(contract_identity(revised,current),contract_identity(self.package,plan))
        self.assertEqual({k:v for k,v in current.items() if k!='sources'},
                         {k:v for k,v in plan.items() if k!='sources'})
        self.assertFalse((revised/'source/component.c').exists())
        self.assertEqual((self.package/'source/component.c').read_text(),original)
        self.assertEqual((revised/'operator-notes.txt').read_text(),'keep the reviewed setup')
        for name in plan['original']['files']:
            self.assertEqual(sha256_file(revised/name),sha256_file(self.package/name))
        code,text,result=self.check(revised,'after-refactor','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        self.assertEqual(load_comparison_result(result)['cases'][0]['observations']['source']['value'],5)
        (self.package/'source/sum.h').write_text('/* retained input, not authored by this unit */\n')
        with self.assertRaisesRegex(ValueError,'unowned file'):
            revise_comparison_package(package=self.package,output=self.root/'collision',source_files=sources)
        self.assertFalse((self.root/'collision').exists())
        plan['original']['files']['source/component.c']=sha256_file(self.package/'source/component.c')
        (self.package/'comparison-plan.json').write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError,'original comparison oracle'):
            revise_comparison_package(package=self.package,output=self.root/'oracle-edit',source_files=sources)
        self.assertFalse((self.root/'oracle-edit').exists())

    def test_retained_environment_reuses_only_validated_tools_and_runtime_roles(self):
        environment=retained_comparison_environment(self.package)
        self.assertEqual(set(environment),{'compiler','runner','server','link_files','runtime_files'})
        self.assertEqual(environment['compiler'],Path(shutil.which('cc')).resolve())
        self.assertIsNone(environment['runner'])
        self.assertEqual(environment['runtime_files'],{})
        (self.package/'adapters/driver.c').write_text('stale oracle')
        with self.assertRaisesRegex(ValueError,'original comparison input is stale'):
            retained_comparison_environment(self.package)

    def test_new_case_arguments_are_retained_without_editing_the_workspace(self):
        original_plan=(self.package/'comparison-plan.json').read_bytes()
        options=('--case','seven','--case-arguments','["7"]')
        code,text,baseline=self.check(self.package,'extra-case',*options)
        self.assertEqual(code,0,text)
        result=load_comparison_result(baseline)
        self.assertEqual(result['case_selection'],'seven')
        self.assertEqual(result['cases'][0]['observations']['source'],{'value':9})
        plan,_=load_comparison_package(baseline/'inputs')
        self.assertEqual(plan['cases'],[dict(id='three',arguments=['3']),dict(id='seven',arguments=['7'])])
        self.assertEqual((self.package/'comparison-plan.json').read_bytes(),original_plan)

        source=self.package/'source/component.c';good=source.read_text()
        source.write_text(good.replace('+=','-='))
        code,text,wrong=self.check(self.package,'extra-wrong',*options,'--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        source.write_text(good)
        replay=shlex.split(next(line.partition('replay: ')[2] for line in text.splitlines() if 'replay: ' in line))
        self.assertNotIn('--case-arguments',replay)
        code,diagnostic=self.command(*replay[2:])
        self.assertEqual(code,2,diagnostic)
        replayed=load_comparison_result(self.root/'extra-wrong-replay')
        self.assertEqual(replayed['cases'],load_comparison_result(wrong)['cases'])
        self.assertEqual(replayed['work_counts']['compiler'],0)

        from spaghetti_extractor.components.comparison_package import revise_comparison_package
        another=self.root/'another-case'
        revise_comparison_package(package=self.package,output=another,cases=[dict(id='nine',arguments=['9'])])
        current=good+'\n/* Continue editing after retaining the discrepancy. */\n'
        source.write_text(current)
        expanded=self.root/'expanded'
        with patch('subprocess.Popen',side_effect=AssertionError('case import must not run tools')):
            code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
                '--reuse-cases',str(baseline),'--reuse-cases',str(wrong/'inputs'),
                '--reuse-cases',str(another),'--output',str(expanded))
        self.assertEqual(code,0,text)
        self.assertEqual(load_comparison_package(expanded)[0]['cases'],[*plan['cases'],dict(id='nine',arguments=['9'])])
        self.assertEqual((expanded/'source/component.c').read_text(),current)
        self.assertFalse((expanded/'comparison-result.json').exists())
        collision=self.root/'collision-case'
        revise_comparison_package(package=self.package,output=collision,cases=[dict(id='seven',arguments=['9'])])
        rejected=self.root/'rejected-cases'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(expanded),
            '--reuse-cases',str(collision),'--output',str(rejected))
        self.assertEqual(code,2,text)
        self.assertIn('reused case name has different arguments: seven',text)
        self.assertFalse(rejected.exists())
        for name,args in [('existing',('--case','three','--case-arguments','["9"]')),
                          ('number',('--case','nine','--case-arguments','[9]')),
                          ('null',('--case','three','--case-arguments','null')),
                          ('unnamed',('--case-arguments','["9"]'))]:
            code,text,output=self.check(self.package,'invalid-'+name,*args)
            self.assertEqual(code,2,text)
            self.assertFalse(output.exists())
        self.assertEqual((self.package/'comparison-plan.json').read_bytes(),original_plan)

    def test_case_files_extend_a_retained_check_without_fixture_edits(self):
        code,text,baseline=self.check(self.package,'case-file-baseline','--case','three')
        self.assertEqual(code,0,text)
        first=self.root/'generated.json';second=self.root/'manual.json'
        first.write_text(json.dumps([dict(id='seven',arguments=['7'])]))
        second.write_text(json.dumps([dict(id='seven',arguments=['7']),dict(id='nine',arguments=['9'])]))
        expanded=self.root/'case-file-work'
        with patch('subprocess.Popen',side_effect=AssertionError('case import must not run tools')):
            code,text=self.command('start','fixture','array-concat','--comparison-result',str(baseline),
                '--case-file',str(first),'--case-file',str(second),'--output',str(expanded))
        self.assertEqual(code,0,text)
        command=shlex.split(next(line.removeprefix('next: ') for line in text.splitlines() if line.startswith('next: ')))
        self.assertNotIn('--case',command)  # Opening a single-case result must not omit the newly added cases.
        first.unlink();second.unlink()  # The draft retains data, not mutable file references.
        self.assertEqual((expanded/'source/component.c').read_bytes(),(self.package/'source/component.c').read_bytes())
        self.assertEqual(load_comparison_package(self.package)[0]['cases'],[dict(id='three',arguments=['3'])])
        code,text=self.command(*command[2:])
        self.assertEqual(code,0,text)
        result=load_comparison_result(self.root/'case-file-work-checks/latest')
        self.assertEqual([row['id'] for row in result['cases']],['three','seven','nine'])
        self.assertEqual(result['work_counts']['compiler'],0)
        self.assertEqual(result['work_counts']['execution'],6)
        self.assertEqual([row['observations']['source']['value'] for row in result['cases']],[5,9,11])
        for name,rows,diagnostic in [('collision',[dict(id='three',arguments=['4'])],'different arguments: three'),
                                     ('invalid',[dict(id='numeric',arguments=[4])],'string arguments')]:
            first.write_text(json.dumps(rows));output=self.root/('case-file-'+name)
            code,text=self.command('start','fixture','array-concat','--comparison-package',str(expanded),
                '--case-file',str(first),'--output',str(output))
            self.assertEqual(code,2,text)
            self.assertIn(diagnostic,text)
            self.assertIn(str(first),text)
            self.assertFalse(output.exists())

    def test_public_edit_failure_replay_and_repair(self):
        draft=self.root/'draft'
        self.assertEqual(self.command('start','fixture','array-concat','--comparison-package',str(self.package),
                                     '--output',str(draft))[0],0)
        self.assertTrue((draft/'compile_commands.json').is_file())
        code,text,baseline=self.check(draft,'baseline')
        self.assertEqual(code,0,text)
        self.assertFalse(json.loads((baseline/'comparison-result.json').read_text())['authorizing'])
        edited=draft/'source/component.c'
        good=edited.read_text()
        edited.write_text(good.replace('+=','-='))
        code,text,wrong=self.check(draft,'wrong','--case','three')
        self.assertEqual(code,2,text)
        self.assertIn('$.value',text)
        self.assertIn('replay:',text)
        self.assertIn('observation context at $:',text)
        self.assertIn('original: {"value": 5}',text)
        self.assertIn('source:   {"value": 1}',text)
        edited.write_text(good)
        code,diagnostic,repaired=self.check(draft,'repaired')
        self.assertEqual(code,0,diagnostic)
        self.assertEqual(load_comparison_result(repaired)['status'],'match')
        # Inspect historical failures after repair without recompiling or executing.
        retained={str(p.relative_to(wrong)):p.read_bytes() for p in wrong.rglob('*') if p.is_file()}
        with (patch('spaghetti_extractor.commands.workflows._operator_index',side_effect=AssertionError('built target')),
              patch('spaghetti_extractor.operator.comparison.run_comparison',side_effect=AssertionError('ran comparison')),
              patch('subprocess.run',side_effect=AssertionError('ran subprocess'))):
            code,inspection=self.command('status','fixture','array-concat','--comparison-result',str(wrong))
            self.assertEqual(code,0,inspection)
            self.assertIn('Retained evidence: no fresh execution',inspection)
            self.assertIn('comparison=mismatch',inspection)
            self.assertIn('original: {"value": 5}',inspection)
            self.assertIn('source:   {"value": 1}',inspection)
            self.assertIn(str(wrong/'cases/0000-original.stdout'),inspection)
            code,payload=self.command('status','fixture','array-concat','--comparison-result',str(repaired),'--json')
            self.assertEqual(code,0,payload)
            self.assertEqual(json.loads(payload),load_comparison_result(repaired))
            code,payload=self.command('status','fixture','array-concat','--comparison-result',str(repaired),
                '--case','three','--details','--json')
            self.assertEqual(code,0,payload)
            focused=json.loads(payload)
            self.assertEqual([row['id'] for row in focused['cases']],['three'])
            self.assertEqual(focused['authority'],'authoring-guidance')
            self.assertNotIn('--case',focused['replay_command'])
            code,diagnostic=self.command('status','fixture','array-concat','--comparison-result',str(repaired),
                '--case','absent')
            self.assertEqual(code,2,diagnostic)
            self.assertIn('case is absent from this retained comparison',diagnostic)
            code,diagnostic=self.command('status','fixture','other','--comparison-result',str(wrong))
            self.assertEqual(code,2,diagnostic)
            self.assertIn('another target/component identity',diagnostic)
        self.assertEqual(retained,{str(p.relative_to(wrong)):p.read_bytes() for p in wrong.rglob('*') if p.is_file()})
        # Replay uses retained wrong inputs after the working draft was repaired.
        replay=shlex.split(next(line.partition('replay: ')[2] for line in text.splitlines() if 'replay: ' in line))
        code,diagnostic=self.command(*replay[2:])
        self.assertEqual(code,2,diagnostic)
        replayed=load_comparison_result(self.root/'wrong-replay')
        self.assertEqual(replayed['case_selection'],'three')
        self.assertEqual(replayed['cases'][0]['first_difference'],load_comparison_result(wrong)['cases'][0]['first_difference'])
        self.assertEqual(replayed['work_counts'],dict(compiler=0,link=1,execution=2,model=0,solver=0))
        phases={r['phase'] for r in json.loads((baseline/'comparison-result.json').read_text())['timings']}
        self.assertTrue({'preparation','compiler','link','execution'}<=phases)

    def test_comparison_sides_have_private_suite_shared_files(self):
        from spaghetti_extractor.util import sha256_file
        driver=self.package/'adapters/driver.c'
        driver.write_text('#include <stdio.h>\n#include <string.h>\n'
            '#include "portable-component-implementation.h"\n'
            'int main(int argc,char **argv) { if(argc!=2) return 2;\n'
            'FILE *f=fopen("marker", "r"); int seen=f!=NULL;\n'
            'if (f) fclose(f);\n'
            'f=fopen("marker", "w"); if (!f) return 3; fclose(f);\n'
            'spx_jv_value_v2 a={0}, b={0}; a.metadata=(uint32_t)seen;\n'
            'uint32_t result=!strcmp(argv[1],"original") ? a.metadata : lifted_array_concat(0,a,b).metadata;\n'
            'printf("{\\\"value\\\":%u}\\n",result); return 0; }\n')
        path=self.package/'comparison-plan.json'
        plan=json.loads(path.read_text())
        plan['original']['files']['adapters/driver.c']=sha256_file(driver)
        plan['cases']=[{'id':'first','arguments':[]},{'id':'second','arguments':[]}]
        path.write_text(json.dumps(plan))
        code,text,out=self.check(self.package,'private-state')
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertEqual(result['runtime_state']['case_state'],'suite-shared')
        for row,expected in zip(result['cases'],(0,1),strict=True):
            self.assertEqual(row['observations'],{side:{'value':expected} for side in ('original','source')})
        self.assertFalse((out/'build/marker').exists())
        for side in ('original','source'):
            self.assertTrue((out/f'runtime-{side}/marker').is_file())

        # The second case depends on the first case's file. A single-case replay
        # starts without it and hides this implementation defect after repair.
        source=self.package/'source/component.c';good=source.read_text()
        source.write_text(good.replace('a.metadata += b.metadata;',
            'a.metadata += b.metadata + (a.metadata != 0);'))
        code,text,wrong=self.check(self.package,'wrong-state','--reuse-comparison',str(out))
        self.assertEqual(code,2,text)
        receipt=load_comparison_result(wrong)
        self.assertEqual([r['status'] for r in receipt['cases']],['match','mismatch'])
        source.write_text(good)
        replay=shlex.split(next(line.partition('replay: ')[2] for line in text.splitlines() if 'replay: ' in line))
        code,diagnostic=self.command(*replay[2:])
        self.assertEqual(code,2,diagnostic)
        replayed=load_comparison_result(self.root/'wrong-state-replay')
        self.assertEqual(replayed['case_selection'],receipt['case_selection'])
        self.assertEqual(replayed['cases'],receipt['cases'])
        self.assertEqual(replayed['work_counts'],dict(compiler=0,link=1,execution=4,model=0,solver=0))

    def test_missing_observation_cannot_match_itself(self):
        path=self.package/'comparison-plan.json'
        plan=json.loads(path.read_text());plan['cases']=[{'id':'missing','arguments':['missing']}]
        path.write_text(json.dumps(plan))
        code,text,out=self.check(self.package,'missing')
        self.assertEqual(code,2,text)
        result=json.loads((out/'comparison-result.json').read_text())
        self.assertEqual(result['cases'][0]['status'],'invalid-observation')

    def test_empty_case_set_and_stale_oracle_fail_before_execution(self):
        path=self.package/'comparison-plan.json'
        text=path.read_text()
        plan=json.loads(text);plan['cases']=[]
        path.write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError,'no cases'):
            load_comparison_package(self.package)
        path.write_text(text)
        (self.package/'adapters/driver.c').write_text('changed original fixture')
        code,message,_=self.check(self.package,'stale')
        self.assertEqual(code,2)
        self.assertIn('original comparison input is stale',message)

    def test_compiled_storage_failure_prevents_execution(self):
        source=self.package/'source/component.c'
        source.write_text(source.read_text()+'\nvolatile int global;\n')
        code,text,out=self.check(self.package,'profile')
        self.assertEqual(code,2,text)
        result=json.loads((out/'comparison-result.json').read_text())
        self.assertEqual(result['status'],'source-profile-failed')
        self.assertTrue(any(row['phase']=='compiler' for row in result['timings']))
        self.assertFalse(any(row['phase']=='execution' for row in result['timings']))

    def test_compiled_header_storage_is_observed(self):
        path=self.package/'comparison-plan.json'
        plan=json.loads(path.read_text());plan['sources'].append('source/helper.h')
        path.write_text(json.dumps(plan))
        (self.package/'source/helper.h').write_text('volatile int shared;\n')
        source=self.package/'source/component.c'
        source.write_text('#include "helper.h"\n'+source.read_text())
        code,text,out=self.check(self.package,'header')
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'source-profile-failed')
        self.assertIn('shared',result['source_profile']['issues'][0]['diagnostic'])

    def test_compiler_view_and_execution_accept_active_macro_code(self):
        source=self.package/'source/component.c'
        source.write_text('#define SUM(a,b) ((a)+(b))\n#if 0\nvoid *inactive_malloc(unsigned long);\n#endif\n'+
                          source.read_text().replace('a.metadata += b.metadata','a.metadata = SUM(a.metadata,b.metadata)'))
        code,text,out=self.check(self.package,'macro-view','--compiler-view')
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertEqual(result['source_profile']['proof_profile']['status'],'incomplete')
        view=out/'build/compiler-views/0'
        metadata=json.loads((view/'view.json').read_text())
        self.assertEqual(metadata['status'],'available')
        self.assertTrue(metadata['inputs'])
        self.assertNotIn('inactive_malloc',(view/'active.i').read_text())
        code,text,reused=self.check(self.package,'macro-reuse','--reuse-comparison',str(out))
        self.assertEqual(code,0,text)
        self.assertEqual(load_comparison_result(reused)['work_counts']['compiler'],0)

    def test_timeout_is_inconclusive_and_process_is_terminated(self):
        path=self.package/'comparison-plan.json'
        plan=json.loads(path.read_text());plan['cases']=[{'id':'timeout','arguments':['timeout']}]
        path.write_text(json.dumps(plan))
        code,text,out=self.check(self.package,'timeout','--comparison-timeout','1')
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(result['cases'][0]['status'],'timeout')
        self.assertIn('execution: original timed out; source not run',text)
        self.assertIn(str(out/'cases/0000-original.stderr'),text)
        self.assertTrue(any(row.get('timed_out') for row in result['timings']))

    def test_observation_types_and_order_are_significant(self):
        self.assertEqual(first_difference({'v':True},{'v':1})['kind'],'type')
        self.assertEqual(first_difference([1,2],[2,1])['path'],'$[0]')
        self.assertEqual(first_difference([1],[1,2])['kind'],'length')

    def test_rehashed_omission_and_changed_binary_are_rejected(self):
        code,text,out=self.check(self.package,'integrity')
        self.assertEqual(code,0,text)
        path=out/'comparison-result.json'
        original=path.read_text()
        result=json.loads(original)
        result['cases']=[]
        result['receipt_sha256']=comparison_result_identity({k:v for k,v in result.items() if k!='receipt_sha256'})
        path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError,'omits selected cases'):
            load_comparison_result(out)
        path.write_text(original)
        with (out/'build/comparison.exe').open('ab') as file:
            file.write(b'changed')
        with self.assertRaisesRegex(ValueError,'artifact is stale'):
            load_comparison_result(out)

    def test_reuse_performs_no_compilation_link_or_execution_after_unrelated_growth(self):
        code,text,baseline=self.check(self.package,'baseline')
        self.assertEqual(code,0,text)
        # A neighboring implementation is not an input to this component's fixture.
        neighbor=self.package/'neighbors';neighbor.mkdir()
        (neighbor/'supplier.c').write_text('/* unrelated implementation growth */\n'*10000)
        walk=Path.rglob
        def bounded_walk(path,*args,**kwargs):
            if path==self.root/'reused':
                raise AssertionError('walked unrelated runtime and archive trees')
            return walk(path,*args,**kwargs)
        with (patch.object(Path,'rglob',bounded_walk),
              patch('spaghetti_extractor.components.comparison_run.compile_comparison',side_effect=AssertionError('compiled')),
              patch('spaghetti_extractor.components.comparison_run.observed_command',side_effect=AssertionError('executed'))):
            code,text,out=self.check(self.package,'reused','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertEqual(result['reuse']['status'],'reused')
        self.assertEqual(set(result['work_counts'].values()),{0})
        self.assertEqual(result['cases'],load_comparison_result(baseline)['cases'])
        self.assertNotIn('neighbors/supplier.c',result['input_sha256s'])
        # A copied result is independently readable; changed origin claims reject.
        (out/'reuse/source-result.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'source identity is stale'):
            load_comparison_result(out)

    def test_legacy_reused_receipt_reads_but_requires_new_runtime_evidence(self):
        code,text,baseline=self.check(self.package,'baseline')
        self.assertEqual(code,0,text)
        code,text,out=self.check(self.package,'reused','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        # Emulate a retained observation from before runtime scope was explicit.
        archive=out/'reuse/source-result.json'
        prior=json.loads(archive.read_text());prior.pop('runtime_state')
        prior['receipt_sha256']=comparison_result_identity({k:v for k,v in prior.items() if k!='receipt_sha256'})
        archive.write_text(json.dumps(prior))
        result_path=out/'comparison-result.json'
        current=json.loads(result_path.read_text());current.pop('runtime_state')
        current['reuse']['receipt_sha256']=prior['receipt_sha256']
        current['receipt_sha256']=comparison_result_identity({k:v for k,v in current.items() if k!='receipt_sha256'})
        result_path.write_text(json.dumps(current))
        self.assertEqual(load_comparison_result(out)['status'],'match')
        code,text,fresh=self.check(self.package,'new-scope','--reuse-comparison',str(out))
        self.assertEqual(code,0,text)
        fresh_result=load_comparison_result(fresh)
        self.assertIn('runtime_state',fresh_result['reuse']['reasons'])
        self.assertGreater(fresh_result['work_counts']['execution'],0)

    def test_contract_meaning_edit_invalidates_reuse_without_signature_change(self):
        code,text,baseline=self.check(self.package,'baseline')
        self.assertEqual(code,0,text)
        path=self.package/'comparison-plan.json'
        plan=json.loads(path.read_text());plan['assumptions'].append('only nonnegative admitted metadata')
        path.write_text(json.dumps(plan))
        code,text,out=self.check(self.package,'refined','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertEqual(result['reuse']['status'],'invalidated')
        self.assertIn('input_sha256s',result['reuse']['reasons'])
        self.assertGreater(result['work_counts']['execution'],0)

    def test_implementation_edit_invalidates_and_cannot_reuse_a_known_match(self):
        code,text,baseline=self.check(self.package,'baseline')
        self.assertEqual(code,0,text)
        source=self.package/'source/component.c'
        source.write_text(source.read_text().replace('+=','-='))
        code,text,out=self.check(self.package,'wrong','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'mismatch')
        self.assertEqual(result['reuse']['status'],'invalidated')

    def test_changed_external_compiler_input_invalidates_reuse(self):
        # The compiler can consume a header outside the package via an absolute
        # include. Its bytes must be checked even though source itself is unchanged.
        header=self.root/'external.h';header.write_text('#define INCREMENT 2\n')
        source=self.package/'source/component.c'
        source.write_text('#include "'+str(header)+'"\n'+source.read_text().replace('a.metadata += b.metadata','(void)b; a.metadata += INCREMENT'))
        code,text,baseline=self.check(self.package,'baseline')
        self.assertEqual(code,0,text)
        header.write_text('#define INCREMENT 3\n')
        code,text,out=self.check(self.package,'external-edited','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'mismatch')
        self.assertIn('compiler dependency: '+str(header),result['reuse']['reasons'])
