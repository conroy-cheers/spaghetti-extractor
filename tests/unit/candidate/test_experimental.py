"""Public experimental admission runs real compiled code and rejects stale selections."""
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
from unittest.mock import patch
import unittest

from spaghetti_extractor.cli import main
from spaghetti_extractor.candidate.experimental_build import build_experimental_execution
from spaghetti_extractor.candidate.formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT
from spaghetti_extractor.candidate.experimental_manifest import load_experimental_manifest,load_experimental_policy
from spaghetti_extractor.candidate.experimental_run import run_experimental_case,run_experimental_suite
from spaghetti_extractor.candidate.functional import run_candidate_test_case
from spaghetti_extractor.components.comparison_run import comparison_result_identity
from spaghetti_extractor.native_realization.receipt_v2 import NativeRealizationV2
from spaghetti_extractor.semantic_providers.qualification_v2 import SemanticProviderQualificationV2
from spaghetti_extractor.semantic_providers.selection_v2 import ImplementationSelectionV2
from spaghetti_extractor.util import write_json,sha256_file
from tests.unit.components import test_comparison as base
from tests.unit.components import test_comparison_dependencies as dependencies

TESTKIT = {'fixtures': ('compiler',), 'commands': ('candidate policy','candidate build','candidate test','component start','component check'),
           'resources': ('tests/fixtures/jq-array-concat','tests/fixtures/jq-array-append')}


class ExperimentalCandidateTests(unittest.TestCase):
    setUp = base.ComponentComparisonTests.setUp
    command = base.ComponentComparisonTests.command
    check = base.ComponentComparisonTests.check

    def candidate(self,*arguments):
        stdout=io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stdout):
            code=main(['candidate',*arguments])
        return code,stdout.getvalue()

    def policy(self):
        plan=json.loads((self.package/'comparison-plan.json').read_text())
        assumptions={plan['component_id']:plan['assumptions'],**{d['id']:d['assumptions'] for d in plan.get('dependencies',[])}}
        value={'format':EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,'target_id':'fixture','configuration_id':'network',
            'scope':'component-network','required_components':list(assumptions),'accepted_assumptions':assumptions,
            'allowed_formal_statuses':['not-requested','unavailable','timeout','proved'],
            'allow_original_runtime_dependencies':False}
        path=self.root/'experimental-policy.json';write_json(path,value)
        return path

    def prepare(self,name='baseline'):
        code,text,comparison=self.check(self.package,name)
        self.assertEqual(code,0,text)
        output=self.root/(name+'-selection')
        code,text=self.candidate('build','fixture','--experimental-comparison',str(comparison),
            '--experimental-policy',str(self.policy()),'--output',str(output))
        self.assertEqual(code,0,text)
        return output

    def test_public_build_run_and_strong_reader_rejection(self):
        package=self.prepare()
        manifest=load_experimental_manifest(package)
        self.assertEqual(manifest['authority'],'experimental-execution-only')
        self.assertEqual(set(manifest['symbols']['definitions']),{'lifted_array_concat'})
        code,text=self.candidate('test','fixture','--experimental-package',str(package),'--output',str(self.root/'run'))
        self.assertEqual(code,0,text)
        run=json.loads((self.root/'run/experimental-run.json').read_text())
        self.assertEqual(run['status'],'pass')
        self.assertEqual(run['candidate_sha256'],manifest['bindings']['candidate_sha256'])
        # NativeRealizationV2 is the shared qualified reader at BOTH Nix suite
        # and per-case admission gates; this manifest must fail that reader.
        with self.assertRaises(ValueError):
            NativeRealizationV2.load(package/'experimental-execution.json')
        # Experimental execution cannot supply either upstream qualification
        # or implementation selection, even after a successful public run.
        for reader in (SemanticProviderQualificationV2, ImplementationSelectionV2):
            with self.subTest(reader=reader.__name__), self.assertRaises(ValueError):
                reader.parse(manifest)
        self.assertFalse((package/'native-realization.json').exists())

    def test_public_policy_preparation_builds_without_manual_hashes(self):
        code,text,comparison=self.check(self.package,'policy-comparison')
        self.assertEqual(code,0,text)
        output=self.root/'review'
        args=['policy','fixture','--comparison',str(comparison),'--configuration','reviewed-network','--output',str(output)]
        code,text=self.candidate(*args)
        self.assertEqual(code,0,text)
        self.assertIn('Build after review:',text)
        self.assertIn('No compilation, execution or qualification',text)
        policy=load_experimental_policy(output/'experimental-policy.json')
        self.assertEqual(policy['configuration_id'],'reviewed-network')
        guide=(output/'README.md').read_text()
        for assumption in policy['accepted_assumptions']['array-concat']:
            self.assertIn(assumption,guide)
        before=(output/'experimental-policy.json').read_bytes()
        self.assertEqual(self.candidate(*args)[0],2)
        self.assertEqual((output/'experimental-policy.json').read_bytes(),before)
        code,text=self.candidate('build','fixture','--experimental-comparison',str(comparison),
            '--experimental-policy',str(output/'experimental-policy.json'),'--output',str(self.root/'policy-built'))
        self.assertEqual(code,0,text)
        code,text=self.candidate('policy','other-target','--comparison',str(comparison),
            '--configuration','wrong','--output',str(self.root/'wrong-target'))
        self.assertEqual(code,2,text)
        self.assertFalse((self.root/'wrong-target').exists())

    def test_reopen_named_experiment_workspace_and_use_printed_check(self):
        experiment=self.prepare()
        workspace=self.root/'reopened'
        code,text=self.command('start','fixture','array-concat','--experimental-package',str(experiment),
            '--output',str(workspace))
        self.assertEqual(code,0,text)
        self.assertIn('reopened main program/network setup',text)
        self.assertTrue((workspace/'generated/workspace.md').is_file())
        self.assertEqual((workspace/'source/component.c').read_bytes(),
            (experiment/'comparison/inputs/source/component.c').read_bytes())
        command=shlex.split(next(line.removeprefix('next: ') for line in text.splitlines() if line.startswith('next: ')))
        self.assertIn('--history-baseline',command)
        self.assertIn('--history',command)
        self.assertEqual(command[:2],['spaghetti-extractor','component'])
        code,text=self.command(*command[2:])
        self.assertEqual(code,0,text)
        code,text=self.command(*command[2:])
        self.assertEqual(code,0,text)
        history=Path(command[command.index('--history')+1])
        self.assertEqual(json.loads((history/'latest/comparison-result.json').read_text())['work_counts'],
                         dict(compiler=0,execution=0,link=0,model=0,solver=0))
        for target,unit in [('wrong-target','array-concat'),('fixture','absent')]:
            rejected=self.root/unit
            code,text=self.command('start',target,unit,'--experimental-package',str(experiment),'--output',str(rejected))
            self.assertEqual(code,2,text)
            self.assertFalse(rejected.exists())

    def test_suite_and_direct_case_revalidate_actual_runtime_and_suite(self):
        package=self.prepare()
        run=self.root/'run'
        self.assertEqual(self.candidate('test','fixture','--experimental-package',str(package),'--output',str(run))[0],0)
        arguments=dict(package=package,case_id='three',output=self.root/'direct',runtime=run/'runtime',suite=run/'effective-suite.json')
        effective=json.loads(arguments['suite'].read_text())
        effective['cases'][0]['env']['LD_PRELOAD']='unexpected.so'
        write_json(arguments['suite'],effective)
        with patch('spaghetti_extractor.candidate.experimental_run.run_candidate_test_case',side_effect=AssertionError('executed')):
            with self.assertRaisesRegex(ValueError,'effective suite'):
                run_experimental_case(**arguments)
            (run/'runtime/comparison.exe').write_bytes(b'wrong binary')
            with self.assertRaisesRegex(ValueError,'runtime binary'):
                run_experimental_case(**arguments)
            binary=package/'comparison/build/comparison.exe';binary.write_bytes(b'wrong admitted binary')
            with self.assertRaisesRegex(ValueError,'stale'):
                run_experimental_case(**arguments)
            code,text=self.candidate('test','fixture','--experimental-package',str(package),'--output',str(self.root/'stale'))
            self.assertNotEqual(code,0,text)
            self.assertFalse((self.root/'stale').exists())

    def two_cases(self):
        path=self.package/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['cases'].append(dict(id='four',arguments=['4']));write_json(path,plan)
        return self.prepare()

    def test_one_full_admission_per_suite_and_fresh_admission_for_direct_case(self):
        package=self.two_cases();out=self.root/'shared'
        with patch('spaghetti_extractor.candidate.experimental_admission.load_experimental_manifest',
                wraps=load_experimental_manifest) as reader:
            result=run_experimental_suite(package=package,output=out,target_id='fixture')
            self.assertEqual(result['status'],'pass')
            self.assertEqual(reader.call_count,1)
            direct=run_experimental_case(package=package,case_id='three',output=self.root/'direct',
                runtime=out/'runtime',suite=out/'effective-suite.json')
            self.assertEqual(direct['status'],'pass')
            self.assertEqual(reader.call_count,2)
            with self.assertRaisesRegex(ValueError,'absent from the admitted suite'):
                run_experimental_case(package=package,case_id='absent',output=self.root/'absent',
                    runtime=out/'runtime',suite=out/'effective-suite.json')
        self.assertIsNone(result['timings'][0]['reuse_limitation'])

    def test_changed_package_content_is_rejected_even_after_the_last_case(self):
        package=self.two_cases()
        paths=['experimental-execution.json','experimental-policy.json','candidate-suite.json','symbols.txt',
            'comparison/inputs/source/component.c','comparison/inputs/interface.json',
            'comparison/cases/0000-source.stdout','comparison/cases/0000-source.stderr',
            'comparison/build/comparison.exe','comparison/comparison-result.json']
        for index,name in enumerate(paths):
            with self.subTest(name=name):
                target=package/name;original=target.read_bytes();info=target.stat();calls=[]
                def mutate(**arguments):
                    result=run_candidate_test_case(**arguments);calls.append(arguments['case_id'])
                    # Preserve length and timestamps: content, not mtime, must bind reuse.
                    if len(calls)==2:
                        target.write_bytes((b'X' if original[:1]!=b'X' else b'Y')+original[1:])
                        os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
                    return result
                try:
                    with patch('spaghetti_extractor.candidate.experimental_run.run_candidate_test_case',side_effect=mutate):
                        with self.assertRaisesRegex(ValueError,'input changed during this run'):
                            run_experimental_suite(package=package,output=self.root/f'mutation-{index}',target_id='fixture')
                    self.assertEqual(calls,['three','four'])
                    self.assertFalse((self.root/f'mutation-{index}/experimental-run.json').exists())
                finally:
                    target.write_bytes(original)

    def test_added_removed_and_symlinked_inputs_stop_before_the_next_case(self):
        package=self.two_cases()
        target=package/'comparison/inputs/source/component.c';original=target.read_bytes()
        added=package/'comparison/inputs/source/extra.h'
        for index,kind in enumerate(['added','removed','symlink']):
            with self.subTest(kind=kind):
                calls=[]
                def mutate(**arguments):
                    result=run_candidate_test_case(**arguments);calls.append(arguments['case_id'])
                    if kind=='added':added.write_text('/* new input */\n')
                    else:
                        target.unlink()
                        if kind=='symlink':target.symlink_to(package/'symbols.txt')
                    return result
                try:
                    with patch('spaghetti_extractor.candidate.experimental_run.run_candidate_test_case',side_effect=mutate):
                        with self.assertRaisesRegex(ValueError,'input changed|symbolic link'):
                            run_experimental_suite(package=package,output=self.root/f'tree-{index}',target_id='fixture')
                    self.assertEqual(calls,['three'])
                finally:
                    added.unlink(missing_ok=True);target.unlink(missing_ok=True);target.write_bytes(original)

    def test_runtime_and_effective_suite_changes_cannot_escape_at_final_case(self):
        package=self.prepare()
        for index,kind in enumerate(['binary','extra-file','suite']):
            with self.subTest(kind=kind):
                def mutate(**arguments):
                    result=run_candidate_test_case(**arguments)
                    if kind=='binary':arguments['candidate_binary'].write_bytes(b'changed executable')
                    elif kind=='extra-file':(arguments['candidate_binary'].parent/'unexpected').write_text('changed runtime')
                    else:
                        suite=json.loads(arguments['suite'].read_text());suite['cases'][0]['env']['LD_PRELOAD']='not-executed.so'
                        write_json(arguments['suite'],suite)
                    return result
                with patch('spaghetti_extractor.candidate.experimental_run.run_candidate_test_case',side_effect=mutate):
                    with self.assertRaisesRegex(ValueError,'runtime binary|effective suite'):
                        run_experimental_suite(package=package,output=self.root/f'runtime-{index}',target_id='fixture')

    def test_external_compiler_content_and_include_lookup_changes_invalidate_admission(self):
        header=self.root/'external.h';header.write_text('#define EXTERNAL 0\n')
        driver=self.package/'adapters/driver.c'
        driver.write_text('#include "'+str(header)+'"\n'+driver.read_text())
        plan=json.loads((self.package/'comparison-plan.json').read_text())
        plan['original']['files']['adapters/driver.c']=sha256_file(driver);write_json(self.package/'comparison-plan.json',plan)
        package=self.two_cases();original=header.read_bytes();probe=header.with_suffix('.h.gch')
        other=self.root/'other.h';other.write_bytes(original)
        for index,kind in enumerate(['content','lookup','symlink']):
            with self.subTest(kind=kind):
                calls=[]
                def mutate(**arguments):
                    result=run_candidate_test_case(**arguments);calls.append(arguments['case_id'])
                    if kind=='content':header.write_text('#define EXTERNAL 1\n')
                    elif kind=='lookup':probe.write_bytes(b'new include lookup')
                    else:header.unlink();header.symlink_to(other)
                    return result
                try:
                    with patch('spaghetti_extractor.candidate.experimental_run.run_candidate_test_case',side_effect=mutate):
                        with self.assertRaisesRegex(ValueError,'external input changed'):
                            run_experimental_suite(package=package,output=self.root/f'external-{index}',target_id='fixture')
                    self.assertEqual(calls,['three'])
                finally:
                    probe.unlink(missing_ok=True);header.unlink(missing_ok=True);header.write_bytes(original)

    def test_changes_during_full_admission_reject_before_execution(self):
        package=self.prepare()
        def mutate(root,*args,**kwargs):
            result=load_experimental_manifest(root,*args,**kwargs)
            (root/'symbols.txt').write_text('changed while admitting')
            return result
        with (patch('spaghetti_extractor.candidate.experimental_admission.load_experimental_manifest',side_effect=mutate),
              patch('spaghetti_extractor.candidate.experimental_run.run_candidate_test_case',side_effect=AssertionError('executed'))):
            with self.assertRaisesRegex(ValueError,'input changed during this run'):
                run_experimental_suite(package=package,output=self.root/'admission-race',target_id='fixture')

    def test_unknown_optional_build_inventory_uses_full_admission_without_blocking_execution(self):
        code,text,comparison=self.check(self.package,'future-inventory');self.assertEqual(code,0,text)
        inventory=comparison/'build/compilation.json'
        payload=json.loads(inventory.read_text());payload['version']=2;write_json(inventory,payload)
        receipt_path=comparison/'comparison-result.json';receipt=json.loads(receipt_path.read_text())
        receipt['artifact_sha256s']['build/compilation.json']=sha256_file(inventory)
        receipt['receipt_sha256']=comparison_result_identity({k:v for k,v in receipt.items() if k!='receipt_sha256'})
        write_json(receipt_path,receipt)
        package=self.root/'future-selection'
        build_experimental_execution(comparison=comparison,component_checks={},policy_path=self.policy(),output=package,target_id='fixture')
        with patch('spaghetti_extractor.candidate.experimental_admission.load_experimental_manifest',wraps=load_experimental_manifest) as reader:
            result=run_experimental_suite(package=package,output=self.root/'future-run',target_id='fixture')
        self.assertEqual(result['status'],'pass')
        self.assertGreater(reader.call_count,1)
        self.assertIn('repeat full admission',result['timings'][0]['reuse_limitation'])

    def test_mismatch_partial_checks_and_unaccepted_assumptions_cannot_admit(self):
        policy=self.policy()
        code,text,partial=self.check(self.package,'partial','--case','three')
        self.assertEqual(code,0,text)
        with self.assertRaisesRegex(ValueError,'full matching'):
            build_experimental_execution(comparison=partial,component_checks={},policy_path=policy,output=self.root/'partial-selected',target_id='fixture')
        source=self.package/'source/component.c';good=source.read_text();source.write_text(good.replace('+=','-='))
        code,text,wrong=self.check(self.package,'wrong')
        self.assertEqual(code,2,text)
        with self.assertRaisesRegex(ValueError,'full matching'):
            build_experimental_execution(comparison=wrong,component_checks={},policy_path=policy,output=self.root/'wrong-selected',target_id='fixture')
        source.write_text(good)
        code,text,matching=self.check(self.package,'matching')
        self.assertEqual(code,0,text)
        value=json.loads(policy.read_text());value['accepted_assumptions']['array-concat']=['different domain'];write_json(policy,value)
        with self.assertRaisesRegex(ValueError,'assumptions'):
            build_experimental_execution(comparison=matching,component_checks={},policy_path=policy,output=self.root/'not-accepted',target_id='fixture')

    def test_selected_supplier_requires_matching_local_implementation_and_headers(self):
        supplier=dependencies.ComparisonDependencyTests.supplier(self)
        driver=supplier/'adapters/driver.c'
        driver.write_text('#include <stdio.h>\n#include <string.h>\n#include "portable-component-implementation.h"\n'
            'int main(int argc,char **argv) { if(argc!=2) return 2; spx_jv_value_v2 a={0},b={0}; b.metadata=2;'
            'unsigned value=!strcmp(argv[1],"original") ? 2 : lifted_array_append(0,a,b).metadata;'
            'printf("{\\\"value\\\":%u}\\n",value); return 0; }\n')
        plan_path=supplier/'comparison-plan.json';plan=json.loads(plan_path.read_text())
        plan['original']['files']['adapters/driver.c']=sha256_file(driver);write_json(plan_path,plan)
        dependencies.ComparisonDependencyTests.select(self,supplier)
        local=self.root/'supplier-check'
        code,text=self.command('check','fixture','array-append','--comparison-package',str(supplier),'--output',str(local))
        self.assertEqual(code,0,text)
        code,text,graph=self.check(self.package,'graph')
        self.assertEqual(code,0,text)
        policy=self.policy()
        with self.assertRaisesRegex(ValueError,'required component checks'):
            build_experimental_execution(comparison=graph,component_checks={},policy_path=policy,output=self.root/'missing',target_id='fixture')
        selected=self.root/'selected'
        manifest=build_experimental_execution(comparison=graph,component_checks={'array-append':local},policy_path=policy,output=selected,target_id='fixture')
        self.assertEqual(len(manifest['symbols']['definitions']),2)
        workspace=self.root/'supplier-reopened'
        code,text=self.command('start','fixture','array-append','--experimental-package',str(selected),'--output',str(workspace))
        self.assertEqual(code,0,text)
        self.assertEqual((workspace/'source/append.c').read_bytes(),(supplier/'source/append.c').read_bytes())
        self.assertIn('--dependency-source array-append=',text)
        # A caller edit needs its new network comparison, without resupplying
        # the unchanged supplier receipt or reauthoring the accepted policy.
        caller=self.package/'source/component.c'
        caller.write_text(caller.read_text().replace('a.metadata += fixture_supplier(b.metadata)',
            'a.metadata = fixture_supplier(b.metadata) + a.metadata'))
        code,text,caller_changed=self.check(self.package,'caller-edited','--reuse-comparison',str(graph))
        self.assertEqual(code,0,text)
        updated=self.root/'updated-selection'
        code,text=self.candidate('build','fixture','--experimental-comparison',str(caller_changed),
            '--reuse-experimental',str(selected),'--output',str(updated))
        self.assertEqual(code,0,text)
        self.assertIn('reused component receipts: array-append',text)
        self.assertEqual(load_experimental_manifest(updated)['component_checks']['array-append']['receipt_sha256'],
            manifest['component_checks']['array-append']['receipt_sha256'])
        costs=json.loads((updated/'experimental-build-costs.json').read_text())
        self.assertTrue(costs['reused_policy'])
        self.assertEqual(costs['work_counts']['compiler'],0)
        # Identical source and signature are insufficient if supplier headers differ.
        (supplier/'source/changed.h').write_text('/* changed compilation context */\n')
        changed=self.root/'supplier-changed'
        code,text=self.command('check','fixture','array-append','--comparison-package',str(supplier),'--output',str(changed))
        self.assertEqual(code,0,text)
        with self.assertRaisesRegex(ValueError,'different selected implementation'):
            build_experimental_execution(comparison=graph,component_checks={'array-append':changed},policy_path=policy,output=self.root/'mixed',target_id='fixture')
        code,text,new_graph=self.check(self.package,'new-graph','--dependency-package','array-append='+str(supplier))
        self.assertEqual(code,0,text)
        missing=self.root/'missing-fresh-supplier'
        code,text=self.candidate('build','fixture','--experimental-comparison',str(new_graph),
            '--reuse-experimental',str(updated),'--output',str(missing))
        self.assertEqual(code,2,text)
        self.assertIn('--component-comparison array-append=CHECK',text)
        self.assertFalse(missing.exists())
        code,text=self.candidate('build','fixture','--experimental-comparison',str(new_graph),
            '--reuse-experimental',str(updated),'--component-comparison','array-append='+str(changed),
            '--output',str(self.root/'fresh-supplier-selection'))
        self.assertEqual(code,0,text)
        # Explicit practical policy can rely on the network comparison for a
        # supplier; a supplied local receipt must still match that selection.
        value=json.loads(policy.read_text());value['required_component_checks']=['array-concat']
        write_json(policy,value)
        network=build_experimental_execution(comparison=graph,component_checks={},policy_path=policy,
            output=self.root/'network-only',target_id='fixture')
        self.assertEqual(set(network['bindings']['components']),{'array-concat','array-append'})
        self.assertEqual(set(network['component_checks']),{'array-concat'})
        missing_setup=self.root/'no-local-setup'
        code,text=self.command('start','fixture','array-append','--experimental-package',str(self.root/'network-only'),
            '--output',str(missing_setup))
        self.assertEqual(code,0,text)
        self.assertIn('no retained independent comparison setup',text)
        self.assertIn('retained consumer check: array-concat',text)
        self.assertIn('component check fixture array-append',text)
        self.assertEqual(json.loads((missing_setup/'comparison-plan.json').read_text())['component_id'],'array-concat')
        self.assertEqual((missing_setup/'dependencies/array-append/source/append.c').read_bytes(),
            (self.root/'network-only/comparison/inputs/dependencies/array-append/source/append.c').read_bytes())
        with self.assertRaisesRegex(ValueError,'different selected implementation'):
            build_experimental_execution(comparison=graph,component_checks={'array-append':changed},policy_path=policy,
                output=self.root/'network-with-stale-local',target_id='fixture')
        # Policy drafting names missing checks rather than silently accepting
        # network evidence; supplied incompatible checks always reject.
        draft_args=['policy','fixture','--comparison',str(graph),'--configuration','graph']
        code,text=self.candidate(*draft_args,'--output',str(self.root/'required-policy'))
        self.assertEqual(code,0,text)
        self.assertIn('Required component checks still missing: array-append',text)
        code,text=self.candidate(*draft_args,'--network-only','array-append','--output',str(self.root/'network-policy'))
        self.assertEqual(code,0,text)
        self.assertEqual(load_experimental_policy(self.root/'network-policy/experimental-policy.json')['required_component_checks'],['array-concat'])
        code,text=self.candidate(*draft_args,'--network-only','array-append',
            '--component-comparison','array-append='+str(changed),'--output',str(self.root/'incompatible-policy'))
        self.assertEqual(code,2,text)
        self.assertIn('different selected implementation',text)
        self.assertFalse((self.root/'incompatible-policy').exists())

    def test_policy_and_public_option_conflicts_fail_closed(self):
        policy=self.policy();value=json.loads(policy.read_text())
        value['allowed_formal_statuses']=['disproved'];write_json(policy,value)
        with self.assertRaisesRegex(ValueError,'formal status'):
            load_experimental_policy(policy)
        for args in [
            ['build','fixture','--experimental-policy',str(policy)],
            ['build','fixture','--configuration','default','--experimental-comparison',str(self.package),'--experimental-policy',str(policy),'--output',str(self.root/'out')],
            ['test','fixture','--suite','default','--experimental-package',str(self.package),'--output',str(self.root/'out')],
        ]:
            code,text=self.candidate(*args)
            self.assertNotEqual(code,0,text)


if __name__ == '__main__':
    unittest.main()
