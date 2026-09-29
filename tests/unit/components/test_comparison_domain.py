"""Runtime domain gates retain excluded bugs without changing production APIs."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.components.comparison_refinement import domain_relation
from spaghetti_extractor.candidate.experimental_build import build_experimental_execution
from spaghetti_extractor.candidate.formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT
from spaghetti_extractor.util import sha256_file,write_json
from tests.unit.components import test_comparison as base

TESTKIT = {'fixtures': ('compiler',), 'commands': ('component start','component check'),
           'resources': ('tests/fixtures/jq-array-concat',)}


class ComparisonDomainTests(unittest.TestCase):
    command=base.ComponentComparisonTests.command
    check=base.ComponentComparisonTests.check

    def setUp(self):
        base.ComponentComparisonTests.setUp(self)
        driver=self.package/'adapters/driver.c'
        driver.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
            '#include "portable-component-implementation.h"\n#include "comparison-input-domain.h"\n'
            'int main(int argc,char **argv) { if(argc!=3) return 2;'
            'spx_jv_value_v2 a={0},b={0}; a.metadata=(uint32_t)atoi(argv[2]); b.metadata=2;'
            'uint32_t words[]={a.metadata}; if(!spx_comparison_admit_input(words,1)) return 77;'
            'unsigned value=!strcmp(argv[1],"original") ? a.metadata+b.metadata : lifted_array_concat(0,a,b).metadata;'
            'printf("{\\\"input_words\\\":[%u],\\\"value\\\":%u}\\n",(unsigned)words[0],value);return 0; }\n')
        p=self.package/'comparison-plan.json';plan=json.loads(p.read_text())
        plan['original']['files']['adapters/driver.c']=sha256_file(driver)
        plan['cases']=[{'id':'zero','arguments':['0']},{'id':'three','arguments':['3']}]
        plan['input_domain']={'words':['value'],'constraints':[{'argument_index':0,'minimum':0,'maximum':10}]}
        write_json(p,plan)

    def domain(self,maximum,*,minimum=0):
        p=self.package/'comparison-plan.json';plan=json.loads(p.read_text())
        plan['input_domain']['constraints'][0].update(minimum=minimum,maximum=maximum)
        write_json(p,plan)

    def test_narrowing_retains_counterexample_and_replay_under_prior_domain(self):
        source=self.package/'source/component.c'
        source.write_text(source.read_text().replace('a.metadata += b.metadata','if(a.metadata) a.metadata -= b.metadata; else a.metadata += b.metadata'))
        code,text,baseline=self.check(self.package,'wrong')
        self.assertEqual(code,2,text)
        self.domain(0)
        code,text,refined=self.check(self.package,'refined','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        result=load_comparison_result(refined)
        self.assertEqual(result['status'],'domain-limited')
        self.assertEqual([r['status'] for r in result['cases']],['match','excluded'])
        self.assertIn('retained excluded case three: previous=mismatch',text)
        measured={(r['phase'],r.get('step')) for r in result['timings']}
        self.assertIn(('evidence-validation','refinement-history'),measured)
        self.assertIn(('evidence-retention','refinement-history-copy'),measured)
        self.assertIn(('evidence-hashing',None),measured)
        report=result['refinement']
        self.assertEqual(report['domain_changes']['array-concat']['relation'],'narrowed')
        self.assertEqual(report['excluded_previous_cases'][0]['counterexample']['path'],'$.value')
        retained=refined/'refinement/previous'
        self.assertEqual(load_comparison_result(retained)['status'],'mismatch')
        code,text,replay=self.check(retained/'inputs','replay','--case','three')
        self.assertEqual(code,2,text)
        self.assertEqual(load_comparison_result(replay)['status'],'mismatch')
        # Subsequent local edits keep the excluded counterexample's provenance.
        code,text,again=self.check(self.package,'again','--reuse-comparison',str(refined))
        self.assertEqual(code,2,text)
        self.assertEqual(load_comparison_result(again)['refinement']['excluded_previous_cases'],report['excluded_previous_cases'])
        (again/'refinement/previous/cases/0001-source.stdout').write_text('{}')
        with self.assertRaisesRegex(ValueError,'stale'):
            load_comparison_result(again)

    def test_dropped_admitted_case_and_changed_projection_reject_before_compiling(self):
        code,text,baseline=self.check(self.package,'baseline');self.assertEqual(code,0,text)
        p=self.package/'comparison-plan.json';plan=json.loads(p.read_text());original_cases=plan['cases'];plan['cases']=plan['cases'][:1];write_json(p,plan)
        code,text,_=self.check(self.package,'same-domain-drop','--reuse-comparison',str(baseline))
        self.assertNotEqual(code,0,text);self.assertIn('still-admitted baseline case three',text)
        plan['cases']=original_cases;write_json(p,plan)
        self.domain(5)
        p=self.package/'comparison-plan.json';plan=json.loads(p.read_text());plan['cases']=plan['cases'][:1];write_json(p,plan)
        with patch('spaghetti_extractor.components.comparison_run.compile_comparison',side_effect=AssertionError('compiled')):
            code,text,_=self.check(self.package,'dropped','--reuse-comparison',str(baseline))
        self.assertNotEqual(code,0,text);self.assertIn('still-admitted baseline case three',text)
        plan['cases'].append({'id':'three','arguments':['3']});plan['input_domain']['words']=['another-meaning'];write_json(p,plan)
        code,text,_=self.check(self.package,'different-projection','--reuse-comparison',str(baseline))
        self.assertNotEqual(code,0,text);self.assertIn('same named input projections',text)

    def test_empty_domain_and_fixture_bypass_are_failures(self):
        self.domain(7,minimum=7)
        code,text,out=self.check(self.package,'empty')
        self.assertEqual(code,2,text);self.assertEqual(load_comparison_result(out)['status'],'empty-domain')
        driver=self.package/'adapters/driver.c'
        driver.write_text(driver.read_text().replace('if(!spx_comparison_admit_input(words,1)) return 77;',''))
        p=self.package/'comparison-plan.json';plan=json.loads(p.read_text());plan['original']['files']['adapters/driver.c']=sha256_file(driver);write_json(p,plan)
        code,text,out=self.check(self.package,'bypassed')
        self.assertEqual(code,2,text);self.assertIn('outside its declared input domain',text)
        self.assertEqual(load_comparison_result(out)['status'],'incomplete')

    def test_domain_relations_use_interval_meaning(self):
        def domain(lo,hi):return {'words':['size'],'constraints':[{'argument_index':0,'minimum':lo,'maximum':hi}]}
        self.assertEqual(domain_relation(domain(0,10),domain(2,8)),'narrowed')
        self.assertEqual(domain_relation(domain(2,8),domain(0,10)),'widened')
        self.assertEqual(domain_relation(domain(0,10),domain(5,15)),'incomparable')
        self.assertEqual(domain_relation(domain(0,0xffffffff),{'words':['size'],'constraints':[]}),'equivalent')

    def test_experimental_policy_must_accept_exact_input_domain(self):
        code,text,baseline=self.check(self.package,'baseline-policy');self.assertEqual(code,0,text)
        result=load_comparison_result(baseline)
        policy=self.root/'policy.json'
        value={'format':EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,'target_id':'fixture','configuration_id':'bounded',
            'scope':'component-network','required_components':['array-concat'],
            'accepted_assumptions':{'array-concat':result['assumptions']},
            'allowed_formal_statuses':['not-requested'],'allow_original_runtime_dependencies':False}
        write_json(policy,value)
        with self.assertRaisesRegex(ValueError,'input domain has not been accepted'):
            build_experimental_execution(comparison=baseline,component_checks={},policy_path=policy,output=self.root/'unaccepted',target_id='fixture')
        plan=json.loads((self.package/'comparison-plan.json').read_text())
        value['accepted_input_domains']={'array-concat':plan['input_domain']};write_json(policy,value)
        manifest=build_experimental_execution(comparison=baseline,component_checks={},policy_path=policy,output=self.root/'accepted',target_id='fixture')
        self.assertEqual(manifest['bindings']['components']['array-concat']['input_domain'],plan['input_domain'])
