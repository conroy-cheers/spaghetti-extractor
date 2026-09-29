"""Actual optional proof outcomes preserve practical execution and scoped reuse."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.candidate.experimental_build import build_experimental_execution
from spaghetti_extractor.candidate.experimental_run import run_experimental_suite
from spaghetti_extractor.candidate.formats import EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT
from spaghetti_extractor.components.comparison_package import prepare_comparison_package
from spaghetti_extractor.components.comparison_run import run_comparison,load_comparison_result,comparison_result_identity
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.util import write_json
from tests.unit.components import test_comparison as base
from tests.unit.components.test_bisimulation_readonly_model import fixed_readonly_bundle,COMPARISON

TESTKIT = {'fixtures': ('compiler','cbmc'), 'commands': ('component check','candidate build','candidate test'),
           'resources': ('tests/fixtures/jq-array-concat','targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json')}


def memory_package(root: Path, body: str = COMPARISON) -> Path:
    interface=root/'interface';interface.mkdir()
    write_json(interface/'component-interface-intent-v1.json',fixed_readonly_bundle().intent.to_payload())
    source=root/'regions.c';source.write_text('#include "portable-component-implementation.h"\n'
        'uint8_t regions_equal(spx_memory_regions_equal_context_v5 *context,const spx_view_v5 *left, '
        'const spx_view_v5 *right,uint32_t count) {\n'+body+'\n}\n')
    package=root/'source'
    build_component_source_package(lift_unit_id='memory-regions-equal',files={'regions.c':source},shared_inputs={},
        operation_symbols={'compare':'regions_equal'},out_dir=package)
    driver=root/'driver.c';driver.write_text('#include <stdio.h>\n#include <string.h>\n'
        '#include "portable-component-implementation.h"\n'
        'spx_ref_status spx_view_read_u8(const spx_view_v5 *v,uint64_t i,uint8_t *out) {'
        'if(i>=v->extent) return SPX_REF_FAULT; *out=((const uint8_t *)v->context)[i];return SPX_REF_OK; }\n'
        'int main(int argc,char **argv) { if(argc!=3) return 2; uint8_t a[]={1,2,3,4},b[]={1,2,3,4};'
        'if(!strcmp(argv[2],"different")) b[3]=5; spx_view_v5 left={0},right={0};'
        'left.context=a;right.context=b;left.extent=4;right.extent=4;'
        'unsigned result=!strcmp(argv[1],"original") ? !memcmp(a,b,4) : regions_equal(0,&left,&right,4);'
        'printf("{\\\"equal\\\":%u}\\n",result);return 0; }\n')
    destination=root/'package'
    prepare_comparison_package(interface_package=interface,source_package=package,target_id='fixture',component_id='memory-regions-equal',
        adapter_files={'driver.c':driver},include_files={},link_files={},runtime_files={},original_files=['adapters/driver.c'],
        oracle_kind='fixture',cases=[{'id':'equal','arguments':['equal']},{'id':'different','arguments':['different']}],
        observation_fields=['equal'],assumptions=['finite host fixture; formal checks cover source memory contracts only'],
        scope='memory-region comparison fixture',compiler=Path(shutil.which('cc')),runner=None,server=None,output=destination)
    return destination


class PracticalContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        if not all(shutil.which(name) for name in ('cbmc','goto-cc','goto-instrument','cc')):
            self.skipTest('CBMC/compiler fixture is unavailable')

    def check(self,package,name,**kwargs):
        out=self.root/name
        run_comparison(package=package,output=out,target_id='fixture',component_id='memory-regions-equal',
            local_contracts=True,**kwargs)
        return out,load_comparison_result(out)

    def admit(self,comparison,name):
        d=load_comparison_result(comparison)
        policy=self.root/'policy.json'
        write_json(policy,{'format':EXPERIMENTAL_COMPONENT_POLICY_V1_FORMAT,'target_id':'fixture',
            'configuration_id':'memory-contracts','scope':'component-network','required_components':[d['component_id']],
            'accepted_assumptions':{d['component_id']:d['assumptions']},
            'allowed_formal_statuses':['proved','timeout','unavailable'],'allow_original_runtime_dependencies':False})
        return build_experimental_execution(comparison=comparison,component_checks={},policy_path=policy,output=self.root/name,target_id='fixture')

    def test_existing_proof_is_reused_alongside_distinct_concrete_evidence(self):
        package=memory_package(self.root)
        out,result=self.check(package,'first')
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['formal_check']['status'],'proved',result['formal_check']['result'])
        with (patch('spaghetti_extractor.components.comparison_run.compile_comparison',side_effect=AssertionError('compiled native')),
              patch('spaghetti_extractor.components.bisimulation_readonly_contracts.run_cbmc_properties',side_effect=AssertionError('queried solver'))):
            reused,current=self.check(package,'reused',reuse_previous=out)
        self.assertEqual(current['reuse']['status'],'reused')
        self.assertEqual(current['formal_check']['status'],'proved')
        self.assertEqual(current['formal_check']['reused_queries'],2)
        self.assertEqual(current['formal_check']['work_counts'],{'compiler':0,'model':0,'solver':0})
        self.assertTrue(all(n==0 for n in current['work_counts'].values()))
        self.admit(reused,'selected')
        self.assertEqual(run_experimental_suite(package=self.root/'selected',output=self.root/'run',target_id='fixture')['status'],'pass')
        proof=reused/'formal/local-contract-result.json';proof.write_text('{}')
        with self.assertRaisesRegex(ValueError,'artifacts are stale'):
            load_comparison_result(reused)

    def test_real_cbmc_timeout_preserves_passing_comparison_and_execution(self):
        package=memory_package(self.root)
        out,result=self.check(package,'timeout',query_timeout=0.0001)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['formal_check']['status'],'timeout',result['formal_check']['result'])
        self.assertGreater(result['formal_check']['work_counts']['solver'],0)
        self.assertTrue(list((out/'formal').glob('query-evidence/*/failed-attempts/*/attempt.json')))
        self.admit(out,'selected')
        self.assertEqual(run_experimental_suite(package=self.root/'selected',output=self.root/'run',target_id='fixture')['status'],'pass')

    def test_immutable_storage_formal_ineligibility_preserves_comparison(self):
        package=memory_package(self.root, 'static const uint8_t yes[] = {1};\n'+COMPARISON.replace('return 1;', 'return yes[0];'))
        out,result=self.check(package,'immutable')
        self.assertEqual(result['status'],'match',result.get('cases'))
        self.assertEqual(result['source_profile']['status'],'satisfied')
        self.assertEqual(result['source_profile']['proof_profile']['status'],'incomplete')
        self.assertEqual(result['formal_check']['status'],'unavailable')
        self.assertEqual(result['formal_check']['work_counts'],{'compiler':0,'model':0,'solver':0})
        self.assertEqual(load_comparison_result(out)['status'],'match')

    def test_known_formal_counterexample_vetoes_matching_sampled_cases(self):
        # count=4 passes both concrete cases; a symbolic count=0 reaches a
        # division-by-zero property. Sampled comparison is not a proof override.
        package=memory_package(self.root,'if(count==0) return 1U/count;\n'+COMPARISON)
        out,result=self.check(package,'wrong')
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['formal_check']['status'],'disproved',result['formal_check']['result'])
        with self.assertRaisesRegex(ValueError,'formal result'):
            self.admit(out,'selected')
        # Reusing comparisons carries the selected optional check forward even
        # when its flag is omitted, so reuse cannot erase a known failure.
        rerun=run_comparison(package=package,output=self.root/'still-wrong',target_id='fixture',
            component_id='memory-regions-equal',reuse_previous=out)
        self.assertEqual(rerun['formal_check']['status'],'disproved')
        path=out/'comparison-result.json';payload=json.loads(path.read_text())
        payload['formal_check']['status']='timeout'
        payload['receipt_sha256']=comparison_result_identity({k:v for k,v in payload.items() if k!='receipt_sha256'})
        write_json(path,payload)
        with self.assertRaisesRegex(ValueError,'outcome differs'):
            load_comparison_result(out)

    def test_unwinding_exhaustion_is_not_labeled_behavioral_disproof(self):
        package=memory_package(self.root,'if(count==0) { for(uint32_t i=0;i<32;i++) { if(i==31) return 1; } }\n'+COMPARISON)
        out,result=self.check(package,'unwind')
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['formal_check']['status'],'incomplete',result['formal_check']['result'])
        with self.assertRaisesRegex(ValueError,'formal result'):
            self.admit(out,'selected')


class UnavailableContractTests(unittest.TestCase):
    setUp=base.ComponentComparisonTests.setUp
    command=base.ComponentComparisonTests.command
    check=base.ComponentComparisonTests.check

    def test_public_supported_c_with_unavailable_stateful_rule(self):
        if not shutil.which('cbmc'):
            self.skipTest('CBMC fixture is unavailable')
        code,text,out=self.check(self.package,'optional','--local-contracts')
        self.assertEqual(code,0,text)
        self.assertIn('formal check: unavailable',text)
        result=load_comparison_result(out)
        self.assertEqual(result['source_profile']['status'],'satisfied')
        self.assertEqual(result['formal_check']['work_counts'],{'compiler':0,'model':0,'solver':0})
