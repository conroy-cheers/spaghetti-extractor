"""Public void/runtime-only callers preserve actual returned bytes and lifetime."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator import source_operation_call_check as checker
from tests.unit.components.returned_caller_fixture import prepare

TESTKIT={'fixtures':('compiler','cbmc')}


class ReturnedCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.root=Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.contracts={}
        for variant in ('valid','stale','wrong','captured'):
            root=cls.root/variant;cls.contracts[variant]=prepare(root,variant=variant)
            result=write_component_source_check(target_id='fixture',component_id='returned-consumer',
                interface_package=root/'interface',source_package=root/'source',out=root/'preparation',
                host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
            if result['status']!='complete':raise AssertionError(result)
        status,result=cls.invoke('valid','baseline')
        if status['status']!='complete':raise AssertionError(result['checks'])

    @classmethod
    def invoke(cls,variant,name,*,contract=None,previous=None):
        root=cls.root/variant;out=root/name
        status=write_component_source_call_check(target_id='fixture',component_id='returned-consumer',
            preparation=root/'preparation',exact=root/'exact',supplier={},
            contract=cls.contracts[variant] if contract is None else contract,
            source_package=root/'source',interface_package=root/'interface',out=out/'feedback',workspace=out/'work',
            goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),smt_solver=None,
            unwind=8,timeout_seconds=60,previous=previous)
        return status,json.loads((out/'feedback/caller-comparison/result.json').read_text())

    def test_current_contents_void_return_and_explicit_conditional_authority(self):
        root=self.root/'valid/baseline/feedback/caller-comparison'
        result=json.loads((root/'result.json').read_text())
        with patch('subprocess.run',side_effect=AssertionError('receipt reader ran tools')):
            checker.validate_operation_call_result(result,root)
        self.assertFalse(result['activation_authorized']);self.assertFalse(result['whole_component_complete'])
        bindings=result['proof_key']['bindings']
        self.assertEqual(bindings['runtime_contract']['suppliers'],{})
        self.assertEqual(bindings['runtime_contract']['services']['cell']['status'],'unverified')
        self.assertEqual(bindings['scope']['unit_rvas'],[8192,8193,8194,8195])

    def test_captured_target_survives_returned_memory_alias_and_sampling_changes_invalidate(self):
        status,result=self.invoke('captured','baseline')
        self.assertEqual(status['status'],'complete',result['checks'])
        premise=result['proof_key']['bindings']['runtime_contract']['services']['cell']
        self.assertEqual(premise['target_sampling'],'operation_entry')
        self.assertNotIn('separate_from',premise['returned_view'])
        with (patch('subprocess.run',side_effect=AssertionError('reuse ran tools')),
              patch.object(checker,'render_caller_boundary',side_effect=AssertionError('reuse rendered model'))):
            status,result=self.invoke('captured','reuse',previous=self.root/'captured/baseline/feedback')
        self.assertEqual(status['status'],'complete')
        self.assertEqual(result['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        contract=deepcopy(self.contracts['captured'])
        contract['runtime_contracts']['cell']['target_sampling']='service_call'
        status,result=self.invoke('captured','reread',contract=contract,previous=self.root/'captured/baseline/feedback')
        self.assertEqual(status['status'],'violated',result['checks'])
        self.assertEqual(result['reuse']['status'],'requires-recheck')
        self.assertIn('contract',result['reuse']['changed_bindings'])
        self.assertIn(result['query']['detail'],{'spx-native-captured-target','spx-paired-code-target',
                                              'spx-source-captured-target-nonnull'})

    def test_invalid_or_forged_sampling_is_refused_before_proof(self):
        for variant in ('unknown','native','boundary','direct'):
            contract=deepcopy(self.contracts['captured'])
            if variant=='unknown':contract['runtime_contracts']['cell']['target_sampling']='first_call'
            elif variant=='native':contract['native_calls'][0]['target_sampling']='operation_entry'
            elif variant=='boundary':contract['boundary']['services'][0]['target_sampling']='operation_entry'
            else:contract['runtime_contracts']['observe']['target_sampling']='operation_entry'
            with patch('subprocess.run',side_effect=AssertionError('invalid sampling ran tools')):
                status,result=self.invoke('captured','invalid-'+variant,contract=contract)
            self.assertEqual(status['status'],'incomplete')
            self.assertEqual(result['reuse']['solver_runs'],0)

    def test_unchanged_reuses_without_model_compiler_or_solver(self):
        with (patch('subprocess.run',side_effect=AssertionError('reuse ran tools')),
              patch.object(checker,'render_caller_boundary',side_effect=AssertionError('reuse rendered model'))):
            status,result=self.invoke('valid','reuse',previous=self.root/'valid/baseline/feedback')
        self.assertEqual(status['status'],'complete')
        self.assertEqual(result['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})

    def test_wrong_write_and_expired_return_are_disproved(self):
        for variant in ('wrong','stale'):
            status,result=self.invoke(variant,'negative')
            self.assertEqual(status['status'],'violated',result['checks'])
            self.assertEqual(result['query']['code'],'cbmc_counterexample')
            if variant=='stale':self.assertEqual(result['query']['detail'],'spx-returned-lifetime')

    def test_missing_lifetime_forged_rule_and_scope_hole_are_refused(self):
        for variant in ('missing','lifetime','forged','scope','untyped-separation'):
            contract=deepcopy(self.contracts['valid'])
            rule=contract['runtime_contracts']['cell']['returned_view']
            if variant=='missing':del contract['runtime_contracts']['cell']['returned_view']
            elif variant=='lifetime':rule['lifetime']='forever'
            elif variant=='forged':contract['boundary']['services'][0]['returned_view']=rule
            elif variant=='untyped-separation':rule['separate_from']=[{'address':4096,'extent':4}]
            else:contract['unit_rvas'].remove(8193)
            with patch('subprocess.run',side_effect=AssertionError('invalid contract ran tools')):
                status,result=self.invoke('valid','bad-'+variant,contract=contract)
            self.assertEqual(status['status'],'incomplete')
            self.assertEqual(result['reuse']['solver_runs'],0)

    def test_impossible_result_range_cannot_prove_vacuously(self):
        contract=deepcopy(self.contracts['valid'])
        from spaghetti_extractor.components.bisimulation_call_relations import constant
        contract['boundary']['call_private_low']=constant(0,64).to_payload()
        contract['boundary']['call_private_high']=constant(2**32,64).to_payload()
        status,result=self.invoke('valid','empty-result-domain',contract=contract)
        self.assertEqual(status['status'],'violated',result['checks'])
        self.assertEqual(result['query']['detail'],'spx-returned-domain-inhabited')

    def test_separation_premises_are_bound_and_have_a_nonempty_witness(self):
        from spaghetti_extractor.components.bisimulation_call_relations import constant
        contract=deepcopy(self.contracts['valid'])
        rule=contract['runtime_contracts']['cell']['returned_view']
        rule['separate_from']=[{'address':constant(0x300).to_payload(),'extent':constant(4,64).to_payload()}]
        status,result=self.invoke('valid','separated',contract=contract,previous=self.root/'valid/baseline/feedback')
        self.assertEqual(status['status'],'complete',result['checks'])
        self.assertEqual(result['reuse']['status'],'requires-recheck')
        self.assertIn('contract',result['reuse']['changed_bindings'])
        rule['separate_from']=[{'address':constant(1).to_payload(),'extent':constant(2**32-1,64).to_payload()}]
        status,result=self.invoke('valid','exclusion-covers-domain',contract=contract)
        self.assertEqual(status['status'],'violated',result['checks'])
        self.assertEqual(result['query']['detail'],'spx-returned-domain-inhabited')
