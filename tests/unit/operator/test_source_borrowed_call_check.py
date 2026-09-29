"""The already exercised ID-31 caller consumes a checked borrowed-view premise.

Fixture summaries are test premises. Retained public workflow evidence separately
runs the actual supplier certificate reader; these tests never confer activation.
"""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_supplier_facts import checked_borrowed_supplier_facts
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check, validate_component_source_call_feedback
from spaghetti_extractor.operator.source_check import write_component_source_check

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-resource-callers/finite-caller'
TESTKIT={'fixtures':('compiler','cbmc'),'commands':('component check',),
         'resources':('tests/fixtures/metapad-resource-callers',)}


def supplier_inputs(contract, *, clobber=None, writes=None):
    transition=json.loads((FIXTURE.parent/'transition.json').read_text())
    if clobber:transition['domain']['machine_domain']['clobbers']=sorted({*transition['domain']['machine_domain']['clobbers'],clobber})
    if writes is not None:transition['domain']['machine_domain']['private_writes']=writes
    transition['domain_sha256']=canonical_sha256_v3(transition['domain'])
    facts,requirements=checked_borrowed_supplier_facts(transition,
        original=json.loads((FIXTURE/'supplier-exact.json').read_text()),required_frame=contract['required_frame'])
    return facts,{'contract_sha256':transition['domain_sha256'],'consumer_requirements':requirements,
        'evidence':{k:transition[k] for k in ('supplier_receipt_sha256','source_certificate_sha256')}}


class SourceBorrowedCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.contract=json.loads((FIXTURE/'caller-contract.json').read_text())
        cls.prepare('source',(FIXTURE/'prepare.c').read_text())
        result=cls.invoke('baseline')
        if result['status']!='complete':raise AssertionError(cls.result('baseline')['checks'])

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    @classmethod
    def prepare(cls,name,source):
        d=cls.root/name;d.mkdir();(d/'ordinary.c').write_text(source)
        build_component_source_package(lift_unit_id='resource-notice-prefix',
            files={'components/resource-notice-prefix.c':d/'ordinary.c'},shared_inputs={},
            operation_symbols={'prepare':'prepare_notice'},out_dir=d/'source')
        result=write_component_source_check(target_id='metapad',component_id='resource-notice-prefix',
            interface_package=FIXTURE,source_package=d/'source',out=d/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if result['status']!='complete':raise AssertionError(result)

    @classmethod
    def invoke(cls,name,*,source='source',contract=None,supplier=None,previous=None):
        d=cls.root/name;d.mkdir();contract=deepcopy(cls.contract if contract is None else contract)
        with patch.object(checker,'checked_caller_supplier',return_value=supplier or supplier_inputs(contract)):
            return write_component_source_call_check(target_id='metapad',component_id='resource-notice-prefix',
                preparation=cls.root/source/'preparation',exact=FIXTURE/'exact',supplier=cls.root/'supplier',
                contract=contract,source_package=cls.root/source/'source',interface_package=FIXTURE,
                out=d/'feedback',workspace=d/'work',goto_cc=Path(shutil.which('goto-cc')),
                cbmc=Path(shutil.which('cbmc')),smt_solver=None,previous=previous,timeout_seconds=60)

    @classmethod
    def result(cls,name):return json.loads((cls.root/name/'feedback/caller-comparison/result.json').read_text())

    def assert_failure(self,name,diagnostic):
        r=self.result(name);self.assertEqual(r['status'],'violated',r['checks'])
        query=json.loads((self.root/name/'feedback/caller-comparison/proof/query.stdout').read_text())
        self.assertIn(diagnostic,{r.get('description') for b in query for r in b.get('result',[]) if r.get('status')=='FAILURE'})

    def test_real_caller_body_and_view_exit_are_checked_without_supplier_body(self):
        r=self.result('baseline');self.assertEqual(r['query']['status'],'satisfied')
        self.assertNotIn('behavioral-fn-00001284.c',r['proof_files'])
        self.assertFalse(r['activation_authorized'])
        self.assertEqual(r['runtime_compatibility'],'unverified')
        self.assertEqual(r['admission']['status'],'satisfied')
        self.assertEqual(r['proof_key']['bindings']['boundary']['result_view'],'buffer')

    def test_wrong_argument_and_returned_descriptor_reject_then_repair_reuses(self):
        original=(FIXTURE/'prepare.c').read_text()
        for name,source,diagnostic in [
            ('id',original.replace('31U','32U'),'spx-paired-call-arguments'),
            ('descriptor',original.replace(' return context->services->resource_text(context->services->context,31U);',
                ' spx_view_v5 result=context->services->resource_text(context->services->context,31U);\n result.base.generation++;return result;'),
                'spx-source-operation-result-view')]:
            self.prepare('source-'+name,source)
            self.invoke(name,source='source-'+name)
            self.assert_failure(name,diagnostic)
        with patch('subprocess.run',side_effect=AssertionError('repair must reuse')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('repair regenerated model')):
            self.assertEqual(self.invoke('repair',previous=self.root/'baseline/feedback')['status'],'complete')
        self.assertEqual(self.result('repair')['proof_files'],self.result('baseline')['proof_files'])

    def test_missing_private_read_and_wrong_continuation_observation_reject(self):
        c=deepcopy(self.contract)
        next(r for r in c['native_memory'] if r['id']=='id')['read']=False
        self.invoke('private-read',contract=c);self.assert_failure('private-read','spx-caller-readable-frame')
        c=deepcopy(self.contract)
        next(r for r in c['boundary']['outcomes'][0]['assertions'] if r['id']=='caption-transport')['expression']['args'][1]['attributes']['value']+=1
        self.invoke('caption',contract=c);self.assert_failure('caption','caption-transport')

    def test_child_writes_must_not_destroy_live_continuation_slots(self):
        supplier=supplier_inputs(self.contract,writes=[{'offset':-28,'bytes':36}])
        self.invoke('child-overlap',supplier=supplier)
        self.assert_failure('child-overlap','supplier-call-live-slot-id-1')

    def test_neighbor_evidence_rebinds_without_consumer_work(self):
        facts,summary=supplier_inputs(self.contract);summary['evidence']['supplier_receipt_sha256']='1'*64
        with patch('subprocess.run',side_effect=AssertionError('neighbor must reuse')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('neighbor regenerated model')):
            self.assertEqual(self.invoke('neighbor',supplier=(facts,summary),previous=self.root/'baseline/feedback')['status'],'complete')
            with patch.object(checker,'checked_caller_supplier',return_value=(facts,summary)):
                feedback=json.loads((self.root/'neighbor/feedback/compiler-checks.json').read_text())
                validate_component_source_call_feedback(self.root/'neighbor/feedback',feedback['local_contract'],'complete')
        r=self.result('neighbor');base=self.result('baseline')
        self.assertEqual(r['proof_key'],base['proof_key']);self.assertEqual(r['proof_files'],base['proof_files'])
        self.assertNotEqual(r['supplier_transition'],base['supplier_transition'])
        self.assertEqual(r['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})

    def test_selected_frame_withdrawal_is_visible_before_model_generation(self):
        with patch.object(checker,'render_caller_boundary',side_effect=AssertionError('missing fact generated model')):
            result=self.invoke('withdraw',supplier=supplier_inputs(self.contract,clobber='edi'))
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(self.result('withdraw')['dependency_contract']['missing_guarantees'],['state.edi==initial.edi'])
