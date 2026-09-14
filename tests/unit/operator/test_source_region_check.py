"""Actual local loop correctness, current-source reuse and rejected false claims."""
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.components import bisimulation_compaction_check as engine
from spaghetti_extractor.operator.source_region_check import (
    write_component_source_region_check, validate_component_source_region_feedback,
)
from .test_source_region_graphs import BOUNDARY, FIXTURE
from .test_source_call_regions import check as prepare

EXACT=Path(__file__).parents[2]/'fixtures/metapad-cleanup-iteration'
TESTKIT={'fixtures':('compiler','cbmc','z3'),'commands':('component check',),
         'resources':('tests/fixtures/metapad-cleanup-iteration','tests/fixtures/metapad-authored-call')}


class SourceRegionCheckTests(unittest.TestCase):
    runtime_revision = 2
    external_solver = True

    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(); cls.root=Path(cls.temporary.name)
        cls.contract=json.loads((EXACT/'local-contract.json').read_text())
        if cls.runtime_revision != 2:
            cls.contract['runtime_revision'] = cls.runtime_revision
        source=(FIXTURE/'cleanup.c').read_text()
        store='      if (spx_view_write_u8(&scratch, output, a)) return UINT32_MAX;\n      ++output;'
        assert source.count(store)==1
        texts={'source':source,'wrong':source.replace(store,store.replace('output, a)','output, a+1U)')),
               'unsupported-return':source.replace(store,store.replace('return UINT32_MAX','return 17U')),
               'outside-edit':source.replace('context, 31U);','context, 32U);')}
        for name,text in texts.items():
            root=cls.root/name; root.mkdir()
            status,feedback,_=prepare(root,text,boundary=BOUNDARY,graph=True)
            if status['status']!='complete':raise AssertionError(feedback)
        status=cls.invoke('baseline')
        if status['status']!='complete':raise AssertionError(cls.result('baseline')['checks'])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def invoke(cls,name,*,source='source',previous=None,contract=None):
        root=cls.root/name; root.mkdir()
        return write_component_source_region_check(target_id='metapad',component_id='text-cleanup',
            preparation=cls.root/source/'feedback',exact=EXACT,contract=cls.contract if contract is None else contract,
            out=root/'feedback',workspace=root/'work',goto_cc=Path(shutil.which('goto-cc')),
            goto_instrument=Path(shutil.which('goto-instrument')),cbmc=Path(shutil.which('cbmc')),
            smt_solver=Path(shutil.which('z3')) if cls.external_solver else None,
            previous=previous,timeout_seconds=60)

    @classmethod
    def result(cls,name):
        return json.loads((cls.root/name/'feedback/region-comparison/result.json').read_text())

    def test_wrong_actual_store_fails_and_public_repair_is_conditional(self):
        status=self.invoke('broken',source='wrong',previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'violated',self.result('broken')['checks'])
        self.assertIn('loop-whole-post-memory',self.result('broken')['checks'][0]['detail'])
        with patch.object(engine,'render_compaction_model',side_effect=AssertionError('model generation forbidden')),patch(
                'subprocess.run',side_effect=AssertionError('compiler and solver forbidden')):
            repaired=self.invoke('repaired',previous=self.root/'baseline/feedback')
        self.assertEqual(repaired['status'],'complete')
        output=io.StringIO()
        with patch('spaghetti_extractor.commands.workflows._operator_index',return_value={
                'components':{'units':{'text-cleanup':{'products':['sourceContractCheck']}}}}),patch(
                'spaghetti_extractor.commands.workflows._realize_artifact',return_value=(self.root/'repaired/feedback/source-check.json',repaired)),contextlib.redirect_stdout(output):
            code=main(['component','check','metapad','text-cleanup','--source','--local-contracts','--json'])
        self.assertEqual(code,0)
        local=json.loads(output.getvalue())['local_contract']
        self.assertFalse(local['region_comparison']['whole_component_complete'])
        self.assertFalse(local['region_comparison']['activation_authorized'])
        self.assertEqual(local['region_comparison']['runtime_compatibility'],'unverified')

    def test_actual_outside_edit_reuses_proof_and_rechecks_current_transport_without_processes(self):
        with patch.object(engine,'render_compaction_model',side_effect=AssertionError('model generation forbidden')),patch(
                'subprocess.run',side_effect=AssertionError('compiler and solver forbidden')):
            status=self.invoke('rebound',source='outside-edit',previous=self.root/'baseline/feedback')
            local=json.loads((self.root/'rebound/feedback/compiler-checks.json').read_text())['local_contract']
            validate_component_source_region_feedback(self.root/'rebound/feedback',local,status['status'])
        self.assertEqual(status['status'],'complete',self.result('rebound')['checks'])
        old,new=self.result('baseline'),self.result('rebound')
        self.assertNotEqual(old['inputs']['preparation'],new['inputs']['preparation'])
        self.assertEqual(old['proof_key'],new['proof_key'])
        self.assertEqual(old['proof_files'],new['proof_files'])
        self.assertEqual(new['reuse']['status'],'reused')
        self.assertTrue(all(new['reuse'][k]==0 for k in ['model_generation','compiler_runs','inventory_runs','solver_runs']))

    def test_incompatible_boundary_and_damaged_proof_fail_before_model_generation(self):
        contract=deepcopy(self.contract);contract['regions'].remove('copy')
        with patch('subprocess.run',side_effect=AssertionError('invalid contract must not execute tools')):
            status=self.invoke('bad-cut',contract=contract,previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('selected regions differ',self.result('bad-cut')['checks'][0]['detail'])
        previous=self.root/'damaged';shutil.copytree(self.root/'baseline/feedback',previous)
        path=previous/'region-comparison/proof/functions.stdout';path.write_text(path.read_text()+'\n')
        with patch('subprocess.run',side_effect=AssertionError('damaged evidence must not execute tools')):
            status=self.invoke('bad-evidence',previous=previous)
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('region proof file changed',self.result('bad-evidence')['checks'][0]['detail'])

    def test_early_return_cannot_impersonate_a_normal_cut_outcome(self):
        with patch('subprocess.run',side_effect=AssertionError('unsupported outcomes must not compile or solve')):
            status=self.invoke('bad-return',source='unsupported-return',previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('explicit outcome contract',self.result('bad-return')['checks'][0]['detail'])

    def test_public_reader_rejects_upgraded_or_misreported_claims(self):
        root=self.root/'baseline/feedback'
        local=json.loads((root/'compiler-checks.json').read_text())['local_contract']
        for key in ['activation_authorized','whole_component_complete']:
            changed=deepcopy(local); changed['region_comparison'][key]=True
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'feedback differs'):
                validate_component_source_region_feedback(root,changed,'complete')


class RefinedSourceRegionCheckTests(SourceRegionCheckTests):
    runtime_revision = 3
    external_solver = False

    def test_model_callback_type_mismatch_rejects_before_goto_or_solver(self):
        render = engine.render_compaction_model
        def wrong_callback(*args, **kwargs):
            return render(*args, **kwargs).replace('static uint32_t spx_mutable_read(', 'static uint64_t spx_mutable_read(')
        with patch.object(engine, 'render_compaction_model', side_effect=wrong_callback):
            status = self.invoke('wrong-callback-type')
        result = self.result('wrong-callback-type')
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('host-typecheck', result['checks'][0]['detail'])
        self.assertIn('incompatible pointer type', result['checks'][0]['detail'])
        self.assertEqual(result['reuse']['solver_runs'], 0)
        self.assertEqual(result['reuse']['inventory_runs'], 0)

    def test_all_normal_exits_check_complete_refined_public_domain(self):
        result = self.result('baseline')
        self.assertEqual(result['proof_key']['bindings']['runtime_contract']['revision'], 3)
        proof = self.root/'baseline/feedback/region-comparison/proof'
        raw = json.loads(next((proof/'query-evidence').glob('*/stdout')).read_text())
        goals = [r for event in raw for r in event.get('result', [])
                 if r['description'].startswith('loop-all-exits-')]
        self.assertEqual(len(goals), 8)
        self.assertEqual({r['status'] for r in goals}, {'SUCCESS'})
        self.assertTrue(any('null-scratch-pending-crlf' in r['description'] for r in goals))

    def test_unknown_revision_cannot_reuse_an_existing_proof(self):
        contract = deepcopy(self.contract); contract['runtime_revision'] = 4
        with patch('subprocess.run', side_effect=AssertionError('unsupported revision must not execute tools')):
            status = self.invoke('unknown-revision', contract=contract, previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('unsupported runtime revision', self.result('unknown-revision')['checks'][0]['detail'])
