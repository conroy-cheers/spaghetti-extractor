"""Real save consumer edits and reuse under an explicit conditional summary."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.bisimulation_cleanup_summary import project_cleanup_summary
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check, validate_component_source_call_feedback
from spaghetti_extractor.operator.source_check import write_component_source_check

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-save'
TESTKIT={'fixtures':('compiler','cbmc'),'commands':('component check',),
         'resources':('tests/fixtures/metapad-cleanup-save',)}


class SourceOperationCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.summary=json.loads((FIXTURE/'summary-input.json').read_text())
        cls.prepare('source',(FIXTURE/'prepare-save.c').read_text())
        status=cls.invoke('baseline')
        if status['status']!='complete':raise AssertionError(cls.result('baseline'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def prepare(cls,name,text):
        d=cls.root/name;d.mkdir();(d/'prepare-save.c').write_text(text)
        build_component_source_package(lift_unit_id='cleanup-save',files={'prepare-save.c':d/'prepare-save.c'},
            shared_inputs={},operation_symbols={'prepare':'prepare_save'},out_dir=d/'source')
        status=write_component_source_check(target_id='metapad',component_id='cleanup-save',
            interface_package=FIXTURE,source_package=d/'source',out=d/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if status['status']!='complete':raise AssertionError(status)

    @classmethod
    def invoke(cls,name,source='source',summary=None,previous=None):
        d=cls.root/name;d.mkdir()
        with patch.object(checker,'checked_component_operation_summary',return_value=cls.summary if summary is None else summary):
            return write_component_source_call_check(target_id='metapad',component_id='cleanup-save',
                preparation=cls.root/source/'preparation',exact=FIXTURE/'exact',supplier=cls.root/'supplier',
                contract={'profile':checker.PROFILE,'entry_rva':0x5c2a,'service_id':'cleanup'},
                source_package=cls.root/source/'source',interface_package=FIXTURE,out=d/'feedback',workspace=d/'work',
                goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),smt_solver=None,
                previous=previous,timeout_seconds=60)

    @classmethod
    def result(cls,name):
        return json.loads((cls.root/name/'feedback/caller-comparison/result.json').read_text())

    def test_real_operation_proof_and_neighbor_rebinding_have_no_callee_body(self):
        r=self.result('baseline');self.assertEqual(r['query']['status'],'satisfied')
        self.assertGreater(r['query']['properties'],1000)
        proof=self.root/'baseline/feedback/caller-comparison/proof'
        names={p.name for p in proof.iterdir() if p.suffix in {'.c','.h'}}
        self.assertNotIn('behavioral-fn-000055b7.c',names);self.assertNotIn('cleanup.c',names)
        changed=copy.deepcopy(self.summary);changed['evidence']['regional_receipts']['tail']='1'*64
        with patch('subprocess.run',side_effect=AssertionError('no compiler or solver on reuse')),patch.object(
                checker,'render_cleanup_save_model',side_effect=AssertionError('no model regeneration')),patch.object(
                checker,'render_component_c_headers_v5',side_effect=AssertionError('no header regeneration')):
            status=self.invoke('neighbor',summary=changed,previous=self.root/'baseline/feedback')
            self.assertEqual(status['status'],'complete',self.result('neighbor'))
            with patch.object(checker,'checked_component_operation_summary',return_value=changed):
                feedback=json.loads((self.root/'neighbor/feedback/compiler-checks.json').read_text())
                validate_component_source_call_feedback(self.root/'neighbor/feedback',feedback['local_contract'],'complete')
        n=self.result('neighbor')
        self.assertEqual(n['proof_key'],r['proof_key']);self.assertEqual(n['proof_files'],r['proof_files'])
        self.assertNotEqual(n['supplier_transition'],r['supplier_transition'])
        self.assertEqual(n['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.assertFalse(n['whole_component_complete']);self.assertFalse(n['activation_authorized'])

    def test_actual_wrong_arithmetic_fault_handling_and_view_arguments_reject(self):
        original=(FIXTURE/'prepare-save.c').read_text()
        cases=[('arithmetic','(uint32_t)previous - removed','(uint32_t)previous + removed','save-adjusted-length'),
            ('fault','  if (removed == UINT32_MAX) return UINT32_MAX;\n','','save-no-post-fault-writes'),
            ('view','text, suppress_notice, main_window, edit_window, caption);',
             'text, main_window, suppress_notice, edit_window, caption);','save-cleanup-complete-view-arguments')]
        cases.append(('temporary-write','  uint32_t removed =', '  uint64_t saved;\n  if (length->read(length->access_context,length->base,0,4,&saved)) return UINT32_MAX;\n  length->write(length->access_context,length->base,0,4,0U);\n  length->write(length->access_context,length->base,0,4,saved);\n  uint32_t removed =', 'save-no-public-writes-before-cleanup'))
        cases.append(('context','  return removed;',
            '  context->protocol_state=(spx_cleanup_save_protocol_state_v5)1;\n  return removed;',
            'save-source-context-frame'))
        for name,before,after,diagnostic in cases:
            with self.subTest(name=name):
                self.assertIn(before,original);self.prepare('source-'+name,original.replace(before,after))
                status=self.invoke(name,source='source-'+name,previous=self.root/'baseline/feedback')
                self.assertEqual(status['status'],'violated',self.result(name))
                query=json.loads((self.root/name/'feedback/caller-comparison/proof/query.stdout').read_text())
                failures={row.get('description') for block in query for row in block.get('result',[])
                          if row.get('status')=='FAILURE'}
                self.assertIn(diagnostic,failures)
                self.assertIn('source',self.result(name)['reuse']['changed_bindings'])
        with patch('subprocess.run',side_effect=AssertionError('repair must reuse')):
            self.assertEqual(self.invoke('repair',previous=self.root/'baseline/feedback')['status'],'complete')

    def test_incompatible_full_contract_stops_before_model_or_solver(self):
        changed=copy.deepcopy(self.summary);changed['contract']['normal_return']['stack_delta']=8
        changed['contract_sha256']=canonical_sha256_v3(changed['contract'])
        with patch('subprocess.run',side_effect=AssertionError('incompatible contract must fail before processes')):
            status=self.invoke('incompatible',summary=changed,previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('reviewed composition rule',self.result('incompatible')['checks'][0]['detail'])

    def test_unused_edi_guarantee_withdrawal_reuses_the_real_save_proof(self):
        frame=self.summary['contract']['normal_return']['preserved_equalities']
        changed=project_cleanup_summary(self.summary, {'rule':'normal-frame-subset-v1',
            'preserved_equalities':[v for v in frame if v!='state.edi==initial.edi']})
        with patch('subprocess.run',side_effect=AssertionError('compatible contract view cannot execute processes')),patch.object(
                checker,'render_cleanup_save_model',side_effect=AssertionError('no model rendering')),patch.object(
                checker,'render_component_c_headers_v5',side_effect=AssertionError('no headers')):
            self.assertEqual(self.invoke('withdraw-edi',summary=changed,previous=self.root/'baseline/feedback')['status'],'complete')
        baseline=self.result('baseline');result=self.result('withdraw-edi')
        self.assertEqual(result['proof_key'],baseline['proof_key']);self.assertEqual(result['proof_files'],baseline['proof_files'])
        self.assertNotEqual(result['supplier_transition']['domain_sha256'],baseline['supplier_transition']['domain_sha256'])
        self.assertEqual(result['dependency_contract']['missing_guarantees'],[])
        self.assertEqual(result['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        model=(self.root/'baseline/feedback/caller-comparison/proof/pair.c').read_text()
        self.assertNotIn('output->edi=input->edi',model)

    def test_tampered_compiler_input_cannot_be_imported(self):
        root=self.root/'tampered';shutil.copytree(self.root/'baseline/feedback/caller-comparison',root)
        r=json.loads((root/'result.json').read_text())
        with (root/'proof/prepare-save.c').open('a') as f:f.write('\n/* changed */\n')
        with self.assertRaisesRegex(ValueError,'proof bytes changed'):
            checker.validate_evidence(r,root)
