"""Guarded real consumer uses current post-cleanup contents in its next service."""
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

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-replace'
TESTKIT={'fixtures':('compiler','cbmc'),'commands':('component check',),
         'resources':('tests/fixtures/metapad-cleanup-replace',)}


class SourceReplaceCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.summary=json.loads((FIXTURE/'summary-input.json').read_text())
        cls.prepare('source',(FIXTURE/'replace-selection.c').read_text())
        status=cls.invoke('baseline')
        if status['status']!='complete':raise AssertionError(cls.result('baseline'))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    @classmethod
    def prepare(cls,name,text):
        d=cls.root/name;d.mkdir();(d/'replace-selection.c').write_text(text)
        build_component_source_package(lift_unit_id='cleanup-replace',files={'replace-selection.c':d/'replace-selection.c'},
            shared_inputs={},operation_symbols={'replace':'replace_selection'},out_dir=d/'source')
        status=write_component_source_check(target_id='metapad',component_id='cleanup-replace',
            interface_package=FIXTURE,source_package=d/'source',out=d/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if status['status']!='complete':raise AssertionError(status)

    @classmethod
    def invoke(cls,name,source='source',summary=None,previous=None):
        d=cls.root/name;d.mkdir()
        with patch.object(checker,'checked_component_operation_summary',return_value=cls.summary if summary is None else summary):
            return write_component_source_call_check(target_id='metapad',component_id='cleanup-replace',
                preparation=cls.root/source/'preparation',exact=FIXTURE/'exact',supplier=cls.root/'supplier',
                contract={'profile':checker.REPLACE_PROFILE,'entry_rva':0xb18e,'service_id':'cleanup'},
                source_package=cls.root/source/'source',interface_package=FIXTURE,out=d/'feedback',workspace=d/'work',
                goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),smt_solver=None,
                previous=previous,timeout_seconds=60)

    @classmethod
    def result(cls,name):return json.loads((cls.root/name/'feedback/caller-comparison/result.json').read_text())

    def test_real_both_guards_and_following_service_reuse_contract_without_bodies(self):
        r=self.result('baseline');self.assertEqual(r['status'],'satisfied')
        self.assertGreater(r['query']['properties'],2000)
        proof=self.root/'baseline/feedback/caller-comparison/proof'
        self.assertEqual({p.name for p in proof.glob('*.c')},
            {'pair.c','replace-selection.c','behavioral-fn-0000b18e.c','behavioral-support.c'})
        changed=copy.deepcopy(self.summary);changed['evidence']['regional_receipts']['tail']='2'*64
        with patch('subprocess.run',side_effect=AssertionError('reuse cannot execute processes')),patch.object(
                checker,'render_cleanup_replace_model',side_effect=AssertionError('reuse cannot render models')),patch.object(
                checker,'render_component_c_headers_v5',side_effect=AssertionError('reuse cannot render headers')):
            self.assertEqual(self.invoke('neighbor',summary=changed,previous=self.root/'baseline/feedback')['status'],'complete')
            with patch.object(checker,'checked_component_operation_summary',return_value=changed):
                f=json.loads((self.root/'neighbor/feedback/compiler-checks.json').read_text())
                validate_component_source_call_feedback(self.root/'neighbor/feedback',f['local_contract'],'complete')
        n=self.result('neighbor');self.assertEqual(n['proof_key'],r['proof_key']);self.assertEqual(n['proof_files'],r['proof_files'])
        self.assertNotEqual(n['supplier_transition'],r['supplier_transition'])
        self.assertEqual(n['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.assertFalse(n['whole_component_complete']);self.assertFalse(n['activation_authorized'])

    def test_actual_wrong_guards_message_fault_and_result_edits_reject(self):
        source=(FIXTURE/'replace-selection.c').read_text()
        cases=[('mode','mode != 2U && mode != 3U','mode != 3U','replace-both-mode-guards'),
            ('message','194U','195U','replace-message-arguments'),
            ('fault','    if (removed == UINT32_MAX) return (spx_outcome_v5){1U, 0U};\n','    (void)removed;\n','replace-fault-prefix'),
            ('result','  return (spx_outcome_v5){0U, result};','  if (result==UINT32_MAX) return (spx_outcome_v5){1U,0U};\n  return (spx_outcome_v5){0U,result};','replace-normal-continuation'),
            ('context','  return (spx_outcome_v5){0U, result};','  context->protocol_state=(spx_cleanup_replace_protocol_state_v5)1;\n  return (spx_outcome_v5){0U,result};','replace-source-context-frame')]
        for name,before,after,diagnostic in cases:
            with self.subTest(name=name):
                self.assertIn(before,source);self.prepare('source-'+name,source.replace(before,after))
                self.assertEqual(self.invoke(name,source='source-'+name,previous=self.root/'baseline/feedback')['status'],'violated',self.result(name))
                raw=json.loads((self.root/name/'feedback/caller-comparison/proof/query.stdout').read_text())
                failures={r.get('description') for b in raw for r in b.get('result',[]) if r.get('status')=='FAILURE'}
                self.assertIn(diagnostic,failures)

    def test_reading_window_before_mutating_dependency_rejects(self):
        source=(FIXTURE/'replace-selection.c').read_text()
        start=source.index('  uint64_t window;');end=source.index('  uint32_t result =')
        block=source[start:end];changed=source[:start]+source[end:]
        changed=changed.replace('  if (mode != 2U',block+'  if (mode != 2U')
        self.prepare('source-stale',changed)
        self.assertEqual(self.invoke('stale',source='source-stale')['status'],'violated',self.result('stale'))
        raw=json.loads((self.root/'stale/feedback/caller-comparison/proof/query.stdout').read_text())
        self.assertTrue(any(r.get('status')=='FAILURE' and r.get('description')=='replace-message-arguments' for b in raw for r in b.get('result',[])))

    def test_edi_withdrawal_invalidates_ui_and_an_omitted_requirement_fails_proof(self):
        frame=self.summary['contract']['normal_return']['preserved_equalities']
        changed=project_cleanup_summary(self.summary, {'rule':'normal-frame-subset-v1',
            'preserved_equalities':[v for v in frame if v!='state.edi==initial.edi']})
        with patch('subprocess.run',side_effect=AssertionError('missing contract guarantee cannot execute processes')),patch.object(
                checker,'render_cleanup_replace_model',side_effect=AssertionError('no model rendering')):
            self.assertEqual(self.invoke('withdraw-edi',summary=changed,previous=self.root/'baseline/feedback')['status'],'incomplete')
        result=self.result('withdraw-edi')
        self.assertEqual(result['dependency_contract']['missing_guarantees'],['state.edi==initial.edi'])
        self.assertEqual(result['reuse']['status'],'requires-recheck')
        self.assertEqual(result['reuse']['solver_runs'],0)
        self.assertFalse((self.root/'withdraw-edi/feedback/caller-comparison/proof').exists())
        # Deliberately underdeclare the profile's requirement. Complete original/C
        # comparison must expose the missing fact rather than certify that profile.
        selected=checker.selected_profile({'profile':checker.REPLACE_PROFILE,'entry_rva':0xb18e,'service_id':'cleanup'})
        selected['required_frame'].remove('edi')
        with patch.object(checker,'selected_profile',return_value=selected):
            self.assertEqual(self.invoke('underdeclared',summary=changed)['status'],'violated',self.result('underdeclared'))
        raw=json.loads((self.root/'underdeclared/feedback/caller-comparison/proof/query.stdout').read_text())
        self.assertTrue(any(r.get('status')=='FAILURE' and r.get('description')=='replace-message-native-arguments' for b in raw for r in b.get('result',[])))

    def test_incompatible_contract_and_changed_bytes_fail_closed(self):
        changed=copy.deepcopy(self.summary);changed['contract']['normal_return']['stack_delta']=8
        changed['contract_sha256']=canonical_sha256_v3(changed['contract'])
        with patch('subprocess.run',side_effect=AssertionError('contract mismatch cannot run processes')):
            self.assertEqual(self.invoke('incompatible',summary=changed,previous=self.root/'baseline/feedback')['status'],'incomplete')
        self.assertIn('reviewed composition rule',self.result('incompatible')['checks'][0]['detail'])
        root=self.root/'tampered';shutil.copytree(self.root/'baseline/feedback/caller-comparison',root)
        with (root/'proof/replace-selection.c').open('a') as f:f.write('\n/* stale */\n')
        with self.assertRaisesRegex(ValueError,'proof bytes changed'):
            checker.validate_evidence(json.loads((root/'result.json').read_text()),root)
