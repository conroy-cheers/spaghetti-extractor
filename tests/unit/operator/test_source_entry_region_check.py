"""Public actual entry proofs establish the complete refined loop admission."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components import bisimulation_compaction_check as engine
from spaghetti_extractor.operator.source_region_check import (
    write_component_source_region_check, validate_component_source_region_feedback,
)
from .test_source_call_regions import check as prepare, FIXTURE as SOURCE

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-entry'
TESTKIT = {'fixtures': ('compiler', 'cbmc'), 'commands': ('component check',),
           'resources': ('tests/fixtures/metapad-cleanup-entry', 'tests/fixtures/metapad-authored-call')}


class SourceEntryRegionCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.contract = json.loads((FIXTURE/'local-contract.json').read_text())
        boundary = json.loads((FIXTURE/'boundary.json').read_text())
        source = (SOURCE/'cleanup.c').read_text()
        first = '  uint32_t length = context->services->length(context->services->context, text);\n'
        cases = {'source': source, 'outside-edit': source.replace('context, 31U);', 'context, 32U);'),
                 'wrong-allocation': source.replace('context, 64U, length + 1U)', 'context, 0U, length + 1U)'),
                 'predecessor': source.replace(first, '  context->state.reserved = 1U;\n'+first)}
        for name, body in cases.items():
            root = cls.root/name; root.mkdir()
            status, feedback, _ = prepare(root, body, boundary=boundary, graph=True)
            if status['status'] != 'complete':
                raise AssertionError(feedback)
        status = cls.invoke('baseline')
        if status['status'] != 'complete':
            raise AssertionError(cls.result('baseline')['checks'])

    @classmethod
    def invoke(cls, name, *, source='source', contract=None, previous=None):
        root = cls.root/name; root.mkdir()
        return write_component_source_region_check(target_id='metapad', component_id='text-cleanup',
            preparation=cls.root/source/'feedback', exact=FIXTURE, contract=cls.contract if contract is None else contract,
            out=root/'feedback', workspace=root/'work', goto_cc=Path(shutil.which('goto-cc')),
            goto_instrument=Path(shutil.which('goto-instrument')), cbmc=Path(shutil.which('cbmc')), smt_solver=None,
            timeout_seconds=180, previous=previous)

    @classmethod
    def result(cls, name):
        return json.loads((cls.root/name/'feedback/region-comparison/result.json').read_text())

    def test_public_entry_checks_all_eight_outgoing_memory_predicates(self):
        root = self.root/'baseline/feedback'; result = self.result('baseline')
        raw = json.loads(next((root/'region-comparison/proof/query-evidence').glob('*/stdout')).read_text())
        checks = [r for event in raw for r in event.get('result', []) if r['description'].startswith('entry-consumer-')]
        self.assertEqual(len(checks), 8)
        self.assertTrue(all(r['status'] == 'SUCCESS' for r in checks))
        self.assertIn('entry-consumer-null-scratch-pending-crlf', {r['description'] for r in checks})
        descriptions = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'SUCCESS'}
        self.assertIn('entry-service-current-memory-is-incoming', descriptions)
        self.assertTrue(result['source_transport']['local_cut_observer_arguments_checked'])
        self.assertFalse(result['whole_component_complete'])
        self.assertFalse(result['activation_authorized'])
        with patch('subprocess.run', side_effect=AssertionError('import processes forbidden')):
            validate_component_source_region_feedback(root, json.loads((root/'compiler-checks.json').read_text())['local_contract'], 'complete')

    def test_temporary_public_write_rejects_even_with_unchanged_final_memory(self):
        render = engine.render_fresh_buffer_model
        def corrupt(data):
            source = render(data)
            anchor = 'entry_before_service(e);'
            self.assertEqual(source.count(anchor), 4)
            return source.replace(anchor, 'spx_mutable_event(e->world,e->text,1U,1U,0U,0U);'+anchor+'e->world->count=0U;', 1)
        with patch.object(engine, 'render_fresh_buffer_model', side_effect=corrupt):
            status = self.invoke('wrong-snapshot')
        self.assertEqual(status['status'], 'violated')
        root = self.root/'wrong-snapshot/feedback/region-comparison/proof'
        raw = json.loads(next((root/'query-evidence').glob('*/stdout')).read_text())
        failures = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
        self.assertIn('entry-service-current-memory-is-incoming', failures)
        self.assertNotIn('entry-whole-post-memory', failures)

    def test_real_allocation_error_fails_and_repair_reuses(self):
        status = self.invoke('broken', source='wrong-allocation', previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'violated', self.result('broken')['checks'])
        self.assertIn('entry-allocation-call', self.result('broken')['checks'][0]['detail'])
        with patch.object(engine, 'render_fresh_buffer_model', side_effect=AssertionError('generation forbidden')), patch(
                'subprocess.run', side_effect=AssertionError('repair processes forbidden')):
            status = self.invoke('repair', previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'complete')
        self.assertEqual(self.result('repair')['reuse']['status'], 'reused')

    def test_outside_edit_and_role_order_preserve_entry_proof(self):
        contract = deepcopy(self.contract)
        contract['source_locals'] = dict(reversed(list(contract['source_locals'].items())))
        with patch.object(engine, 'render_fresh_buffer_model', side_effect=AssertionError('generation forbidden')), patch(
                'subprocess.run', side_effect=AssertionError('consumer processes forbidden')):
            status = self.invoke('outside', source='outside-edit', contract=contract, previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'complete', self.result('outside')['checks'])
        old, new = self.result('baseline'), self.result('outside')
        self.assertEqual(old['proof_key'], new['proof_key'])
        self.assertEqual(old['proof_files'], new['proof_files'])
        self.assertTrue(all(new['reuse'][k] == 0 for k in ['model_generation', 'compiler_runs', 'inventory_runs', 'solver_runs']))

    def test_missing_region_and_real_predecessor_cannot_be_ignored(self):
        contract = deepcopy(self.contract); contract['regions'].remove('prefix_iter')
        with patch('subprocess.run', side_effect=AssertionError('invalid admission must not run tools')):
            missing = self.invoke('missing-region', contract=contract)
            predecessor = self.invoke('unproved-predecessor', source='predecessor')
        self.assertEqual(missing['status'], 'incomplete')
        self.assertIn('selected regions differ', self.result('missing-region')['checks'][0]['detail'])
        self.assertEqual(predecessor['status'], 'incomplete')
        self.assertIn('unproved predecessor', self.result('unproved-predecessor')['checks'][0]['detail'])
