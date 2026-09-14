"""Real terminal cleanup consumes a checked supplier without its implementation."""
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
from .test_source_original_comparison import check as supplier_check, ORIGINAL

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-tail'
TESTKIT = {'fixtures': ('compiler', 'cbmc', 'z3'), 'commands': ('component check',), 'resources': (
    'tests/fixtures/metapad-cleanup-tail', 'tests/fixtures/metapad-authored-call',
    'tests/fixtures/hand-defined-boundaries/resource-text', 'profiles/pe32-user32-resource-text-runtime-v1.json')}


class SourceTailCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.root = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.contract = json.loads((FIXTURE/'contract.json').read_text())
        source = (ORIGINAL/'resource-text.c').read_text()
        start, end = source.index('  uint64_t module;'), source.index('  spx_view_v5 buffer =')
        loop = source[:start]+'''  uint32_t module=0U;
  for(uint32_t i=0; i<4U; ++i) {
    uint64_t byte;
    const spx_view_v5 *view=&context->state.module;
    if(view->read(view->access_context,view->base,i,1U,&byte)) return (spx_view_v5){0};
    module|=(uint32_t)byte << (8U*i);
  }
'''+source[end:]
        for name, body in [('supplier', source), ('edited-supplier', loop)]:
            status, _, _ = supplier_check(cls.root/name, body)
            if status['status'] != 'complete':
                raise AssertionError(status)
        text = (SOURCE/'cleanup.c').read_text()
        boundary = json.loads((FIXTURE/'boundary.json').read_text())
        anchor = '  context->services->release(context->services->context, scratch.base);'
        assert text.count(anchor) == 1
        for name, body in [('source', text), ('wrong-source', text.replace(anchor, '  scratch.base.generation += 1U;\n'+anchor))]:
            root = cls.root/name; root.mkdir()
            status, feedback, _ = prepare(root, body, boundary=boundary, graph=True)
            if status['status'] != 'complete':
                raise AssertionError(feedback)
        status = cls.invoke('baseline')
        if status['status'] != 'complete':
            raise AssertionError(cls.result('baseline')['checks'])

    @classmethod
    def invoke(cls, name, *, source='source', supplier='supplier', previous=None, contract=None, **kwargs):
        root = cls.root/name; root.mkdir()
        return write_component_source_region_check(target_id='metapad', component_id='text-cleanup',
            preparation=cls.root/source/'feedback', exact=FIXTURE/'exact',
            contract=cls.contract if contract is None else contract, out=root/'feedback', workspace=root/'work',
            goto_cc=Path(shutil.which('goto-cc')), goto_instrument=Path(shutil.which('goto-instrument')),
            cbmc=Path(shutil.which('cbmc')), smt_solver=None, previous=previous, timeout_seconds=240,
            dependencies=kwargs.get('dependencies', {'resource_text': cls.root/supplier/'feedback'}))

    @classmethod
    def result(cls, name):
        return json.loads((cls.root/name/'feedback/region-comparison/result.json').read_text())

    def test_supplier_implementation_edit_rebinds_without_consumer_work(self):
        with patch.object(engine, 'render_cleanup_model', side_effect=AssertionError('consumer generation forbidden')), patch(
                'subprocess.run', side_effect=AssertionError('consumer processes forbidden')):
            status = self.invoke('neighbor', supplier='edited-supplier', previous=self.root/'baseline/feedback')
            local = json.loads((self.root/'neighbor/feedback/compiler-checks.json').read_text())['local_contract']
            validate_component_source_region_feedback(self.root/'neighbor/feedback', local, status['status'])
        self.assertEqual(status['status'], 'complete')
        old, new = self.result('baseline'), self.result('neighbor')
        self.assertNotEqual(old['dependency_evidence']['resource_text']['supplier_receipt_sha256'],
                            new['dependency_evidence']['resource_text']['supplier_receipt_sha256'])
        self.assertEqual(old['proof_key'], new['proof_key'])
        self.assertEqual(old['proof_files'], new['proof_files'])
        self.assertEqual(new['reuse']['status'], 'reused')
        self.assertTrue(all(new['reuse'][k] == 0 for k in ['model_generation', 'compiler_runs', 'inventory_runs', 'solver_runs']))
        self.assertNotIn('behavioral-fn-00001284.c', new['proof_files'])
        self.assertNotIn('authored.goto', new['proof_files'])
        self.assertFalse(new['whole_component_complete'])
        self.assertFalse(new['activation_authorized'])

    def test_actual_reference_error_fails_and_repair_reuses(self):
        status = self.invoke('broken', source='wrong-source', previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'violated', self.result('broken')['checks'])
        self.assertIn('tail-release-reference', self.result('broken')['checks'][0]['detail'])
        with patch('subprocess.run', side_effect=AssertionError('repair processes forbidden')):
            repaired = self.invoke('repair', previous=self.root/'baseline/feedback')
        self.assertEqual(repaired['status'], 'complete')
        self.assertEqual(self.result('repair')['reuse']['status'], 'reused')

    def test_incompatible_domain_and_malformed_dependencies_fail_closed(self):
        contract = deepcopy(self.contract); contract['supplier_call']['private_stack']['low'] = -40
        with patch('subprocess.run', side_effect=AssertionError('invalid inputs must not run tools')):
            status = self.invoke('bad-frame', contract=contract, previous=self.root/'baseline/feedback')
            malformed = self.invoke('bad-dependencies', dependencies=[])
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('does not admit supplier private frame', self.result('bad-frame')['checks'][0]['detail'])
        self.assertEqual(malformed['status'], 'incomplete')
        self.assertIn('dependencies must be a mapping', self.result('bad-dependencies')['checks'][0]['detail'])

    def test_changed_admission_requires_new_consumer_proof(self):
        contract = deepcopy(self.contract); contract['views']['caption']['extent'] -= 1
        with patch.object(engine, 'render_cleanup_model', side_effect=ValueError('new proof required')) as model:
            status = self.invoke('refine', contract=contract, previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'incomplete')
        model.assert_called_once()
        self.assertEqual(self.result('refine')['reuse']['status'], 'requires-recheck')
        self.assertIn('contract', self.result('refine')['reuse']['changed_bindings'])

    def test_public_reader_rejects_wrong_supplier_binding(self):
        root = self.root/'baseline/feedback'
        local = json.loads((root/'compiler-checks.json').read_text())['local_contract']
        local['region_comparison']['dependencies']['resource_text']['supplier_receipt_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'feedback differs'):
            validate_component_source_region_feedback(root, local, 'complete')
