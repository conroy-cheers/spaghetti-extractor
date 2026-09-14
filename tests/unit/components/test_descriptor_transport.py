"""Actual view accessors and full-source grant flow reject broken transport."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_descriptor_transport import (
    cleanup_descriptor_transport_domain, checked_cleanup_grant_protocol, descriptor_files,
    check_descriptor_files, TEMPLATE,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-descriptor/inputs.json'
TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('tests/fixtures/metapad-cleanup-descriptor',)}


class DescriptorTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text())
        cls.domain = cleanup_descriptor_transport_domain(cls.fixture['model_excerpts'], cls.fixture['headers'])

    def query(self, source=TEMPLATE, *, domain=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'admission.c').write_text(source)
            for name, content in descriptor_files(self.domain if domain is None else domain).items():
                (root/name).write_text(content)
            subprocess.run([shutil.which('cc'), '-m32', '-fsyntax-only', '-nostdinc', '-I', '.',
                '-Werror=incompatible-pointer-types', '-Wno-implicit-function-declaration', 'admission.c'],
                cwd=root, capture_output=True, check=True)
            subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', '-I', '.', 'admission.c',
                '--function', 'check_admission', '-o', 'model.goto'], cwd=root, capture_output=True, check=True)
            result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function',
                'check_admission', *checker_options(20, None)], cwd=root, timeout_seconds=60, output_prefix=root/'query')
            raw = json.loads((root/'query.stdout').read_text())
            failures = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
            return result, failures

    def test_live_contexts_preserve_access_results_faults_and_effect_arguments(self):
        result, failures = self.query()
        self.assertEqual(result['status'], 'satisfied', failures)
        self.assertGreater(result['properties'], 100)
        self.assertNotIn('authored.c', TEMPLATE)

    def test_changed_reference_generation_and_physical_coordinate_reject(self):
        variants = [
            ('right.access_context=&right_context;', 'right.access_context=&right_context;right.base.generation++;',
             'descriptor-public-reference-preserved'),
            ('right_context={&right_runtime,address,extent,3U}', 'right_context={&right_runtime,address+1U,extent,3U}',
             'descriptor-access-effect-arguments')]
        for old, new, property_ in variants:
            with self.subTest(property=property_):
                source = TEMPLATE.replace(old, new); self.assertNotEqual(source, TEMPLATE)
                result, failures = self.query(source)
                self.assertEqual(result['status'], 'violated'); self.assertIn(property_, failures)

    def test_context_storage_must_survive_the_borrow(self):
        helper = '''static void expire_context(spx_view_v5 *v,spx_runtime *r,uint32_t a,uint32_t n){
 spx_component_view_context temporary={r,a,n,3U};v->context=&temporary;v->access_context=&temporary;
}
'''
        source = TEMPLATE.replace('void check_admission(void){', helper+'void check_admission(void){')
        source = source.replace('right.access_context=&right_context;',
            'right.access_context=&right_context;expire_context(&right,&right_runtime,address,extent);')
        result, failures = self.query(source)
        self.assertEqual(result['status'], 'violated')
        self.assertTrue(any('dead object' in f for f in failures), failures)

    def test_revoked_access_is_rejected_without_claiming_physical_free(self):
        result, failures = self.query(TEMPLATE.replace('struct environment environment={0}',
            'struct environment environment={1}'))
        self.assertEqual(result['status'], 'violated')
        self.assertIn('tail-source-no-use-after-release', failures)

    def test_trace_abstraction_cannot_hide_an_additional_access(self):
        domain = deepcopy(self.domain)
        statement = '''view->runtime->write(view->runtime->context,
      view->address + (uint32_t)offset, UINT32_C(1), value, &fault);'''
        body = domain['accessors']['spx_component_view_write']
        self.assertEqual(body.count(statement), 1)
        domain['accessors']['spx_component_view_write'] = body.replace(statement, statement+'\n  '+statement)
        result, failures = self.query(domain=domain)
        self.assertEqual(result['status'], 'violated')
        self.assertIn('descriptor-single-access-hook', failures)

    def test_full_real_source_has_an_inductive_grant_protocol(self):
        result = checked_cleanup_grant_protocol(self.fixture['source_body'], context_parameter='cleanup::context')
        self.assertEqual(result['reachable_instructions'], 149)
        self.assertEqual(result['abstract_states'], 149)
        self.assertEqual(result['normal_return_grant'], 'revoked')
        self.assertFalse(result['physical_deallocation_checked'])
        self.assertEqual({grant for _, outcome, grant in result['returns'] if outcome == 'fault'}, {'active', 'revoked'})

    def test_protocol_rejects_early_return_double_issue_and_post_release_use(self):
        for change in ['early-return', 'double-issue', 'late-use', 'missing-release']:
            with self.subTest(change=change):
                body = deepcopy(self.fixture['source_body']); rows = body['instructions']
                if change == 'early-return':
                    rows[28]['code']['sub'][0]['namedSub']['value']['id'] = '00000000'
                elif change == 'double-issue':
                    rows[10]['code'] = deepcopy(rows[7]['code'])
                elif change == 'late-use':
                    rows[195]['code'] = deepcopy(rows[42]['code'])
                else:
                    rows[191]['code'] = deepcopy(rows[189]['code'])
                with self.assertRaises(ValueError):
                    checked_cleanup_grant_protocol(body, context_parameter='cleanup::context')

    def test_accessor_and_complete_descriptor_guarantees_are_bound(self):
        for role, old, new in [('loop', 'view->runtime->read(', 'changed_read('),
                ('entry', 'entry-full-view-base.generation', 'omitted-generation'),
                ('tail', '!source_environment->released', '1U')]:
            models = deepcopy(self.fixture['model_excerpts']); models[role] = models[role].replace(old, new)
            with self.assertRaises(ValueError):
                cleanup_descriptor_transport_domain(models, self.fixture['headers'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in descriptor_files(self.domain).items():
                (root/name).write_text(content)
            with patch('spaghetti_extractor.components.bisimulation_descriptor_transport.descriptor_files',
                       side_effect=AssertionError('import must not generate headers')):
                check_descriptor_files(root, self.domain)
                header = root/'descriptor-accessors.h'; header.write_text(header.read_text()+'__CPROVER_assume(0);\n')
                with self.assertRaisesRegex(ValueError, 'extra descriptor'):
                    check_descriptor_files(root, self.domain)


if __name__ == '__main__':
    unittest.main()
