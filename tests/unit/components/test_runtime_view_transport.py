"""Actual returned-view callbacks must preserve admitted observations and effects."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_descriptor_transport import cleanup_descriptor_transport_domain, descriptor_files
from spaghetti_extractor.components.bisimulation_runtime_view_transport import (
    TEMPLATE, runtime_view_recipe, runtime_view_files, check_runtime_view_files,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-descriptor/inputs.json'
TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('tests/fixtures/metapad-cleanup-descriptor',)}


class RuntimeViewTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = json.loads(FIXTURE.read_text())
        cls.domain = cleanup_descriptor_transport_domain(fixture['model_excerpts'], fixture['headers'])

    def query(self, source=TEMPLATE):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'admission.c').write_text(source)
            for name, content in (descriptor_files(self.domain) | runtime_view_files()).items():
                (root/name).write_text(content)
            for command in [
                [shutil.which('cc'), '-m32', '-fsyntax-only', '-nostdinc', '-I', '.',
                 '-Werror=incompatible-pointer-types', '-Wno-implicit-function-declaration', 'admission.c'],
                [shutil.which('goto-cc'), '--i386-win32', '-nostdinc', '-I', '.', 'admission.c',
                 '--function', 'check_admission', '-o', 'model.goto']]:
                process = subprocess.run(command, cwd=root, capture_output=True, text=True)
                self.assertEqual(process.returncode, 0, process.stderr)
            result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function',
                'check_admission', *checker_options(20, None)], cwd=root, timeout_seconds=60, output_prefix=root/'query')
            raw = json.loads((root/'query.stdout').read_text())
            failures = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
            return result, failures

    def test_production_callbacks_relate_null_live_and_offset_views(self):
        result, failures = self.query()
        self.assertEqual(result['status'], 'satisfied', failures)
        self.assertGreater(result['properties'], 100)

    def test_expired_or_wrong_generation_and_wrong_coordinate_reject(self):
        for old, new in [
            ('origin_live=1U;', 'origin_live=0U;'),
            ('uint64_t abstract_value=0', 'actual.base.generation++;uint64_t abstract_value=0'),
            ('origin_address=address-origin_offset;', 'origin_address=address-origin_offset+1U;')]:
            with self.subTest(change=new):
                source = TEMPLATE.replace(old, new); self.assertNotEqual(source, TEMPLATE)
                result, failures = self.query(source)
                self.assertEqual(result['status'], 'violated', failures)
                self.assertTrue(failures & {'runtime-view-outcome-correspondence',
                    'runtime-view-complete-access-effect-arguments'}, failures)

    def test_fault_output_and_unsupported_width_cannot_be_observed(self):
        for old, new, expected in [
            ('abstract_status!=0U || abstract_value==actual_value', 'abstract_value==actual_value',
             'runtime-view-successful-value'),
            ('width==1U || width==2U || width==4U', 'width==3U',
             'runtime-view-outcome-correspondence')]:
            with self.subTest(change=new):
                result, failures = self.query(TEMPLATE.replace(old, new))
                self.assertEqual(result['status'], 'violated', failures)
                self.assertIn(expected, failures)

    def test_reader_binds_actual_accessor_and_native_dispatch_without_generation(self):
        recipe = runtime_view_recipe()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in runtime_view_files().items():
                (root/name).write_text(content)
            with patch('spaghetti_extractor.components.bisimulation_runtime_view_transport.result_view_runtime_helpers',
                       side_effect=AssertionError('reader must not generate runtime headers')):
                check_runtime_view_files(root, recipe)
                changed = deepcopy(recipe); changed['dispatch_sha256'] = '0'*64
                with self.assertRaisesRegex(ValueError, 'dispatch differs'):
                    check_runtime_view_files(root, changed)
                header = root/'runtime-accessors.h'
                header.write_text(header.read_text()+'\n__CPROVER_assume(0);')
                with self.assertRaisesRegex(ValueError, 'accessor code differs'):
                    check_runtime_view_files(root, recipe)


if __name__ == '__main__':
    unittest.main()
