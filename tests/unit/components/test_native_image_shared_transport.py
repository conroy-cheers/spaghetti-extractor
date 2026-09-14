"""A real logical consumer uses retained Metapad origins and native lookup code."""

import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.cbmc_backend import bind_smt_solver, run_cbmc_properties, solver_arguments
from .native_image_shared_fixture import NATIVE_FIXTURE, write_image_logical_fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'z3'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'tests/fixtures/native-image-shared-transport')}


class NativeImageSharedTransportTests(unittest.TestCase):
    def test_retained_namespace_matches_original_image(self):
        authority = json.loads((NATIVE_FIXTURE/'reference-authority.json').read_text())
        self.assertEqual(authority['bindings']['original_pe_sha256'],
                         '685989bad8d8119eddbb49e36006d8ac9155c45d69dee060807368241c8e58ce')
        self.assertEqual(len(authority['rules']), 4)
        self.assertEqual(hashlib.sha256((NATIVE_FIXTURE/'reference-authority.json').read_bytes()).hexdigest(),
                         'a3b250527dd5006b3175e6511f7c5bef37a5a8b72aaa71fd706ad29bcc1d3fdc')

    def test_actual_namespace_and_generated_logical_consumer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_image_logical_fixture(root)
            compiled = subprocess.run([shutil.which('cc'), '-std=c11', str(source), '-o', str(root/'exercise')],
                text=True, capture_output=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            ran = subprocess.run([str(root/'exercise')], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)

    def test_alias_contents_and_corruption_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            source = write_image_logical_fixture(Path(directory))
            solver = bind_smt_solver(Path(shutil.which('z3')))
            for mutation in range(12):
                with self.subTest(mutation=mutation):
                    result = run_cbmc_properties(command=[shutil.which('cbmc'), str(source),
                        f'-DSPX_TEST_MUTATION={mutation}', '--json-ui', '--unwind', '32', '--object-bits', '12',
                        '--unwinding-assertions', '--pointer-check', '--bounds-check',
                        '--signed-overflow-check', '--undefined-shift-check', '--div-by-zero-check',
                        *solver_arguments(solver)], timeout_seconds=60)
                    self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_removing_native_image_admission_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = write_image_logical_fixture(Path(directory))
            text = source.read_text()
            guard = ('rule->locator_offset > context->image_size ||\n'
                     '        rule->extent > context->image_size - rule->locator_offset ||')
            self.assertEqual(text.count(guard), 1)
            source.write_text(text.replace(guard, '0 ||'))
            result = run_cbmc_properties(command=[shutil.which('cbmc'), str(source),
                '-DSPX_TEST_MUTATION=0', '--json-ui', '--unwind', '32', '--object-bits', '12', '--unwinding-assertions',
                '--pointer-check', '--bounds-check', '--signed-overflow-check',
                '--undefined-shift-check', '--div-by-zero-check',
                *solver_arguments(bind_smt_solver(Path(shutil.which('z3'))))], timeout_seconds=60)
            self.assertEqual(result['status'], 'violated', result.get('detail'))
