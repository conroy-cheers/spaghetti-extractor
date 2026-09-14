"""A wrong edit in the authored caller must fail its actual binary-region proof."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.cbmc_backend import bind_smt_solver, run_cbmc_properties, solver_arguments
from .authored_call_region import render_authored_call
from .shared_call_region import FIXTURE as MACHINE
from tests.unit.operator.test_source_call_regions import check, FIXTURE

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'z3'), 'resources': (
    'tests/fixtures/metapad-authored-call', 'tests/fixtures/metapad-resource-callers')}


class AuthoredCallRegionTests(unittest.TestCase):
    def test_actual_authored_call_and_wrong_id_against_original(self):
        for value, expected in ((31, 'satisfied'), (30, 'violated')):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = (FIXTURE/'cleanup.c').read_text().replace('context, 31U);', f'context, {value}U);')
                boundary = json.loads((FIXTURE/'boundary.json').read_text())
                for anchor in [boundary['entry'], *boundary['exits'].values()]:
                    anchor['text'] = anchor['text'].replace('31U', f'{value}U')
                status, feedback, _ = check(root, source, boundary=boundary)
                self.assertEqual(status['status'], 'complete')
                model = render_authored_call(json.loads((MACHINE/'transition.json').read_text()),
                    feedback['source_call_regions'], source_artifacts=root/'regions')
                self.assertNotIn('spx_sub_00001284(', model)
                for file in (root/'regions/0000-ordinary/include').iterdir():
                    shutil.copyfile(file, root/file.name)
                for file in MACHINE.iterdir():
                    if file.suffix in ('.c', '.h'):
                        shutil.copyfile(file, root/file.name)
                (root/'pair.c').write_text(model)
                run = subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', '-I', '.',
                    'pair.c', 'behavioral-fn-00005646.c', 'behavioral-fn-0000570e.c', 'behavioral-support.c',
                    '--function', 'check_call_regions', '-o', 'model.goto'], cwd=root,
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stderr)
                result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function', 'check_call_regions',
                    '--json-ui', '--unwind', '16', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                    '--signed-overflow-check', '--undefined-shift-check', '--div-by-zero-check', '--object-bits', '12',
                    '--no-self-loops-to-assumptions', *solver_arguments(bind_smt_solver(Path(shutil.which('z3')))),
                    '--reachability-slice-fb', '--slice-formula'], cwd=root, timeout_seconds=30)
                self.assertEqual(result['status'], expected, result.get('detail'))
                if expected == 'violated':
                    self.assertIn('caller-dependency-arguments', result['detail'])
