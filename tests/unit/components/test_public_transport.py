"""Current-memory cut transport must not forget bytes or invent zero contents."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_public_transport import (
    cleanup_public_transport_domain, render_public_transport, check_public_transport,
    public_transport_statements,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-entry/public-memory-excerpts.json'
TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('tests/fixtures/metapad-cleanup-entry',)}


class PublicTransportTests(unittest.TestCase):
    def query(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'model.c').write_text(source)
            subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', 'model.c',
                '--function', 'check_admission', '-o', 'model.goto'], cwd=root, capture_output=True, check=True)
            result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function',
                'check_admission', *checker_options(20, None)], cwd=root, timeout_seconds=60, output_prefix=root/'query')
            raw = json.loads((root/'query.stdout').read_text())
            failures = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
            return result, failures

    def test_arbitrary_current_bytes_and_nonempty_domain(self):
        source = render_public_transport(); check_public_transport(source)
        result, failures = self.query(source)
        self.assertEqual(result['status'], 'satisfied', failures)
        self.assertGreaterEqual(result['properties'], 10)
        witness = source.removesuffix('}\n')+' __CPROVER_assert(0,"public-domain-nonempty");\n}\n'
        result, failures = self.query(witness)
        self.assertEqual(result['status'], 'violated')
        self.assertEqual(failures, {'public-domain-nonempty'})

    def test_fresh_unrelated_memory_cannot_replace_predecessor_contents(self):
        source = render_public_transport().replace('static uint8_t rebased_byte',
            'uint8_t __CPROVER_uninterpreted_fresh_byte(uint32_t);\nstatic uint8_t rebased_byte')
        source = source.replace('return __CPROVER_uninterpreted_current_byte(address);',
            'return __CPROVER_uninterpreted_fresh_byte(address);')
        result, failures = self.query(source)
        self.assertEqual(result['status'], 'violated')
        self.assertIn('public-cut-whole-current-memory', failures)

    def test_zero_overlay_requires_a_checked_predecessor_guarantee(self):
        source = render_public_transport()
        assumption, = [s for s in public_transport_statements() if s.startswith('__CPROVER_assume(!')]
        source = source.replace(assumption, '')
        result, failures = self.query(source)
        self.assertEqual(result['status'], 'violated')
        self.assertIn('public-cut-whole-current-memory', failures)

    def test_overwriting_one_byte_outside_the_suffix_breaks_transport(self):
        source = render_public_transport().replace('(uint64_t)address<(uint64_t)scratch+extent',
            '(uint64_t)address<=(uint64_t)scratch+extent')
        result, failures = self.query(source)
        self.assertEqual(result['status'], 'violated')
        self.assertIn('public-cut-whole-current-memory', failures)

    def test_checked_regional_guarantees_and_consumer_premises_are_required(self):
        models = json.loads(FIXTURE.read_text())['model_excerpts']
        domain = cleanup_public_transport_domain(models)
        self.assertEqual(domain['edges'], [['entry', 'loop'], ['loop', 'loop'], ['loop', 'tail']])
        for role, old, new in [('entry', 'entry-consumer-zero-suffix', 'missing-zero-suffix'),
                ('loop', 'input<text_extent', 'input<=text_extent'),
                ('tail', 'return 0U;', 'return 1U;'),
                ('loop', 'loop-whole-post-memory', 'missing-post-memory')]:
            with self.subTest(role=role, old=old):
                changed = deepcopy(models); changed[role] = changed[role].replace(old, new)
                with self.assertRaisesRegex(ValueError, 'public-memory clause'):
                    cleanup_public_transport_domain(changed)

    def test_import_rejects_changed_recipe_or_an_extra_assumption(self):
        source = render_public_transport()
        with self.assertRaisesRegex(ValueError, 'recipe changed'):
            check_public_transport(source.replace('return 0U;', 'return 1U;'))
        with self.assertRaisesRegex(ValueError, 'predicates changed'):
            check_public_transport(source.replace(' __CPROVER_assume(text_address',
                ' __CPROVER_assume(0);\n __CPROVER_assume(text_address'))


if __name__ == '__main__':
    unittest.main()
