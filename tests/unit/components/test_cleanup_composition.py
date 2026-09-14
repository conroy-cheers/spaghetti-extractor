"""Real regional scopes, topology and private frames bind the composition rule."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_cleanup_composition import cleanup_control_domain, TEMPLATE
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-composition/inputs.json'
TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('tests/fixtures/metapad-cleanup-composition',)}


class CleanupCompositionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text())

    def domain(self):
        x = self.fixture
        return cleanup_control_domain(x['postambles'], x['contracts'], x['graph'], x['private_transport'])

    def query(self, source=TEMPLATE):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'admission.c').write_text(source)
            process = subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', 'admission.c',
                '--function', 'check_admission', '-o', 'model.goto'], cwd=root, capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function',
                'check_admission', *checker_options(20, None)], cwd=root, timeout_seconds=60, output_prefix=root/'query')
            raw = json.loads((root/'query.stdout').read_text())
            failed = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
            return result, failed

    def test_actual_scoped_guarantees_cover_the_loop_and_normal_return_frame(self):
        domain = self.domain()
        self.assertEqual(domain['edges'], [['entry', 'loop'], ['loop', 'loop'], ['loop', 'tail']])
        self.assertEqual(len(domain['source_cover']), 7)
        self.assertEqual({k: [v['low'], v['high']] for k, v in domain['saved_word_transport'].items()},
                         {'ebp': [-4, 0], 'ebx': [-24, -20], 'esi': [-28, -24], 'return_word': [0, 4]})
        result, failures = self.query()
        self.assertEqual(result['status'], 'satisfied', failures)
        self.assertNotIn('authored.c', TEMPLATE)

    def test_changed_guard_or_weakened_progress_cannot_keep_the_same_property_label(self):
        original = deepcopy(self.fixture)
        for role, old, new in [
            ('entry', 'if(result!=UINT32_MAX){', 'if(result==UINT32_MAX){'),
            ('loop', 'state.esi>input && state.esi<text_extent', 'state.esi>=input && state.esi<text_extent'),
            ('tail', '__CPROVER_assert((step.kind==SPX_MEMORY_FAULT)',
             'if(result!=UINT32_MAX)__CPROVER_assert((step.kind==SPX_MEMORY_FAULT)')]:
            with self.subTest(role=role):
                self.fixture = deepcopy(original); source = self.fixture['postambles'][role]
                changed = source.replace(old, new); self.assertNotEqual(source, changed)
                self.fixture['postambles'][role] = changed
                with self.assertRaisesRegex(ValueError, 'scoped guarantee'):
                    self.domain()

    def test_new_post_call_assumptions_or_effects_reject(self):
        for statement in ['__CPROVER_assume(input==0U);', 'state.esi=0U;', 'while(1){}']:
            with self.subTest(statement=statement):
                self.setUp()
                source = self.fixture['postambles']['loop']
                self.fixture['postambles']['loop'] = source.replace(
                    '__CPROVER_assert((step.kind', statement+'__CPROVER_assert((step.kind', 1)
                with self.assertRaisesRegex(ValueError, 'unsupported assumption, effect or control'):
                    self.domain()

    def test_missing_duplicate_foreign_and_interior_control_ownership_reject(self):
        for change in ['missing', 'duplicate', 'foreign', 'interior', 'foreign-interior']:
            with self.subTest(change=change):
                self.setUp(); x = self.fixture
                if change == 'missing':
                    x['contracts']['tail']['regions'].remove('tail_iteration')
                elif change == 'duplicate':
                    x['contracts']['loop']['regions'].append('prefix_iter')
                elif change == 'foreign':
                    next(n for n in x['graph']['regions'] if n['entry'] == 'advance')['exits'] = [['cut', 'entry']]
                elif change == 'interior':
                    next(n for n in x['graph']['regions'] if n['entry'] == 'copy')['exits'] = [['cut', 'tail_iteration']]
                else:
                    loop = next(n for n in x['graph']['regions'] if n['entry'] == 'loop')
                    x['graph']['regions'][0]['external_interior_entries'].append({
                        'source_instruction': loop['instruction_indices'][0], 'target_instruction': 24})
                with self.assertRaisesRegex(ValueError, 'cleanup .*control'):
                    self.domain()

    def test_saved_word_relocation_and_loop_overlap_reject(self):
        for change in ['relocation', 'overlap', 'missing']:
            with self.subTest(change=change):
                self.setUp(); layouts = self.fixture['private_transport']['layouts']
                if change == 'relocation':
                    next(c for c in layouts['tail']['cells'] if c['field'] == 'word_11')['offset'] += 1
                elif change == 'overlap':
                    layouts['loop']['cells'][0]['offset'] = -16
                else:
                    self.fixture['private_transport']['saved_frame']['esi'][0] = 'missing'
                with self.assertRaisesRegex(ValueError, 'cleanup .*saved'):
                    self.domain()

    def test_stuttering_loop_and_wrong_stack_coordinate_have_counterexamples(self):
        for old, new, expected in [
            ('after_input>input', 'after_input>=input', 'cleanup-composed-strict-rank'),
            ('loop_stack=stack-12U', 'loop_stack=stack-8U', 'cleanup-composed-return-stack'),
            ('removed==input-output', 'removed==input-output+1U', 'cleanup-normal-result-not-fault-sentinel')]:
            with self.subTest(change=new):
                result, failures = self.query(TEMPLATE.replace(old, new))
                self.assertEqual(result['status'], 'violated', failures)
                self.assertIn(expected, failures)


if __name__ == '__main__':
    unittest.main()
