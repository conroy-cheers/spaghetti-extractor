"""Compiler-backed prefix composition and fail-closed call-dependency controls."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_source_edit import prepare_pure_region_comparison
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

TESTKIT = {'fixtures': ('cbmc', 'compiler')}
SOURCE = '''unsigned int shared_word;
unsigned int read_byte(unsigned char *out, unsigned int index) {
  *out = (unsigned char)(shared_word + index);
  shared_word += 1U;
  return shared_word == 0U;
}
void region_entry(void) {}
void region_lookahead(void) {}
void region_tail(void) {}
unsigned int cleanup(unsigned int index) {
  unsigned char a;
  region_entry();
  PREFIX
  BODY
  region_lookahead();
  return a + 4U;
tail:;
  region_tail();
  return 0U;
}
'''
PREFIX = 'if (read_byte(&a, index)) return 9U;'
BASE = 'if (!a) goto tail;'
EDIT = 'int has_byte = a != 0U; if (!has_byte) goto tail;'


class SourceEditPrefixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler, cls.instrument, cls.cbmc = [shutil.which(v) for v in ('goto-cc', 'goto-instrument', 'cbmc')]
        if not all((cls.compiler, cls.instrument, cls.cbmc)):
            raise unittest.SkipTest('compiler and CBMC fixtures unavailable')
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.models = {}
        cases = {
            'baseline': (PREFIX, BASE), 'edited': (PREFIX, EDIT),
            'wrong': (PREFIX, EDIT.replace('!has_byte', 'has_byte')),
            'argument': (PREFIX.replace('index)', 'index + 1U)'), EDIT),
            'extra-call': (PREFIX + ' read_byte(&a, index);', EDIT),
            'failure-result': (PREFIX.replace('9U', '8U'), EDIT),
            'failure-condition': (PREFIX.replace('if (read_byte', 'if (!read_byte'), EDIT),
            'transient-write': (PREFIX, 'shared_word ^= 1U; shared_word ^= 1U; ' + EDIT),
            'grown-baseline': (PREFIX, BASE), 'grown-edited': (PREFIX, EDIT),
        }
        for name, (prefix, body) in cases.items():
            folder = cls.root / name
            folder.mkdir()
            text = SOURCE.replace('PREFIX', prefix).replace('BODY', body)
            if name.startswith('grown-'):
                text = text.replace('  shared_word += 1U;', '  shared_word += 1U;\n' * 80)
            c, model = folder / 'source.c', folder / 'model.goto'
            c.write_text(text)
            cls.run_tool([cls.compiler, '--i386-win32', str(c), '-o', str(model)])
            values = {}
            for key, flag, field in [('functions', '--show-goto-functions', 'functions'), ('symbols', '--show-symbol-table', 'symbolTable')]:
                data = json.loads(cls.run_tool([cls.instrument, flag, '--json-ui', str(model)]))
                value = next(b[field] for b in data if field in b)
                values[key] = {v['name']: v for v in value} if key == 'functions' else value
            cls.models[name] = values

    @staticmethod
    def run_tool(command):
        r = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise AssertionError(r.stderr)
        return r.stdout

    def prepare(self, name='edited', baseline='baseline', model=None):
        a, b = self.models[baseline], self.models[name] if model is None else model
        return prepare_pure_region_comparison(original_functions=a['functions'], original_symbols=a['symbols'],
            edited_functions=b['functions'], edited_symbols=b['symbols'], function='cleanup', entry='region_entry',
            exits={'lookahead': 'region_lookahead', 'tail': 'region_tail'})

    def solve(self, name):
        prepared = self.prepare(name)
        root = self.root / name
        (root / 'comparison.c').write_text(prepared['source'])
        self.run_tool([self.compiler, '--i386-win32', str(root / 'comparison.c'), '-o', str(root / 'comparison.goto')])
        result = run_cbmc_properties(command=[self.cbmc, str(root / 'comparison.goto'), '--function', 'compare_regions',
            '--json-ui', '--bounds-check', '--pointer-check', '--signed-overflow-check', '--undefined-shift-check',
            '--div-by-zero-check', '--unwinding-assertions'], timeout_seconds=30)
        return prepared, result

    def test_mutable_read_and_failure_prefix_preserved_before_universal_edit(self):
        prepared, result = self.solve('edited')
        self.assertEqual(result['status'], 'satisfied')
        prefix = prepared['binding']['common_prefix']
        self.assertEqual(prefix['completed_ports'], ['@return'])
        self.assertEqual([v['callee'] for v in prefix['calls']], ['read_byte'])
        self.assertNotIn('read_byte', prepared['source'])
        self.assertFalse(prepared['preexisting_storage_unchanged'])
        self.assertTrue(prepared['common_prefix_effects_preserved'])
        self.assertTrue(prepared['suffix_preexisting_storage_unchanged'])
        self.assertFalse(prefix['callee_summary_claimed'])
        self.assertFalse(prepared['parent_evidence_imported'])

    def test_wrong_suffix_decision_fails_universal_proof(self):
        _, result = self.solve('wrong')
        self.assertEqual(result['status'], 'violated')

    def test_changed_call_argument_cannot_inherit_common_prefix(self):
        with self.assertRaises(ValueError):
            self.prepare('argument')

    def test_extra_call_cannot_be_discarded(self):
        with self.assertRaises(ValueError):
            self.prepare('extra-call')

    def test_changed_failure_result_cannot_be_discarded(self):
        with self.assertRaises(ValueError):
            self.prepare('failure-result')

    def test_changed_failure_guard_cannot_be_discarded(self):
        with self.assertRaises(ValueError):
            self.prepare('failure-condition')

    def test_transient_suffix_memory_write_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'preexisting storage'):
            self.prepare('transient-write')

    def test_local_query_does_not_expand_identical_callee_growth(self):
        small = self.prepare()
        grown = self.prepare('grown-edited', 'grown-baseline')
        self.assertEqual(small['source'], grown['source'])
        # Changing a helper on one side requires its own equivalence evidence.
        with self.assertRaisesRegex(ValueError, 'context helper changed'):
            self.prepare('grown-edited')

    def test_bypassing_the_prefix_frontier_is_rejected(self):
        model = deepcopy(self.models['edited'])
        rows = model['functions']['cleanup']['instructions']
        branch = next(r for r in rows if r['instructionId'] == 'GOTO')
        branch['targets'] = [rows[0]['locationNumber']]
        with self.assertRaises(ValueError):
            self.prepare(model=model)

    def test_feedback_cannot_relabel_common_effects_as_an_empty_frame(self):
        from spaghetti_extractor.components.bisimulation_edit_prefix import comparison_effects_preserved
        comparison = self.prepare()
        self.assertTrue(comparison_effects_preserved(comparison))
        for field, value in [('preexisting_storage_unchanged', True), ('common_prefix_effects_preserved', False),
                             ('suffix_preexisting_storage_unchanged', False)]:
            with self.subTest(field=field):
                changed = deepcopy(comparison)
                changed[field] = value
                self.assertFalse(comparison_effects_preserved(changed))
        for field, value in [('callee_summary_claimed', True), ('incoming_domain_assumed', True), ('calls', [])]:
            with self.subTest(field=field):
                changed = deepcopy(comparison)
                changed['binding']['common_prefix'][field] = value
                self.assertFalse(comparison_effects_preserved(changed))
        comparison['binding']['policy'] = 'pure-scalar-region-comparison-v1'
        comparison['preexisting_storage_unchanged'] = True
        self.assertFalse(comparison_effects_preserved(comparison))
