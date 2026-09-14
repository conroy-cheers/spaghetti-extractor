"""Compiler and solver controls for pure edit composition, including rejection."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.bisimulation_cut_state import _walk
from tests.unit.components.pure_region_comparison import prepare_pure_region_comparison


TESTKIT = {'fixtures': ('cbmc', 'compiler')}
SOURCE = '''void __CPROVER_assume(_Bool);
unsigned int shared_word;
void region_entry(void) {}
void region_lookahead(void) {}
void region_tail(void) {}
unsigned int cleanup(unsigned char a) {
  __CPROVER_assume(1);
  region_entry();
  BODY
  region_lookahead();
  return a + 4U;
tail:;
  region_tail();
  return 0U;
}
unsigned int caller(void) { return cleanup(4); }
'''
BASELINE = 'if (!a) goto tail;'
EDIT = 'int has_byte = a != 0U; if (!has_byte) goto tail;'


class PureRegionComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler, cls.instrument, cls.cbmc = [shutil.which(v) for v in ('goto-cc', 'goto-instrument', 'cbmc')]
        if not all((cls.compiler, cls.instrument, cls.cbmc)):
            raise unittest.SkipTest('compiler/CBMC fixtures unavailable')
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.models = {}
        for name, body in {
            'baseline': BASELINE, 'edited': EDIT,
            'grown-baseline': BASELINE, 'grown-edited': EDIT,
            'wrong': EDIT.replace('!has_byte', 'has_byte'),
            'write': 'a = 0; ' + EDIT,
            'call': 'caller(); ' + EDIT,
            'assume': '__CPROVER_assume(a); ' + EDIT,
            'volatile': EDIT.replace('int has_byte', 'volatile int has_byte'),
            'narrow': 'signed char has_byte = (signed char)a; if (!has_byte) goto tail;',
            'arithmetic': 'int has_byte = a + 1U; if (!has_byte) goto tail;',
            'uninitialized': 'int has_byte; if (a) has_byte = 1; if (!has_byte) goto tail;',
            'cycle': 'again: if (a) goto again; ' + EDIT,
            'wide': 'unsigned int wide = a; int has_byte = wide != 0U; if (!has_byte) goto tail;',
            'shared-read': 'int has_byte = shared_word != 0U; if (!has_byte) goto tail;',
            'transient-write': 'shared_word ^= 1U; shared_word ^= 1U; ' + EDIT,
        }.items():
            folder = cls.root / name
            folder.mkdir()
            source = SOURCE.replace('BODY', body)
            if name.startswith('grown-'):
                source = source.replace('  region_entry();', '  shared_word = 17U;\n' * 12 + '  region_entry();')
            (folder / 'source.c').write_text('unsigned int caller(void);\n' + source)
            cls.run_tool([cls.compiler, '--i386-win32', str(folder / 'source.c'), '-o', str(folder / 'model.goto')])
            model = {}
            for key, field, flag in [('functions', 'functions', '--show-goto-functions'), ('symbols', 'symbolTable', '--show-symbol-table')]:
                data = json.loads(cls.run_tool([cls.instrument, flag, '--json-ui', str(folder / 'model.goto')]))
                value = next(v[field] for v in data if field in v)
                model[key] = {v['name']: v for v in value} if key == 'functions' else value
            cls.models[name] = model

    @staticmethod
    def run_tool(command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout

    def prepare(self, name='edited', model=None):
        a, b = self.models['baseline'], self.models[name] if model is None else model
        return prepare_pure_region_comparison(original_functions=a['functions'], original_symbols=a['symbols'],
            edited_functions=b['functions'], edited_symbols=b['symbols'], function='cleanup', entry='region_entry',
            exits={'lookahead': 'region_lookahead', 'tail': 'region_tail'})

    def solve(self, name):
        result = self.prepare(name)
        folder = self.root / name
        (folder / 'comparison.c').write_text(result['source'])
        self.run_tool([self.compiler, '--i386-win32', str(folder / 'comparison.c'), '-o', str(folder / 'comparison.goto')])
        query = run_cbmc_properties(command=[self.cbmc, str(folder / 'comparison.goto'), '--function', 'compare_regions',
            '--json-ui', '--bounds-check', '--pointer-check', '--signed-overflow-check', '--undefined-shift-check',
            '--div-by-zero-check', '--unwinding-assertions'], timeout_seconds=30)
        return result, query

    def test_universal_branch_edit_passes_with_preserved_existing_storage(self):
        prepared, query = self.solve('edited')
        self.assertEqual(query['status'], 'satisfied')
        self.assertIn('compare_regions.assertion.1', query['property_ids'])
        self.assertEqual(prepared['binding']['inputs'], {'cleanup::a': ('unsignedbv', 8)})
        self.assertTrue(prepared['preexisting_storage_unchanged'])
        self.assertFalse(prepared['authorizing'])
        self.assertFalse(prepared['parent_evidence_imported'])

    def test_changed_exit_is_rejected_by_solver(self):
        _, query = self.solve('wrong')
        self.assertEqual(query['status'], 'violated')

    def test_local_query_is_independent_of_surrounding_instruction_numbers(self):
        original = self.prepare()
        a, b = self.models['grown-baseline'], self.models['grown-edited']
        grown = prepare_pure_region_comparison(original_functions=a['functions'], original_symbols=a['symbols'],
            edited_functions=b['functions'], edited_symbols=b['symbols'], function='cleanup', entry='region_entry',
            exits={'lookahead': 'region_lookahead', 'tail': 'region_tail'})
        self.assertEqual(original['source'], grown['source'])
        self.assertNotEqual(original['binding']['regions'][0]['indices'], grown['binding']['regions'][0]['indices'])
        self.assertNotEqual(original['binding_sha256'], grown['binding_sha256'])
        # Only the universal local query is reusable. The changed surrounding
        # writes still require their own freshly checked context relation.
        self.assertNotEqual(original['binding']['context'], grown['binding']['context'])

    def test_widening_and_two_private_temporaries_are_supported(self):
        _, query = self.solve('wide')
        self.assertEqual(query['status'], 'satisfied')

    def test_assignment_to_preexisting_parameter_needs_a_state_relation(self):
        with self.assertRaisesRegex(ValueError, 'preexisting storage'):
            self.prepare('write')

    def test_calls_need_a_separate_composition_rule(self):
        with self.assertRaisesRegex(ValueError, 'effect or unsupported instruction'):
            self.prepare('call')

    def test_assumption_cannot_remove_a_bad_input(self):
        with self.assertRaisesRegex(ValueError, 'effect or unsupported instruction'):
            self.prepare('assume')

    def test_volatile_private_storage_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'volatile'):
            self.prepare('volatile')

    def test_narrowing_requires_additional_semantics(self):
        with self.assertRaisesRegex(ValueError, 'cast is not value preserving'):
            self.prepare('narrow')

    def test_arithmetic_requires_additional_safety_semantics(self):
        with self.assertRaisesRegex(ValueError, 'unsupported expression'):
            self.prepare('arithmetic')

    def test_partial_initialization_does_not_cover_the_other_branch(self):
        with self.assertRaisesRegex(ValueError, 'definite initialization'):
            self.prepare('uninitialized')

    def test_cycle_requires_a_progress_rule(self):
        with self.assertRaisesRegex(ValueError, 'cycle requires a progress rule'):
            self.prepare('cycle')

    def test_unchanged_context_must_include_other_callers(self):
        model = deepcopy(self.models['edited'])
        rows = model['functions']['caller']['instructions']
        call = next(r for r in rows if r['instructionId'] == 'FUNCTION_CALL')
        next(n for n in _walk(call['code']['sub'][2]) if n.get('id') == 'constant')['namedSub']['value']['id'] = '5'
        with self.assertRaisesRegex(ValueError, 'context helper changed'):
            self.prepare(model=model)

    def test_volatile_existing_input_cannot_be_erased_into_a_scalar(self):
        a, b = deepcopy(self.models['baseline']), deepcopy(self.models['edited'])
        for model in [a, b]:
            model['symbols']['cleanup::a']['type']['namedSub']['#volatile'] = {'id': '1'}
        with self.assertRaisesRegex(ValueError, 'unqualified integer'):
            prepare_pure_region_comparison(original_functions=a['functions'], original_symbols=a['symbols'],
                edited_functions=b['functions'], edited_symbols=b['symbols'], function='cleanup', entry='region_entry',
                exits={'lookahead': 'region_lookahead', 'tail': 'region_tail'})

    def test_shared_read_cannot_be_replaced_by_an_unrelated_input(self):
        with self.assertRaisesRegex(ValueError, 'not an automatic object'):
            self.prepare('shared-read')

    def test_transient_write_is_rejected_even_when_final_memory_matches(self):
        with self.assertRaisesRegex(ValueError, 'preexisting storage'):
            self.prepare('transient-write')
