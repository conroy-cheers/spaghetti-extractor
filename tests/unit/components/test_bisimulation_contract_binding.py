"""Compiled contract clauses must be bound even when the C signature is unchanged."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.unit.components.compiled_contract_binding import check_compiled_contract_identity
from spaghetti_extractor.components.bisimulation_entry_conformance import _semantic
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError


TESTKIT = {'fixtures': ('cbmc', 'compiler')}
SOURCE = '''struct view { unsigned int extent; struct view *next; };
static unsigned int input_word;
static unsigned int observed;
unsigned int read_byte(const struct view *view, unsigned char *out)
__CPROVER_requires(__CPROVER_r_ok(view, sizeof(*view)) && __CPROVER_w_ok(out, 1))
__CPROVER_requires(view->extent > 0)
__CPROVER_ensures(*out == (unsigned char)__CPROVER_old(input_word))
__CPROVER_ensures(observed == 1)
__CPROVER_assigns(*out, observed);
unsigned int read_byte(const struct view *view, unsigned char *out) {
  *out = input_word; observed = 1; return 0;
}
'''


class CompiledContractBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler, cls.instrument = shutil.which('goto-cc'), shutil.which('goto-instrument')
        if not cls.compiler or not cls.instrument:
            raise unittest.SkipTest('GOTO compiler is unavailable')
        cls.baseline = cls.compile(SOURCE)

    @classmethod
    def compile(cls, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'model.c').write_text(source)
            r = subprocess.run([cls.compiler, '--i386-win32', '-std=c11', str(root / 'model.c'),
                                '-o', str(root / 'model.goto')], capture_output=True, text=True, timeout=30)
            if r.returncode:
                raise AssertionError(r.stderr)
            r = subprocess.run([cls.instrument, '--show-symbol-table', '--json-ui', str(root / 'model.goto')],
                               capture_output=True, text=True, timeout=30)
            if r.returncode:
                raise AssertionError(r.stderr)
            return next(b['symbolTable'] for b in json.loads(r.stdout) if 'symbolTable' in b)

    def check(self, symbols=None):
        return check_compiled_contract_identity(qualified_symbols=self.baseline,
            consumer_symbols=self.baseline if symbols is None else symbols, function='read_byte')

    def test_actual_clause_symbols_are_bound_separately_from_signature(self):
        result = self.check()
        self.assertEqual(result['clause_counts'], {'assigns': 2, 'ensures': 2, 'frees': 0, 'requires': 2})
        self.assertEqual({v['symbol'] for v in result['storage_dependencies']}, {'input_word', 'observed'})
        self.assertEqual(set(result['aggregate_definitions']), {'tag-view'})
        self.assertNotEqual(result['signature_sha256'], result['contract_sha256'])
        for key in ('authorizing', 'callee_body_checked', 'input_domain_checked', 'theorem_import_authorized'):
            self.assertFalse(result[key])

    def test_body_growth_and_source_locations_do_not_change_contract_identity(self):
        grown = self.compile('\n' * 10 + SOURCE.replace('*out = input_word;', 'unsigned int x = 0; ' +
            'for (unsigned int i = 0; i < 100; ++i) x += i; *out = input_word + x;'))
        self.assertEqual(self.check(grown), self.check())

    def test_requires_change_with_identical_signature_is_rejected(self):
        changed = self.compile(SOURCE.replace('view->extent > 0', 'view->extent > 1'))
        self.assertEqual(_semantic(self.baseline['read_byte']['type']), _semantic(changed['read_byte']['type']))
        with self.assertRaisesRegex(BisimulationRefinementError, 'contract clauses differ'):
            self.check(changed)

    def test_postcondition_change_with_identical_signature_is_rejected(self):
        changed = self.compile(SOURCE.replace('__CPROVER_ensures(observed == 1)', '__CPROVER_ensures(observed == 0)'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'contract clauses differ'):
            self.check(changed)

    def test_extra_frame_target_is_rejected(self):
        changed = self.compile(SOURCE.replace('__CPROVER_assigns(*out, observed)', '__CPROVER_assigns(*out, observed, input_word)'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'contract clauses differ'):
            self.check(changed)

    def test_frees_clause_change_is_rejected(self):
        changed = self.compile(SOURCE.replace('__CPROVER_assigns(*out, observed);', '__CPROVER_assigns(*out, observed)\n__CPROVER_frees(out);'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'contract clauses differ'):
            self.check(changed)

    def test_missing_contract_symbol_is_rejected(self):
        changed = deepcopy(self.baseline)
        del changed['contract::read_byte']
        with self.assertRaisesRegex(BisimulationRefinementError, 'missing compiled contract'):
            self.check(changed)

    def test_missing_dependency_declaration_is_rejected(self):
        changed = deepcopy(self.baseline)
        del changed['input_word']
        with self.assertRaisesRegex(BisimulationRefinementError, 'missing contract dependency'):
            self.check(changed)

    def test_changed_storage_linkage_is_rejected(self):
        changed = self.compile(SOURCE.replace('static unsigned int input_word;', 'unsigned int input_word;'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'dependency declaration differs'):
            self.check(changed)

    def test_unmentioned_aggregate_field_type_change_is_rejected(self):
        changed = self.compile(SOURCE.replace('struct view *next;', 'unsigned int next;'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'aggregate definition differs'):
            self.check(changed)

    def test_contract_helper_needs_its_own_semantic_binding(self):
        changed = self.compile(SOURCE.replace('static unsigned int observed;',
            'static unsigned int observed;\nint predicate(unsigned int);').replace('view->extent > 0', 'predicate(view->extent)'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'helper needs separate semantic binding'):
            check_compiled_contract_identity(qualified_symbols=changed, consumer_symbols=changed, function='read_byte')

    def test_transitive_pointee_definition_is_bound(self):
        source = 'struct inner { unsigned int version; };\n' + SOURCE.replace(
            'struct view *next;', 'struct view *next; struct inner *detail;')
        original = self.compile(source)
        changed = self.compile(source.replace('unsigned int version', 'unsigned long long version'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'aggregate definition differs: tag-inner'):
            check_compiled_contract_identity(qualified_symbols=original, consumer_symbols=changed, function='read_byte')

    def test_indirect_predicate_cannot_bypass_helper_binding(self):
        changed = self.compile(SOURCE.replace('static unsigned int observed;',
            'static unsigned int observed;\nint (*predicate_ptr)(unsigned int);').replace(
            'view->extent > 0', 'predicate_ptr(view->extent)'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'helper needs separate semantic binding'):
            check_compiled_contract_identity(qualified_symbols=changed, consumer_symbols=changed, function='read_byte')

    def test_enum_definition_is_bound_through_aggregate_fields(self):
        source = 'enum state { READY = 0, DONE = 1 };\n' + SOURCE.replace(
            'struct view *next;', 'struct view *next; enum state state;')
        original = self.compile(source)
        changed = self.compile(source.replace('DONE = 1', 'DONE = 2'))
        with self.assertRaisesRegex(BisimulationRefinementError, 'aggregate definition differs: tag-state'):
            check_compiled_contract_identity(qualified_symbols=original, consumer_symbols=changed, function='read_byte')

    def test_global_initialization_requires_separate_domain_evidence(self):
        changed = self.compile(SOURCE.replace('static unsigned int input_word;', 'static unsigned int input_word = 7;'))
        result = self.check(changed)
        self.assertEqual(result, self.check())
        self.assertFalse(result['input_domain_checked'])
