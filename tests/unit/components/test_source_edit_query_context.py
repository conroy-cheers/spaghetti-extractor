"""Actual CBMC instrumentation must preserve property sites and unwind counters."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_source_edit import prepare_pure_region_comparison
from spaghetti_extractor.components.bisimulation_source_edit_query_context import (
    compare_processed_query_context, summarize_processed_query_context,
)

TESTKIT = {'fixtures': ('cbmc', 'compiler')}
MARKERS = {'entry': 'region_entry', 'lookahead': 'region_lookahead', 'tail': 'region_tail'}
SOURCE = '''unsigned int shared_count;
void region_entry(void) {}
void region_lookahead(void) {}
void region_tail(void) {}
unsigned int cleanup(unsigned char a) {
  for (unsigned int i = 0; i < a; ++i) shared_count += 1;
  region_entry();
  BODY
  region_lookahead();
  __CPROVER_assert(a != 0, "nonzero exit");
  return shared_count;
tail:;
  region_tail();
  __CPROVER_assert(a == 0, "zero exit");
  return 0;
}
void caller(unsigned char a) { cleanup(a); cleanup(0); }
'''


class SourceEditQueryContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler, cls.cbmc, cls.instrument = [shutil.which(v) for v in ('goto-cc', 'cbmc', 'goto-instrument')]
        if not all((cls.compiler, cls.cbmc, cls.instrument)):
            raise unittest.SkipTest('compiler/CBMC fixtures unavailable')
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        cls.models, cls.symbols, cls.processed, raw = {}, {}, {}, {}
        for side in ('baseline', 'baseline-marked', 'edited', 'edited-marked'):
            source = SOURCE.replace('BODY', 'int has_byte = a != 0; if (!has_byte) goto tail;'
                                    if side.startswith('edited') else 'if (!a) goto tail;')
            if not side.endswith('marked'):
                for marker in MARKERS.values():
                    source = source.replace('void ' + marker + '(void) {}\n', '').replace('  ' + marker + '();\n', '')
            c, model = root / (side + '.c'), root / (side + '.goto')
            c.write_text(source)
            subprocess.run([cls.compiler, '--i386-win32', str(c), '-o', str(model)], check=True, capture_output=True)
            args = [cls.cbmc, str(model), '--json-ui', '--function', 'caller', '--unwind', '3', '--no-unwinding-assertions']
            functions = cls.inventory([*args, '--show-goto-functions'], 'functions')
            loops = cls.inventory([*args, '--show-loops'], 'loops')
            cls.processed[side] = (functions, loops)
            cls.models[side] = summarize_processed_query_context(functions, loops, function='cleanup', markers=MARKERS)
            if side.endswith('marked'):
                cls.symbols[side] = cls.inventory([cls.instrument, '--json-ui', '--show-symbol-table', str(model)], 'symbolTable')
                raw[side] = {v['name']: v for v in cls.inventory([cls.instrument, '--json-ui', '--show-goto-functions', str(model)], 'functions')}
        cls.comparison = prepare_pure_region_comparison(original_functions=raw['baseline-marked'],
            original_symbols=cls.symbols['baseline-marked'], edited_functions=raw['edited-marked'],
            edited_symbols=cls.symbols['edited-marked'], function='cleanup', entry=MARKERS['entry'],
            exits={k:v for k,v in MARKERS.items() if k != 'entry'})['source']

    @staticmethod
    def inventory(command, field):
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return next(v[field] for v in json.loads(result.stdout) if field in v)

    def compare(self, models=None, source=None):
        return compare_processed_query_context(self.models if models is None else models, self.symbols,
            function='cleanup', markers=MARKERS, checked_source=self.comparison if source is None else source)

    def test_actual_instrumented_predicates_and_loop_counters_match(self):
        result = self.compare()
        self.assertEqual(result['status'], 'matched-processed-query-context')
        self.assertIn('cleanup.0', result['loop_ids'])
        self.assertIn('cleanup.assertion.1', result['property_ids'])
        self.assertFalse(result['authorizing'])

    def test_same_property_name_with_changed_predicate_is_rejected(self):
        models = deepcopy(self.models)
        for side in ('edited', 'edited-marked'):
            functions, loops = deepcopy(self.processed[side])
            cleanup = next(v for v in functions if v['name'] == 'cleanup')
            row = next(v for v in cleanup['instructions'] if v['sourceLocation'].get('propertyId') == 'cleanup.assertion.1')
            row['guard'] = {'id': 'constant', 'namedSub': {'type': {'id': 'bool'}, 'value': {'id': 'false'}}}
            models[side] = summarize_processed_query_context(functions, loops, function='cleanup', markers=MARKERS)
        with self.assertRaisesRegex(ValueError, 'context outside region differs'):
            self.compare(models)

    def test_property_renumbering_cannot_borrow_old_selected_ids(self):
        functions, loops = deepcopy(self.processed['edited-marked'])
        cleanup = next(v for v in functions if v['name'] == 'cleanup')
        row = next(v for v in cleanup['instructions'] if v['instructionId'] == 'ASSERT')
        row['sourceLocation']['propertyId'] = 'cleanup.assertion.999'
        models = dict(self.models)
        models['edited-marked'] = summarize_processed_query_context(functions, loops, function='cleanup', markers=MARKERS)
        with self.assertRaisesRegex(ValueError, 'marker erasure differs'):
            self.compare(models)

    def test_changed_loop_inventory_cannot_reuse_same_unwindset(self):
        functions, loops = deepcopy(self.processed['edited-marked'])
        loops[0]['name'] += '.changed'
        with self.assertRaisesRegex(ValueError, 'loop sites differ'):
            summarize_processed_query_context(functions, loops, function='cleanup', markers=MARKERS)

    def test_different_local_proof_cannot_supply_the_premise(self):
        with self.assertRaisesRegex(ValueError, 'local query differs'):
            self.compare(source=self.comparison.replace('original_port == edited_port', '1'))

    def test_missing_model_cannot_omit_marker_erasure(self):
        models = dict(self.models)
        del models['edited']
        with self.assertRaisesRegex(ValueError, 'model coverage differs'):
            self.compare(models)

    def test_same_loop_id_with_changed_backward_target_is_rejected(self):
        models = deepcopy(self.models)
        for side in ('edited', 'edited-marked'):
            functions, loops = deepcopy(self.processed[side])
            cleanup = next(v for v in functions if v['name'] == 'cleanup')
            rows = cleanup['instructions']
            locations = {row['locationNumber']: i for i, row in enumerate(rows)}
            branch = next(row for i, row in enumerate(rows) if row['instructionId'] == 'GOTO'
                          and any(locations[v] <= i for v in row['targets']))
            self.assertNotEqual(branch['targets'], [rows[0]['locationNumber']])
            branch['targets'] = [rows[0]['locationNumber']]
            models[side] = summarize_processed_query_context(functions, loops, function='cleanup', markers=MARKERS)
        with self.assertRaisesRegex(ValueError, 'context outside region differs'):
            self.compare(models)

    def test_acyclic_local_backward_jump_still_changes_unwind_counters(self):
        root = Path(self.directory.name)
        c, model = root / 'acyclic.c', root / 'acyclic.goto'
        c.write_text(SOURCE.replace('BODY', 'goto forward; back:; if (!a) goto tail; '
                                   'goto after; forward:; goto back; after:;'))
        subprocess.run([self.compiler, '--i386-win32', str(c), '-o', str(model)], check=True, capture_output=True)
        args = [self.cbmc, str(model), '--json-ui', '--function', 'caller', '--unwind', '3', '--no-unwinding-assertions']
        functions = self.inventory([*args, '--show-goto-functions'], 'functions')
        loops = self.inventory([*args, '--show-loops'], 'loops')
        with self.assertRaisesRegex(ValueError, 'bounded backward GOTO'):
            summarize_processed_query_context(functions, loops, function='cleanup', markers=MARKERS)
