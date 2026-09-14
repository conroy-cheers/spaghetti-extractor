"""Compiler-backed checks for experimental cut-local dependency inventory."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.unit.components.source_region_calls import match_source_region_calls, source_region_calls

TESTKIT = {'fixtures': ('cbmc', 'compiler')}

PRELUDE = '''typedef unsigned int uint32_t;
#define CUT(id) do { uint32_t __CPROVER_spx_local_sync_##id = 0; } while (0)
int read_byte(int);
int run(int value) {
  CUT(entry);
'''


class SourceRegionCallsTests(unittest.TestCase):
    def check(self, source, *, prelude=PRELUDE):
        if not all(shutil.which(t) for t in ('goto-cc','goto-instrument')):
            self.skipTest('compiler fixtures unavailable')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'source.c').write_text(prelude+source+'\n}\n')
            command = [shutil.which('goto-cc'),'--i386-win32',str(root/'source.c'),'-o',str(root/'model.goto')]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            inventories = []
            for flag, field in [('--show-goto-functions','functions'),('--show-symbol-table','symbolTable')]:
                result = subprocess.run([shutil.which('goto-instrument'),flag,'--json-ui',str(root/'model.goto')],
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                rows = [v[field] for v in json.loads(result.stdout) if field in v]
                self.assertEqual(len(rows), 1)
                inventories.append(rows[0])
        functions, symbols = inventories
        return source_region_calls(functions={v['name']:v for v in functions},symbols=symbols,
                                   function='run',entry_sync='entry')

    def test_both_successors_and_early_return_are_preserved(self):
        result = self.check('''value = read_byte(value);
if (value < 0) return -1;
if (value) { CUT(next); return 1; }
CUT(tail); return 0;''')
        self.assertEqual([v['callee'] for v in result['calls']], ['read_byte'])
        self.assertEqual({v[0] for v in result['exits']}, {'cut','return'})
        self.assertEqual({v[1] for v in result['exits'] if v[0]=='cut'}, {'next','tail'})
        self.assertFalse(result['call_contracts_checked'])

    def test_extra_call_is_a_new_dependency_but_calls_beyond_cut_are_excluded(self):
        result = self.check('''value=read_byte(value);
if (value) value=read_byte(value+1);
CUT(next); return read_byte(value);''')
        self.assertEqual(len(result['calls']), 2)
        self.assertEqual(result['exits'], [('cut','next')])

    def test_internal_cycle_cannot_reuse_one_invocation_contract(self):
        with self.assertRaisesRegex(ValueError, 'repeated-call/progress'):
            self.check('while (value) value=read_byte(value); CUT(next); return 0;')

    def test_returning_to_the_entry_cut_starts_a_new_region(self):
        result = self.check('value=read_byte(value); if (value) goto again; CUT(next); return value;',
                            prelude=PRELUDE.replace('  CUT(entry);', 'again: CUT(entry);'))
        self.assertEqual(len(result['calls']), 1)
        self.assertTrue(result['acyclic'])
        self.assertEqual(result['exits'], [('cut','entry'),('cut','next')])

    def test_indirect_call_needs_target_and_contract_evidence(self):
        with self.assertRaisesRegex(ValueError, 'indirect call'):
            self.check('int (*callback)(int)=read_byte; value=callback(value); CUT(next); return value;')

    def test_source_assumption_cannot_prune_dependencies(self):
        with self.assertRaisesRegex(ValueError, 'unsupported source instruction ASSUME'):
            self.check('__CPROVER_assume(0); value=read_byte(value); CUT(next); return value;')

    def test_marker_initializer_cannot_hide_an_effect(self):
        with self.assertRaisesRegex(ValueError, 'marker prelude shape'):
            self.check('CUT(next); return value;', prelude=PRELUDE.replace(' = 0;', ' = read_byte(value);'))

    def test_linear_region_has_no_python_recursion_limit(self):
        result = self.check('value=read_byte(value);\n'+'value += 1;\n'*1200+'CUT(next); return value;')
        self.assertEqual(len(result['calls']), 1)
        self.assertGreater(len(result['instruction_indices']), 1200)

    def test_volatile_marker_is_not_an_erasable_scope_token(self):
        with self.assertRaisesRegex(ValueError, 'private uint32 storage'):
            self.check('CUT(next); return value;', prelude=PRELUDE.replace('do { uint32_t', 'do { volatile uint32_t'))

    def test_added_invocation_requires_new_qualification(self):
        baseline = self.check('value=read_byte(value); CUT(next); return value;')
        edited = self.check('value=read_byte(value); value=read_byte(value); CUT(next); return value;')
        prefix_calls = [v['payload'] for v in baseline['calls']]
        result = match_source_region_calls(baseline, prefix_calls=prefix_calls)
        self.assertEqual(len(result['matches']), 1)
        self.assertFalse(result['call_contracts_checked'])
        with self.assertRaisesRegex(ValueError, 'missing invocation qualification'):
            match_source_region_calls(edited, prefix_calls=prefix_calls)

    def test_changed_arguments_do_not_inherit_same_signature_qualification(self):
        baseline = self.check('value=read_byte(value); CUT(next); return value;')
        edited = self.check('value=read_byte(value+1); CUT(next); return value;')
        with self.assertRaisesRegex(ValueError, 'missing invocation qualification'):
            match_source_region_calls(edited, prefix_calls=[v['payload'] for v in baseline['calls']])

    def test_identical_payload_cannot_spend_one_occurrence_twice(self):
        region = self.check('value=read_byte(value); CUT(next); return value;')
        call = region['calls'][0]
        region['calls'].append(dict(call, instruction_index=call['instruction_index']+1))
        with self.assertRaisesRegex(ValueError, 'missing invocation qualification'):
            match_source_region_calls(region, prefix_calls=[call['payload']])

    def test_removed_call_invalidates_exact_invocation_inventory(self):
        baseline = self.check('value=read_byte(value); CUT(next); return value;')
        edited = self.check('CUT(next); return value;')
        with self.assertRaisesRegex(ValueError, 'unused prefix invocation'):
            match_source_region_calls(edited, prefix_calls=[v['payload'] for v in baseline['calls']])
