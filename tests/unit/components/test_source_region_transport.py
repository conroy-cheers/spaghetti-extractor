"""Compiler-backed controls for proof-only cut entry and body transport."""

import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tests.unit.components.source_region_transport import check_source_region_transport

TESTKIT = {'fixtures': ('cbmc', 'compiler')}

TYPES = '''typedef unsigned int uint32_t;
typedef unsigned char uint8_t;
int read_byte(uint32_t input, uint8_t *result);
'''
ORDINARY = '''#define BEGIN do { uint32_t __CPROVER_spx_local_begin = 0; } while (0)
#define CUT(id) do { uint32_t __CPROVER_spx_local_sync_##id = 0; } while (0)
'''
LOCAL = '''static struct { uint32_t input; uint8_t a; } spx_cut;
#define BEGIN uint32_t spx_local_entered = 0; goto spx_local_loop
#define CUT(id) LOCAL_##id
#define LOCAL_entry spx_local_loop: do { if (spx_local_entered) return 2U; spx_local_entered=1U; input=spx_cut.input; a=spx_cut.a; __CPROVER_assert(1, "source-cut-invariant"); } while (0)
#define LOCAL_next do { __CPROVER_assert(1, "source-cut-invariant:next"); return 3U; } while (0)
#define LOCAL_tail do { __CPROVER_assert(1, "source-cut-invariant:tail"); return 6U; } while (0)
'''
BODY = '''uint32_t run(int value) {
  BEGIN;
  uint32_t input=value;
  uint8_t a;
  for (;;) {
    CUT(entry);
    if (read_byte(input, &a)) return 0xFFFFFFFFU;
    if (!a) break;
    CUT(next);
    ++input;
  }
  CUT(tail);
  return input;
}
'''


class SourceRegionTransportTests(unittest.TestCase):
    def inventories(self, *, local=LOCAL, body=BODY, original_body=BODY):
        if not all(shutil.which(t) for t in ('goto-cc', 'goto-instrument')):
            self.skipTest('compiler fixtures unavailable')
        result = {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for side, text in [('original', TYPES+ORDINARY+original_body), ('local', TYPES+local+body)]:
                source, model = root/(side+'.c'), root/(side+'.goto')
                source.write_text(text)
                r = subprocess.run([shutil.which('goto-cc'), '--i386-win32', str(source), '-o', str(model)],
                                   capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 0, r.stderr)
                for key, flag, field in [('functions', '--show-goto-functions', 'functions'),
                                         ('symbols', '--show-symbol-table', 'symbolTable')]:
                    r = subprocess.run([shutil.which('goto-instrument'), flag, '--json-ui', str(model)],
                                       capture_output=True, text=True, timeout=30)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    rows = [v[field] for v in json.loads(r.stdout) if field in v]
                    self.assertEqual(len(rows), 1)
                    result[side+'_'+key] = {v['name']: v for v in rows[0]} if key == 'functions' else rows[0]
        return result

    def check(self, inventories):
        return check_source_region_transport(**inventories, function='run', entry_sync='entry',
            restored_locals={'run::1::input': 'input', 'run::1::a': 'a'}, cut_results={'next': 3, 'tail': 6})

    def test_compiled_restore_and_both_branch_exits_match(self):
        result = self.check(self.inventories())
        self.assertEqual(result['status'], 'matched-source-region-transport')
        self.assertEqual({v[1] for v in result['exits'] if v[0] == 'cut'}, {'next', 'tail'})
        self.assertFalse(result['input_harness_domain_checked'])
        self.assertFalse(result['runtime_contracts_checked'])

    def test_swapped_cut_ordinals_are_not_equivalent(self):
        local = LOCAL.replace('return 3U;', 'return 99U;').replace('return 6U;', 'return 3U;').replace('return 99U;', 'return 6U;')
        with self.assertRaisesRegex(ValueError, 'cut result differs'):
            self.check(self.inventories(local=local))

    def test_inverted_branch_cannot_reuse_body_correspondence(self):
        with self.assertRaisesRegex(ValueError, 'body instruction differs'):
            self.check(self.inventories(body=BODY.replace('if (!a)', 'if (a)')))

    def test_wrong_restored_member_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'local restore differs'):
            self.check(self.inventories(local=LOCAL.replace('input=spx_cut.input;', 'input=spx_cut.a;')))

    def test_missing_restore_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing or duplicate incoming restore'):
            self.check(self.inventories(local=LOCAL.replace('input=spx_cut.input;', '')))

    def test_incoming_width_change_is_not_a_storage_relation(self):
        with self.assertRaisesRegex(ValueError, 'incoming storage type closure differs'):
            self.check(self.inventories(body=BODY.replace('uint32_t input=value;', 'unsigned long long input=value;')))

    def test_volatile_entry_flag_cannot_be_erased(self):
        with self.assertRaisesRegex(ValueError, 'unexpected entry assignment'):
            self.check(self.inventories(local=LOCAL.replace('uint32_t spx_local_entered', 'volatile uint32_t spx_local_entered')))

    def test_return_colliding_with_cut_ordinal_requires_tagged_outcomes(self):
        source = BODY.replace('return 0xFFFFFFFFU;', 'return 3U;')
        with self.assertRaisesRegex(ValueError, 'separately tagged outcome'):
            self.check(self.inventories(body=source, original_body=source))

    def test_assumption_before_entry_cannot_hide_a_bad_state(self):
        with self.assertRaisesRegex(ValueError, 'effect or assumption before restore frontier'):
            self.check(self.inventories(local=LOCAL.replace('goto spx_local_loop', '__CPROVER_assume(0); goto spx_local_loop')))

    def test_entry_cycle_cannot_be_silently_erased(self):
        with self.assertRaisesRegex(ValueError, 'entry cycle'):
            self.check(self.inventories(local=LOCAL.replace('goto spx_local_loop', 'forever: goto forever; goto spx_local_loop')))

    def test_extra_call_in_body_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'body instruction differs'):
            self.check(self.inventories(body=BODY.replace('if (!a)', 'read_byte(input, &a); if (!a)')))

    def test_effect_after_return_value_is_not_ignored(self):
        inventory = self.inventories()
        rows = inventory['local_functions']['run']['instructions']
        call = copy.deepcopy(next(v for v in rows if v['instructionId'] == 'FUNCTION_CALL'))
        call['locationNumber'] = max(v['locationNumber'] for v in rows)+1
        # Select the ordinary fault return, after the unique read call.
        read_index = next(i for i, v in enumerate(rows) if v['instructionId'] == 'FUNCTION_CALL')
        target = next(i for i in range(read_index+1, len(rows)) if rows[i]['instructionId'] == 'SET_RETURN_VALUE')
        rows.insert(target+1, call)
        with self.assertRaisesRegex(ValueError, 'effect after return value'):
            self.check(inventory)
