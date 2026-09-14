"""Real terminal returns need an entry boundary, without synthetic exit APIs."""
from copy import deepcopy
import unittest

from spaghetti_extractor.components.bisimulation_region_observer import check_marked_region_transport
from spaghetti_extractor.components.bisimulation_source_region_transport import check_source_region_transport
from . import test_source_region_transport as fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler')}
BODY = '''uint32_t run(int value) {
 BEGIN;
 uint32_t input=value;
 uint8_t a;
 CUT(entry);
 for(uint32_t k=0;k<2U;++k) {
  if(read_byte(input,&a))return 0xFFFFFFFFU;
  input+=a;
 }
 return input;
}
'''
MARKED = '''#undef CUT
void terminal_entry(void) {}
#define CUT(id) terminal_entry()
'''
LOCAL = '''static struct {uint32_t input;} spx_cut;
#define BEGIN goto resume
#define CUT(id) resume: input=spx_cut.input; __CPROVER_assert(1,"source-cut-invariant")
'''


class SourceTerminalTransportTests(unittest.TestCase):
    inventories = fixture.SourceRegionTransportTests.inventories

    def prepared(self, *, body=BODY, local=LOCAL):
        data = self.inventories(original_body=MARKED+BODY, body=body, local=local)
        return {key.replace('original_', 'marked_'): value for key, value in data.items()}

    def check(self, data):
        return check_marked_region_transport(**data, function='run', entry_sync='entry',
            markers={'entry': 'terminal_entry'}, restored_locals={'run::1::input': 'input'},
            cut_results={}, control_graph=True)

    def test_single_entry_retains_normal_and_early_return_and_loop(self):
        result = self.check(self.prepared())
        self.assertEqual(result['status'], 'matched-source-region-transport')
        self.assertFalse(result['inventory_tokens_executed'])
        self.assertFalse(result['authorizing'])
        self.assertFalse(result['runtime_contracts_checked'])
        self.assertFalse(result['execution_obligations_checked'])
        self.assertFalse(result['dependency_inventory']['acyclic'])
        self.assertTrue(result['exits'])

    def test_changed_normal_or_early_return_is_rejected(self):
        for before, after in [('return input;', 'return input+1U;'),
                              ('return 0xFFFFFFFFU;', 'return 0U;')]:
            with self.subTest(before=before), self.assertRaisesRegex(ValueError, 'body instruction differs'):
                self.check(self.prepared(body=BODY.replace(before, after)))

    def test_changed_call_effect_or_control_is_rejected(self):
        for before, after in [('read_byte(input,&a)', 'read_byte(input+1U,&a)'),
                              ('k<2U', 'k<3U')]:
            with self.subTest(before=before), self.assertRaisesRegex(ValueError, 'body instruction differs'):
                self.check(self.prepared(body=BODY.replace(before, after)))

    def test_entry_assumptions_or_wrong_restoration_are_rejected(self):
        for before, after in [('input=spx_cut.input;', 'input=spx_cut.input+1U;'),
                              ('resume:', 'resume: __CPROVER_assume(value>0);')]:
            with self.subTest(before=before), self.assertRaisesRegex(ValueError, 'local restore differs|effect or assumption'):
                self.check(self.prepared(local=LOCAL.replace(before, after)))

    def test_single_marker_must_still_be_inert_and_unique(self):
        data = self.prepared()
        changed = deepcopy(data)
        rows = changed['marked_functions']['run']['instructions']
        assignment = next(row for row in rows if row['instructionId'] == 'ASSIGN')
        changed['marked_functions']['terminal_entry']['instructions'].insert(0, assignment)
        with self.assertRaisesRegex(ValueError, 'marker has behavior'):
            self.check(changed)
        changed = deepcopy(data)
        rows = changed['marked_functions']['run']['instructions']
        call = next(row for row in rows if row['instructionId'] == 'FUNCTION_CALL'
                    and 'terminal_entry' in str(row['code']))
        rows.insert(0, deepcopy(call))
        with self.assertRaisesRegex(ValueError, 'not unique'):
            self.check(changed)

    def test_symbolic_return_cannot_collide_with_synthetic_cut_ordinals(self):
        body = fixture.BODY.replace('return 0xFFFFFFFFU;', 'return input;')
        data = self.inventories(body=body, original_body=body)
        with self.assertRaisesRegex(ValueError, 'separately tagged outcome'):
            check_source_region_transport(**data, function='run', entry_sync='entry',
                restored_locals={'run::1::input': 'input', 'run::1::a': 'a'},
                cut_results={'next': 3, 'tail': 6})
