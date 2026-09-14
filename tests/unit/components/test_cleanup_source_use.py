"""Representation substitution requires the real source to use opaque views safely."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from spaghetti_extractor.components.bisimulation_cleanup_source_use import checked_cleanup_source_use

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-descriptor/inputs.json'
TESTKIT = {'resources': ('tests/fixtures/metapad-cleanup-descriptor',)}
PARAMETERS = {role: 'cleanup::'+role for role in
    ['context', 'text', 'suppress_notice', 'main_window', 'edit_window', 'caption']}


class CleanupSourceUseTests(unittest.TestCase):
    def setUp(self):
        self.body = json.loads(FIXTURE.read_text())['source_body']
        self.rows = self.body['instructions']

    def check(self):
        return checked_cleanup_source_use(self.body, parameters=PARAMETERS)

    def test_actual_owned_graph_uses_opaque_copies_and_silent_read_fault_exits(self):
        result = self.check()
        self.assertEqual(result['reachable_instructions'], 149)
        self.assertEqual(result['supported_widths'], [1, 4])
        self.assertEqual(len(result['accesses']), 11)
        self.assertEqual(sum('fault_exit' in a for a in result['accesses']), 8)
        self.assertEqual([r['instruction'] for r in result['opaque_copies']], [8, 214])
        self.assertFalse(result['reference_fields_observed'])
        self.assertFalse(result['authorizing'])

    def test_descriptor_observation_and_partial_assignment_reject(self):
        original = deepcopy(self.body)
        scratch = self.rows[8]['code']['sub'][0]
        field = {'id': 'member', 'sub': [scratch], 'namedSub': {
            'component_name': {'id': 'extent'}, 'type': {'id': 'unsignedbv', 'namedSub': {'width': {'id': '64'}}}}}
        for change in ['return', 'partial-write', 'reconstruct', 'allocate-size']:
            with self.subTest(change=change):
                self.body = deepcopy(original); rows = self.body['instructions']
                if change == 'return':
                    rows[255]['code']['sub'][0] = field
                elif change == 'partial-write':
                    rows[8]['code']['sub'][0] = field
                elif change == 'reconstruct':
                    rows[8]['code']['sub'][1] = {'id': 'struct', 'namedSub': scratch['namedSub'], 'sub': []}
                else:
                    rows[7]['code']['sub'][2]['sub'][2] = field
                with self.assertRaises(ValueError):
                    self.check()

    def test_nonconstant_unsupported_and_unchecked_cast_widths_reject(self):
        original = deepcopy(self.body)
        for change in ['width-three', 'variable', 'narrow-cast']:
            with self.subTest(change=change):
                self.body = deepcopy(original); rows = self.body['instructions']
                args = rows[195]['code']['sub'][2]['sub']
                if change == 'width-three':
                    args[3]['sub'][0]['namedSub']['value']['id'] = '3'
                elif change == 'variable':
                    args[3] = rows[255]['code']['sub'][0]
                else:
                    args[3]['namedSub']['type']['namedSub']['width']['id'] = '8'
                with self.assertRaisesRegex(ValueError, 'span width'):
                    self.check()

    def test_fault_value_observation_effects_cycles_and_dead_status_reject(self):
        original = deepcopy(self.body)
        for change in ['return-output', 'branch-output', 'effect', 'cycle', 'dead-status']:
            with self.subTest(change=change):
                self.body = deepcopy(original); rows = self.body['instructions']
                output = rows[25]['code']['sub'][2]['sub'][2]['sub'][0]
                if change == 'return-output':
                    rows[28]['code']['sub'][0] = output
                elif change == 'branch-output':
                    rows[26]['guard']['sub'][0]['sub'][0] = output
                elif change == 'effect':
                    rows[27]['instructionId'] = 'FUNCTION_CALL'; rows[27]['code'] = rows[191]['code']
                else:
                    # A nonzero status follows the false edge. Returning to the
                    # same branch cycles; consulting it after DEAD is unproved.
                    index = 26 if change == 'cycle' else 28
                    location = rows[index]['locationNumber']
                    rows[index] = deepcopy(rows[26]); rows[index]['locationNumber'] = location
                    if change == 'cycle':
                        rows[index]['guard'] = rows[index]['guard']['sub'][0]
                        rows[index]['targets'] = [location]
                with self.assertRaisesRegex(ValueError, 'cleanup read fault'):
                    self.check()

    def test_scalar_behavior_change_is_not_mistaken_for_equivalence(self):
        before = self.check()
        self.rows[255]['code']['sub'][0] = deepcopy(self.rows[28]['code']['sub'][0])
        after = self.check()
        self.assertNotEqual(before['body_sha256'], after['body_sha256'])
        self.assertFalse(after['authorizing'])


if __name__ == '__main__':
    unittest.main()
