"""Authored read/write footprints are checked facts, independent of workspace size."""

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_image_frame import (
    FRAME, checked_operations, consumer_private_ranges, frame_spec, guarantee,
)
from .borrowed_state_fixture import check_borrowed_state
from . import test_bisimulation_mutable_composition as composition_tests

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'nix/jq/strong-contextual-proof.jq')}


class PrivateAccessFootprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name); cls.cases = {}
        for name, ranges in (('adjacent', [{'offset': 0, 'bytes': 4}, {'offset': 4, 'bytes': 4}]),
                             ('missing-argument-read', [{'offset': 0, 'bytes': 4}]), ('empty', []), ('wide', None)):
            root = cls.root/name; root.mkdir()
            result, case = check_borrowed_state(root, cbmc=Path(shutil.which('cbmc')), private_accesses=ranges)
            if result['status'] != 'satisfied': raise AssertionError(result.get('issues'))
            cls.cases[name] = case
        cls.program = (Path(__file__).resolve().parents[3]/TESTKIT['resources'][1]).read_text()

    seal = staticmethod(composition_tests.MutableCompositionTests.seal)
    readers = composition_tests.MutableCompositionTests.readers

    def test_adjacent_grants_cover_word_reads_and_bind_retained_evidence(self):
        case = self.cases['adjacent']
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
        self.assertEqual(checked_operations(case['proof'], artifacts=self.root/'adjacent/diagnostics'), ('get',))
        operation = case['proof']['models']['operation_models'][0]
        self.assertEqual(consumer_private_ranges(operation, {'private_high_offset': 4096}), [(0, 8)])
        self.assertEqual(case['proof']['shards'][0][FRAME.field]['policy'], 'paired-image-private-access-footprint-v1')

    def test_uncovered_argument_and_return_reads_fail_only_the_auxiliary_claim(self):
        for name in ('missing-argument-read', 'empty'):
            with self.subTest(name=name):
                case = self.cases[name]
                self.assertEqual(case['proof']['shards'][0][FRAME.field]['result']['status'], 'violated')
                self.assertEqual(checked_operations(case['proof'], artifacts=self.root/name/'diagnostics'), ())
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))

    def test_modified_or_erased_footprint_cannot_consume_old_evidence(self):
        for mutation in ('model', 'plan', 'erased', 'policy', 'guard'):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(self.cases['adjacent']); proof = case['proof']
                operation = proof['models']['operation_models'][0]; model = operation['obligation_models'][0]
                frame = proof['shards'][0][FRAME.field]
                if mutation == 'model': operation['private_stack_accesses'][0]['bytes'] = 3
                elif mutation == 'plan': case['proof_plan']['operations'][0]['private_stack_accesses'] = []
                elif mutation == 'erased':
                    for row in (operation, model, case['proof_plan']['operations'][0]): row.pop('private_stack_accesses')
                elif mutation == 'policy': frame['policy'] = FRAME.policy; self.seal(frame)
                else: model['required_assertion_descriptions'].remove(frame_spec(((0, 4), (4, 4))).description)
                self.assertEqual(self.readers(case), (False, False))

    def test_segment_entry_bounds_are_not_a_whole_callee_anchor_theorem(self):
        proof = copy.deepcopy(self.cases['adjacent']['proof']); operation = proof['models']['operation_models'][0]
        operation['obligation_models'].append(copy.deepcopy(operation['obligation_models'][0]))
        self.assertFalse(guarantee(proof, operation))

    def test_omitted_footprint_rejects_explicit_null_metadata(self):
        self.assertEqual(self.readers(copy.deepcopy(self.cases['wide'])), (True, True))
        for target in ('operation', 'segment', 'plan'):
            with self.subTest(target=target):
                case = copy.deepcopy(self.cases['wide'])
                operation = case['proof']['models']['operation_models'][0]
                row = {'operation': operation, 'segment': operation['obligation_models'][0],
                       'plan': case['proof_plan']['operations'][0]}[target]
                row['private_stack_accesses'] = None
                self.assertEqual(self.readers(case), (False, False))

    def test_absence_and_empty_are_distinct_and_malformed_ranges_reject(self):
        def intent(fields):
            return ComponentBisimulationIntentV1.create(component_id='sample', operations=[{
                'operation_id': 'run', 'syncs': [], **fields}])
        self.assertNotIn('private_stack_accesses', intent({}).to_payload()['operations'][0])
        self.assertEqual(intent({'private_stack_accesses': []}).to_payload()['operations'][0]['private_stack_accesses'], [])
        for ranges in (None, {}, [{'offset': True, 'bytes': 1}], [{'offset': -1025, 'bytes': 1}],
                       [{'offset': 0, 'bytes': 4}, {'offset': 3, 'bytes': 4}]):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError): intent({'private_stack_accesses': ranges})
